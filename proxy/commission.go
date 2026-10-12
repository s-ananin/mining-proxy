// Файл commission.go — «комиссия» за использование инфраструктуры.
//
// ТЗ заказчика: за сутки на commission_worker должно уйти ~commission_percent
// процентов принятых шар, изъятие происходит порциями (итерациями) в
// случайные моменты, но не чаще commission_iteration раз в сутки.
//
// Как работает:
//
//   - суточное окно (скользящие 24h): target = процент от принятых за окно
//     шар (accepted реестра Stats — подтверждённые реальным пулом);
//   - есть два режима изъятия:
//     1) фиксированный интервал (commission_interval, напр. "10m"):
//     каждые N планировщик добирает бюджет до target. target растёт по мере
//     принятия шар, поэтому порция пропорциональна принятым за интервал
//     шарам, а сумма выданного бюджета никогда не превышает target
//     (кап — commission_percent% за сутки);
//     2) случайные итерации (commission_iteration, дефолт 40/сутки):
//     batch = ceil((target - уже взято) / оставшиеся итерации). Так процент
//     сходится к target, а число изъятий не превышает commission_iteration;
//   - в момент итерации следующие batch mining.submit из ЛЮБОГО ASIC не уходят
//     в его реальный пул, а перенаправляются на выделенное соединение с
//     commission_worker (subscribe+authorize), где воркер шары переписан;
//   - fail-open: если пул комиссии недоступен или перенаправление не удалось,
//     шара остаётся у майнера (идёт в реальный пул как обычно), комиссия
//     НЕ изымается. Майнинг клиента не прерывается никогда.
//
// Комиссия учитывается в своих счётчиках (/status.commission) и НЕ влияет на
// totals/workers штатного мониторинга: забранные шары не регистрируются как
// submits реального пула.
package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"
)

// Таймауты и окно комиссионного изъятия.
const (
	// commissionDialTimeout TCP-подключение к пулу комиссии.
	commissionDialTimeout = 10 * time.Second

	// commissionHandshakeTimeout полный handshake (subscribe+authorize).
	commissionHandshakeTimeout = 30 * time.Second

	// commissionForwardTimeout ожидание ответа пула на перенаправленную шару.
	commissionForwardTimeout = 5 * time.Second

	// commissionWindow суточное окно изъятий (скользящее).
	commissionWindow = 24 * time.Hour

	// commissionMinGap минимальная пауза между итерациями изъятия.
	commissionMinGap = time.Minute
)

// commissionConn — выделенное соединение к пулу с commission_worker.
// subscribe+authorize выполняются один раз, дальше переиспользуется.
type commissionConn struct {
	conn   net.Conn
	reader *bufio.Reader
	seq    int // последовательный id наших перенаправленных submit
}

// Commission — сборщик комиссии. Потокобезопасен (mu).
//
// Для каждого пула, на который ходят ASIC, держится отдельное соединение с
// commission_worker (воркер одинаковый, пулы разные). Решения по изъятию
// принимаются глобально по всем ASIC, как и процент в ТЗ (25000 -> 500).
type Commission struct {
	mu   sync.Mutex
	stop chan struct{}
	wg   sync.WaitGroup

	// Параметры (worker == "" → комиссия выключена).
	worker           string
	percent          float64
	iterationsPerDay int
	interval         time.Duration // >0 — фиксированный интервал изъятия
	stats            *Stats

	// Состояние суточного окна.
	windowStart     time.Time
	baseAccepted    int // stats.Accepted() в момент начала окна
	taken           int // принято комиссионных шар за окно
	attempts        int // всего перенаправлено за всё время
	acceptedCnt     int // из них принято пулом
	rejectedCnt     int // отклонено пулом
	failedCnt       int // ошибок перенаправления / недоступности пула
	iterationsUsed  int // итераций в текущем окне
	takeBudget      int // сколько следующих шар забрать (порция итерации)
	budgetIssued    int // выдано бюджета за окно (interval-режим, кап на target)
	nextIterationAt time.Time

	// Выделенные соединения к пулам: pool address → conn.
	conns map[string]*commissionConn

	rng *rand.Rand
}

// NewCommission создаёт сборщик комиссии. worker == "" — комиссия
// выключена: Redirect всегда вернёт false, Start ничего не планирует.
//
// interval > 0 включает режим фиксированного интервала: изъятие идёт каждые
// interval, а iterationsPerDay выводится из интервала и аргумент
// iterationsPerDay игнорируется.
func NewCommission(worker string, percent float64, iterationsPerDay int, interval time.Duration, stats *Stats) *Commission {
	now := time.Now()
	if interval > 0 {
		iterationsPerDay = int(commissionWindow / interval)
		if iterationsPerDay < 1 {
			iterationsPerDay = 1
		}
	}
	return &Commission{
		stop:             make(chan struct{}),
		worker:           worker,
		percent:          percent,
		iterationsPerDay: iterationsPerDay,
		interval:         interval,
		stats:            stats,
		windowStart:      now,
		baseAccepted:     stats.Accepted(),
		conns:            map[string]*commissionConn{},
		rng:              rand.New(rand.NewSource(now.UnixNano())),
	}
}

// Enabled true, если комиссия сконфигурирована (worker задан).
func (c *Commission) Enabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.worker != ""
}

// Start запускает планировщик итераций изъятия (неблокирующая).
func (c *Commission) Start() {
	if c.worker == "" {
		return
	}
	c.wg.Add(1)
	go c.scheduler()
}

// Close останавливает планировщик и закрывает соединения к пулам.
func (c *Commission) Close() {
	select {
	case <-c.stop:
		return
	default:
		close(c.stop)
	}
	c.wg.Wait()

	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cc := range c.conns {
		cc.conn.Close()
	}
	c.conns = map[string]*commissionConn{}
}

// scheduler будит комиссию в моменты итераций. В interval-режиме — ровно
// каждые interval; в случайном режиме первая итерация — в случайный момент
// в первой трети суток (не сразу после старта).
func (c *Commission) scheduler() {
	defer c.wg.Done()

	var delay time.Duration
	if c.interval > 0 {
		delay = c.interval
	} else {
		delay = time.Duration(c.rng.Int63n(int64(commissionWindow/3))) + commissionMinGap
	}
	timer := time.NewTimer(delay)
	for {
		select {
		case <-c.stop:
			timer.Stop()
			return
		case t := <-timer.C:
			next := c.iterate(t)
			timer.Reset(time.Until(next))
		}
	}
}

// iterate выполняет одну итерацию изъятия: начисляет порцию следующих шар
// на бюджет и планирует следующую итерацию. Возвращает момент следующей.
func (c *Commission) iterate(now time.Time) time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Сброс суточного окна: старые счётчики окна обнуляются, лимит
	// итераций снова полный. Рекурсии нет — дальше работаем уже в новом
	// окне (после сброса now внутри окна, проверка пройдена).
	if !now.Before(c.windowStart.Add(commissionWindow)) {
		c.windowStart = now
		c.baseAccepted = c.stats.Accepted()
		c.taken = 0
		c.iterationsUsed = 0
		c.takeBudget = 0
		c.budgetIssued = 0
	}
	end := c.windowStart.Add(commissionWindow)

	// Фиксированный интервал: каждый тик добираем бюджет до текущего target
	// = percent% принятых за окно. target растёт вместе с accepted, поэтому
	// порция пропорциональна принятым за интервал шарам, а сумма выданного
	// за окно бюджета не превышает target (суточный кап на процент).
	if c.interval > 0 {
		acceptedToday := c.stats.Accepted() - c.baseAccepted
		target := int(float64(acceptedToday) * c.percent / 100)
		batch := target - c.budgetIssued
		if batch < 0 {
			batch = 0
		}
		c.takeBudget += batch
		c.budgetIssued += batch
		c.iterationsUsed++
		if batch > 0 {
			log.Printf("[COMMISSION] every %s: batch %d (accepted today=%d, target≈%d, issued=%d)",
				c.interval, batch, acceptedToday, target, c.budgetIssued)
		}
		next := c.windowStart.Add(time.Duration(c.iterationsUsed) * c.interval)
		if !next.After(now) {
			next = now.Add(c.interval)
		}
		c.nextIterationAt = next
		return next
	}

	iterationsLeft := c.iterationsPerDay - c.iterationsUsed
	if iterationsLeft <= 0 {
		// Лимит итераций на сегодня исчерпан — вернёмся завтра.
		return end.Add(time.Minute)
	}

	acceptedToday := c.stats.Accepted() - c.baseAccepted
	batch := planBatch(acceptedToday, c.taken, iterationsLeft, c.percent)
	c.takeBudget += batch
	c.iterationsUsed++
	if batch > 0 {
		log.Printf("[COMMISSION] iteration %d/%d: batch %d (accepted today=%d, target≈%d, taken=%d)",
			c.iterationsUsed, c.iterationsPerDay, batch, acceptedToday,
			int(float64(acceptedToday)*c.percent/100), c.taken)
	}

	// Следующая итерация — случайный момент, равномерно размазанный по
	// оставшимся итерациям на оставшийся день.
	remaining := c.iterationsPerDay - c.iterationsUsed
	avail := end.Sub(now)
	if remaining <= 0 || avail <= 0 {
		return end.Add(time.Minute)
	}
	maxGap := avail / time.Duration(remaining)
	if maxGap < commissionMinGap {
		maxGap = commissionMinGap
	}
	gap := commissionMinGap
	if maxGap > commissionMinGap {
		gap = commissionMinGap + time.Duration(c.rng.Int63n(int64(maxGap-commissionMinGap)))
	}
	next := now.Add(gap)
	if next.After(end) {
		next = end.Add(time.Minute)
	}
	c.nextIterationAt = next
	return next
}

// planBatch считает порцию шар для текущей итерации: сколько ещё нужно
// изъять за оставшиеся итерации (округляем вверх). Чистая функция —
// вынесена для тестирования. Возвращает 0, если изымать нечего.
func planBatch(acceptedToday, taken, iterationsLeft int, percent float64) int {
	if iterationsLeft <= 0 {
		return 0
	}
	target := int(float64(acceptedToday) * percent / 100)
	need := target - taken
	if need <= 0 {
		return 0
	}
	return (need + iterationsLeft - 1) / iterationsLeft
}

// Redirect обрабатывает mining.submit от ASIC.
//
// Возвращает true, если шара ЗАБРАНА: ушла на commission_worker, в реальный
// пул майнера НЕ отправляется (вызывающий не должен писать её в upstream).
// Возвращает false, если шара остаётся майнеру: комиссия выключена, бюджет
// исчерпан или перенаправление не удалось (fail-open — комиссия не
// изымается при недоступном пуле).
//
// После успешной записи в пул комиссии шара считается забранной ВСЕГДА
// (ответ читается только для счётчиков): дубль в реальный пул не шлём.
func (c *Commission) Redirect(submitRaw []byte, pool string) (swallowed bool) {
	if c.worker == "" {
		return false
	}

	c.mu.Lock()
	if c.takeBudget <= 0 {
		c.mu.Unlock()
		return false
	}
	c.takeBudget--
	cc := c.connForLocked(pool)
	c.mu.Unlock()

	if cc == nil {
		// Пул комиссии недоступен — шару не трогаем (fail-open).
		c.countFailed()
		return false
	}

	cc.conn.SetWriteDeadline(time.Now().Add(commissionForwardTimeout))
	c.mu.Lock()
	cc.seq++
	raw, err := rewriteSubmitWorker(submitRaw, c.worker, cc.seq)
	c.mu.Unlock()
	if err != nil {
		log.Printf("[COMMISSION] rewrite worker %q: %v", c.worker, err)
		c.countFailed()
		return false
	}

	if _, err := cc.conn.Write(append(raw, '\n')); err != nil {
		log.Printf("[COMMISSION] write %s: %v (reconnect next time)", pool, err)
		c.dropConn(pool, cc)
		c.countFailed()
		return false
	}
	c.countAttempt()

	// Ответ читаем до timeout; счётчики accepted/rejected пополняются по
	// живому ответу пула. Ошибка чтения на swallow не влияет.
	cc.conn.SetReadDeadline(time.Now().Add(commissionForwardTimeout))
	for {
		line, err := cc.reader.ReadBytes('\n')
		if err != nil {
			c.dropConn(pool, cc)
			return true
		}
		resp, ok := ParsePoolResponse(line)
		if ok {
			if resp.Accepted {
				log.Printf("[COMMISSION] шара зачтена воркеру %q (пул %s)", c.worker, pool)
			} else {
				log.Printf("[COMMISSION] пул %s отклонил шару воркера %q: %s", pool, c.worker, resp.Error)
			}
			c.countResult(resp.Accepted)
			return true
		}
	}
}

// connForLocked возвращает (или создаёт) соединение к пулу под
// commission_worker. Вызывается под c.mu. При неудаче вернёт nil.
func (c *Commission) connForLocked(pool string) *commissionConn {
	if cc, ok := c.conns[pool]; ok {
		return cc
	}
	cc, err := c.dialAndHandshake(pool)
	if err != nil {
		log.Printf("[COMMISSION] connect %s (worker %q): %v", pool, c.worker, err)
		return nil
	}
	c.conns[pool] = cc
	return cc
}

// dialAndHandshake подключается к пулу и выполняет полный Stratum handshake:
// mining.subscribe → ответ, mining.authorize (commission_worker) → ответ.
func (c *Commission) dialAndHandshake(pool string) (*commissionConn, error) {
	conn, err := net.DialTimeout("tcp", pool, commissionDialTimeout)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(commissionHandshakeTimeout)
	conn.SetDeadline(deadline)
	reader := bufio.NewReader(conn)

	sub, _ := json.Marshal(map[string]interface{}{
		"id": 1, "method": "mining.subscribe", "params": []string{"mining-proxy/commission/1.0"},
	})
	if _, err := conn.Write(append(sub, '\n')); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := readHandshakeResp(reader, 1); err != nil {
		conn.Close()
		return nil, err
	}

	auth, _ := json.Marshal(map[string]interface{}{
		"id": 2, "method": "mining.authorize", "params": []string{c.worker, ""},
	})
	if _, err := conn.Write(append(auth, '\n')); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := readHandshakeResp(reader, 2)
	if err != nil {
		conn.Close()
		return nil, err
	}
	var ar struct {
		Result json.RawMessage `json:"result"`
	}
	if json.Unmarshal(resp, &ar) == nil && string(ar.Result) != "true" {
		conn.Close()
		return nil, fmt.Errorf("authorize rejected (worker %q)", c.worker)
	}

	conn.SetDeadline(time.Time{})
	return &commissionConn{conn: conn, reader: reader}, nil
}

// readHandshakeResp читает строки, пока не придёт ответ с нужным id
// (без method — это ответ на наш запрос, а не notify/set_difficulty).
func readHandshakeResp(r *bufio.Reader, wantID int) ([]byte, error) {
	want := strconv.Itoa(wantID)
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		msg, err := Parse(line)
		if err != nil {
			continue
		}
		if msg.Method == "" && string(msg.ID) == want {
			return line, nil
		}
	}
}

// rewriteSubmitWorker переписывает в mining.submit имя воркера (params[0])
// на newWorker и ставит последовательный id. Остаток шары (job_id, nonce2,
// ntime, nonce) сохраняется — это «перекосит» шару на commission_worker.
func rewriteSubmitWorker(raw []byte, newWorker string, id int) ([]byte, error) {
	var msg struct {
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, err
	}
	if msg.Method != "mining.submit" {
		return nil, fmt.Errorf("not mining.submit")
	}
	var params []json.RawMessage
	if err := json.Unmarshal(msg.Params, &params); err != nil || len(params) == 0 {
		return nil, fmt.Errorf("bad submit params")
	}
	params[0], _ = json.Marshal(newWorker)
	newParams, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		ID     int             `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
	}{ID: id, Method: msg.Method, Params: newParams})
}

// dropConn закрывает и удаляет соединение к пулу (следующая шара создаст
// новое). Безопасно вызывать повторно.
func (c *Commission) dropConn(pool string, cc *commissionConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cur, ok := c.conns[pool]; ok && cur == cc {
		delete(c.conns, pool)
	} else if !ok {
		return
	}
	cc.conn.Close()
}

// countAttempt / countResult / countFailed обновляют счётчики комиссии.
func (c *Commission) countAttempt() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts++
}

func (c *Commission) countResult(accepted bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if accepted {
		c.acceptedCnt++
		c.taken++
	} else {
		c.rejectedCnt++
	}
}

func (c *Commission) countFailed() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failedCnt++
}

// CommissionReport — снимок комиссии для /status.commission.
type CommissionReport struct {
	Enabled          bool    `json:"enabled"`
	Worker           string  `json:"worker,omitempty"`
	Percent          float64 `json:"percent,omitempty"`
	Interval         string  `json:"interval,omitempty"`
	IterationsPerDay int     `json:"iterations_per_day,omitempty"`
	Attempts         int     `json:"attempts"`
	Accepted         int     `json:"accepted"`
	Rejected         int     `json:"rejected"`
	Failed           int     `json:"failed"`
	AcceptedToday    int     `json:"accepted_today"`
	TargetToday      int     `json:"target_today"`
	TakenToday       int     `json:"taken_today"`
	IterationsUsed   int     `json:"iterations_used"`
	IterationsLeft   int     `json:"iterations_left"`
	NextIterationAt  string  `json:"next_iteration_at,omitempty"`
	WindowEnd        string  `json:"window_end,omitempty"`
}

// intervalString возвращает читаемое представление интервала ("" если 0).
func intervalString(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return d.String()
}

// Snapshot строит снимок состояния комиссии (для /status).
func (c *Commission) Snapshot() CommissionReport {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.worker == "" {
		return CommissionReport{Enabled: false}
	}
	acceptedToday := c.stats.Accepted() - c.baseAccepted
	target := int(float64(acceptedToday) * c.percent / 100)
	left := c.iterationsPerDay - c.iterationsUsed
	if left < 0 {
		left = 0
	}
	rep := CommissionReport{
		Enabled:          true,
		Worker:           c.worker,
		Percent:          c.percent,
		Interval:         intervalString(c.interval),
		IterationsPerDay: c.iterationsPerDay,
		Attempts:         c.attempts,
		Accepted:         c.acceptedCnt,
		Rejected:         c.rejectedCnt,
		Failed:           c.failedCnt,
		AcceptedToday:    acceptedToday,
		TargetToday:      target,
		TakenToday:       c.taken,
		IterationsUsed:   c.iterationsUsed,
		IterationsLeft:   left,
		NextIterationAt:  c.nextIterationAt.Format(time.RFC3339),
		WindowEnd:        c.windowStart.Add(commissionWindow).Format(time.RFC3339),
	}
	if c.nextIterationAt.IsZero() {
		rep.NextIterationAt = ""
	}
	return rep
}

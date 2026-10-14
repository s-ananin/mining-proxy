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
//     (кап — commission_percent% за сутки). Если задан commission_session
//     (напр. "20m"), изъятие дополнительно ограничено одним окном такой
//     длины внутри каждого интервала; начало окна выбирается случайно,
//     вне окна шары не изымаются;
//     2) случайные итерации (commission_iteration, дефолт 40/сутки):
//     batch = ceil((target - уже взято) / оставшиеся итерации). Так процент
//     сходится к target, а число изъятий не превышает commission_iteration;
//   - в момент итерации следующие batch mining.submit из ЛЮБОГО ASIC уходят в
//     ТОТ ЖЕ upstream-соединение майнера (job_id/extranonce1 сохраняются),
//     но воркер подменяется на commission_worker. Пул привязывает воркер к
//     mining.authorize, поэтому одной подмены params[0] мало: на время
//     изъятия прокси отправляет в пул служебный mining.authorize с
//     commission_worker, а в конце возвращает воркер майнера. Так authorize и
//     submit согласованы, и шары засчитываются комиссии;
//   - fail-open: если переписать шару не удалось, она уходит как обычно,
//     комиссия НЕ изымается. Майнинг клиента не прерывается никогда.
//
// Комиссия учитывается в своих счётчиках (/status.commission) и НЕ влияет на
// totals/workers штатного мониторинга: забранные шары не регистрируются как
// submits реального пула.
package proxy

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"time"
)

// Окно комиссионного изъятия.
const (
	// commissionWindow суточное окно изъятий (скользящее).
	commissionWindow = 24 * time.Hour

	// commissionMinGap минимальная пауза между итерациями изъятия.
	commissionMinGap = time.Minute

	// commissionAuthTag — id служебного mining.authorize, которым прокси на
	// время изъятия переводит соединение майнера на commission_worker.
	// commissionAuthID — тот же id в виде, в котором его вернёт пул в ответе.
	commissionAuthTag = "__commission_switch__"
	commissionAuthID  = `"` + commissionAuthTag + `"`
)

// Commission — сборщик комиссии. Потокобезопасен (mu).
//
// Изъятие идёт НА СОЕДИНЕНИИ МАЙНЕРА: шара, которую забрали, не уходит в
// реальный пул майнера, а отправляется в тот же upstream с подменённым
// воркером (params[0]). Так сохраняются job_id и extranonce1 соединения, и
// шара остаётся валидной для пула. Решения по изъятию принимаются глобально
// по всем ASIC, как и процент в ТЗ (25000 -> 500).
type Commission struct {
	mu   sync.Mutex
	stop chan struct{}
	wg   sync.WaitGroup

	// Параметры (worker == "" → комиссия выключена).
	worker           string
	percent          float64
	iterationsPerDay int
	interval         time.Duration // >0 — фиксированный интервал изъятия
	session          time.Duration // >0 — окно изъятия внутри интервала
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

	// Активное окно изъятия текущего интервала (session > 0).
	sessionStart time.Time
	sessionEnd   time.Time

	// Диагностика: суммарная сложность (work) изъятых шар. Сравнивается с
	// тем, что пул показал по commission_worker: наш work должен расти ровно.
	workIssued    float64 // work всех изъятых шар (по сложности на момент изъятия)
	workAccepted  float64 // work зачтённых пулом
	workRejected  float64 // work отклонённых пулом
	workSinceTick float64 // work, изъятый с прошлого тика (сбрасывается в iterate)

	rng *rand.Rand
}

// NewCommission создаёт сборщик комиссии. worker == "" — комиссия
// выключена: Redirect всегда вернёт false, Start ничего не планирует.
//
// interval > 0 включает режим фиксированного интервала: изъятие идёт каждые
// interval, а iterationsPerDay выводится из интервала и аргумент
// iterationsPerDay игнорируется.
//
// session > 0 (только вместе с interval) ограничивает изъятие одним окном
// такой длины внутри каждого интервала; начало окна выбирается случайно.
func NewCommission(worker string, percent float64, iterationsPerDay int, interval, session time.Duration, stats *Stats) *Commission {
	now := time.Now()
	if interval > 0 {
		iterationsPerDay = int(commissionWindow / interval)
		if iterationsPerDay < 1 {
			iterationsPerDay = 1
		}
	}
	if session < 0 || session > interval {
		session = 0
	}
	return &Commission{
		stop:             make(chan struct{}),
		worker:           worker,
		percent:          percent,
		iterationsPerDay: iterationsPerDay,
		interval:         interval,
		session:          session,
		stats:            stats,
		windowStart:      now,
		baseAccepted:     stats.Accepted(),
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

// Close останавливает планировщик изъятия.
func (c *Commission) Close() {
	select {
	case <-c.stop:
		return
	default:
		close(c.stop)
	}
	c.wg.Wait()
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

		// Окно изъятия на предстоящий интервал: случайное начало,
		// длина ровно session (влезает в интервал: offset ≤ interval-session).
		if c.session > 0 {
			span := c.interval - c.session
			off := time.Duration(0)
			if span > 0 {
				off = time.Duration(c.rng.Int63n(int64(span)))
			}
			c.sessionStart = now.Add(off)
			c.sessionEnd = c.sessionStart.Add(c.session)
		}
		if batch > 0 {
			if c.session > 0 {
				log.Printf("[COMMISSION] every %s: batch %d (accepted today=%d, target≈%d, issued=%d, session %s..%s)",
					c.interval, batch, acceptedToday, target, c.budgetIssued,
					c.sessionStart.Format("15:04:05"), c.sessionEnd.Format("15:04:05"))
			} else {
				log.Printf("[COMMISSION] every %s: batch %d (accepted today=%d, target≈%d, issued=%d)",
					c.interval, batch, acceptedToday, target, c.budgetIssued)
			}
		}
		// Диагностика: сколько work реально изъято за прошедший интервал и
		// сколько пул зачёл. Наш work должен держаться ровно — если на
		// диаграмме пула воркер «затухает», а здесь ровно, причина на пуле.
		if c.workSinceTick > 0 {
			log.Printf("[COMMISSION] за интервал work изъято=%.0f (issued=%.0f, зачтено=%.0f, отклонено=%.0f)",
				c.workSinceTick, c.workIssued, c.workAccepted, c.workRejected)
			c.workSinceTick = 0
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

// reserve пытается зарезервировать одну шару под комиссию. true — бюджет
// есть: вызывающий должен переписать воркера шары и отправить её в тот же
// upstream. Потокобезопасно.
//
// Если задано окно изъятия (session > 0), шара забирается только внутри
// текущего окна; вне окна бюджет не тратится и переносится на следующее окно.
func (c *Commission) reserve() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.worker == "" || c.takeBudget <= 0 {
		return false
	}
	if c.session > 0 {
		now := time.Now()
		if now.Before(c.sessionStart) || !now.Before(c.sessionEnd) {
			return false
		}
	}
	c.takeBudget--
	return true
}

// rewriteSubmitWorker переписывает в mining.submit имя воркера (params[0])
// на newWorker, СОХРАНЯЯ id шары (чтобы ответ пула вернулся майнеру по его
// id). Остаток шары (job_id, extranonce2, ntime, nonce) не трогаем — на
// соединении майнера шара остаётся валидной.
func rewriteSubmitWorker(raw []byte, newWorker string) ([]byte, error) {
	var msg struct {
		ID     json.RawMessage   `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, err
	}
	if msg.Method != "mining.submit" {
		return nil, fmt.Errorf("not mining.submit")
	}
	if len(msg.Params) == 0 {
		return nil, fmt.Errorf("bad submit params")
	}
	msg.Params[0], _ = json.Marshal(newWorker)
	return json.Marshal(struct {
		ID     json.RawMessage   `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}{ID: msg.ID, Method: msg.Method, Params: msg.Params})
}

// countSteal / countResult / countFailed обновляют счётчики комиссии.
// diff — сложность изъятой шары: копим work как сумму сложностей, чтобы
// сверять реальный вклад с тем, что показывает пул по commission_worker.
func (c *Commission) countSteal(diff float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts++
	c.workIssued += diff
	c.workSinceTick += diff
}

func (c *Commission) countResult(accepted bool, diff float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if accepted {
		c.acceptedCnt++
		c.taken++
		c.workAccepted += diff
	} else {
		c.rejectedCnt++
		c.workRejected += diff
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
	Session          string  `json:"session,omitempty"`
	SessionStart     string  `json:"session_start,omitempty"`
	SessionEnd       string  `json:"session_end,omitempty"`
	IterationsPerDay int     `json:"iterations_per_day,omitempty"`
	Attempts         int     `json:"attempts"`
	Accepted         int     `json:"accepted"`
	Rejected         int     `json:"rejected"`
	Failed           int     `json:"failed"`
	WorkIssued       float64 `json:"work_issued"`
	WorkAccepted     float64 `json:"work_accepted"`
	WorkRejected     float64 `json:"work_rejected"`
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
		Session:          intervalString(c.session),
		IterationsPerDay: c.iterationsPerDay,
		Attempts:         c.attempts,
		Accepted:         c.acceptedCnt,
		Rejected:         c.rejectedCnt,
		Failed:           c.failedCnt,
		WorkIssued:       c.workIssued,
		WorkAccepted:     c.workAccepted,
		WorkRejected:     c.workRejected,
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
	if c.session > 0 && !c.sessionStart.IsZero() {
		rep.SessionStart = c.sessionStart.Format(time.RFC3339)
		rep.SessionEnd = c.sessionEnd.Format(time.RFC3339)
	}
	return rep
}

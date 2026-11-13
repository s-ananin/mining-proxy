// Файл commission.go — «комиссия» за использование инфраструктуры.
//
// Бюджет — commission_percent% суммы сложностей принятых обычных шар.
// Каждая комиссионная шара расходует сложность, с которой её зачтёт пул,
// поэтому разная сложность ASIC и vardiff комиссии не обесценивают бюджет.
// Планировщик выдаёт работу порциями: с фиксированным интервалом либо
// случайными итерациями в суточном окне. session ограничивает время изъятия.
// Изъятие использует исходное upstream-соединение и служебную авторизацию;
// job_id и extranonce сохраняются. После порции восстанавливается майнер.
// Неотправленная работа возвращается в бюджет; отклонённая работа повторно
// планируется на следующем тике. Превышение на последнюю зарезервированную
// шару переносится как отрицательный баланс на следующие тики.
//
// Комиссия учитывается в своих счётчиках (/status.commission) и НЕ влияет на
// totals/workers штатного мониторинга: забранные шары не регистрируются как
// submits реального пула.
package proxy

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"math/rand"
	"sort"
	"strconv"
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
	commissionAuthTag    = "__commission_switch__"
	commissionAuthID     = `"` + commissionAuthTag + `"`
	commissionRestoreTag = "__commission_restore__"
	commissionRestoreID  = `"` + commissionRestoreTag + `"`

	// commissionBreakerDenies — сколько отказов служебной переавторизации
	// подряд по пулу открывают «предохранитель».
	commissionBreakerDenies = 3

	// commissionDiffTag — id служебного mining.suggest_difficulty: им прокси
	// просит у пула закрепить сложность сессии на уровне сложности майнера.
	// commissionDiffID — тот же id в виде, в котором его вернёт пул.
	commissionDiffTag = "__commission_diff__"
	commissionDiffID  = `"` + commissionDiffTag + `"`

	// commissionSuggestInterval — не чаще как часто просим у пула закрепить
	// сложность сессии: пул ограничивает частоту таких запросов
	// ("Frequency limit exceeded").
	commissionSuggestInterval = 90 * time.Second
)

// commissionBreakerCooldown — на сколько пул исключается из изъятия после
// срабатывания предохранителя. Переменная (не const), чтобы тесты могли
// задавать короткую паузу.
var commissionBreakerCooldown = 10 * time.Minute

// commissionCarryFraction — какая доля бюджета нового тика может прийти из
// неизрасходованного остатка прошлых тиков. Остаток сверх неё сгорает и
// повторно не выдаётся: провал изъятия (пул недоступен, шторм реконнектов)
// не догоняется всплеском, который забрал бы у майнеров больше 1.5x
// причитающегося за интервал.
const commissionCarryFraction = 0.5

// poolCommission — счётчики изъятия по конкретному пулу. Нужны, чтобы при
// работе с несколькими пулами видеть, где комиссия фактически идёт, а где
// пул не знает commission_worker.
type poolCommission struct {
	attempts     int
	accepted     int
	rejected     int
	failed       int
	workIssued   float64
	workAccepted float64
	workRejected float64

	// Диагностика скорости изъятия: время и сложность последних изъятых
	// шар. По ним считается мгновенный и средний хешрейт комиссии.
	lastStealAt     time.Time
	samples         []stealSample
	acceptedSamples []stealSample

	// Сложность, которую пул назначил воркеру комиссии (vardiff). По ней
	// пул зачитывает изъятые шары: если она падает, комиссия обесценивается
	// (каждая шара стоит всё меньше work).
	feeDiff float64
}

// stealSample — изъятая шара для расчёта хешрейта комиссии.
type stealSample struct {
	at   time.Time
	diff float64
}

// commissionRateWindow — окно усреднения хешрейта изъятия (как у Stats).
const commissionRateWindow = 10 * time.Minute

// diffToHash переводит сложность в хеш (дублирует stats.diffToHash как
// float64 — та же размерность, чтобы TH/s были сопоставимы).
const diffToHashF = 4294967296.0

// stealRateLocked считает мгновенный (относительно предыдущей изъятой шары)
// и средний (скользящее окно) хешрейт изъятия по пулу. Мгновенный — 0, если
// это первая шара. now и diff — текущая изъятая шара.
func (p *poolCommission) stealRateLocked(now time.Time, diff float64) (instant, avg float64) {
	if !p.lastStealAt.IsZero() {
		if dt := now.Sub(p.lastStealAt).Seconds(); dt > 0 {
			instant = diff * diffToHashF / dt
		}
	}
	p.lastStealAt = now
	p.samples = append(p.samples, stealSample{at: now, diff: diff})
	// Обрезаем старое окно.
	cut := 0
	for cut < len(p.samples) && now.Sub(p.samples[cut].at) > commissionRateWindow {
		cut++
	}
	if cut > 0 {
		p.samples = append([]stealSample(nil), p.samples[cut:]...)
	}
	return instant, p.avgRateLocked()
}

// avgRateLocked средний хешрейт изъятия по накопленным сэмплам (hash/s).
func (p *poolCommission) avgRateLocked() float64 {
	if len(p.samples) < 2 {
		return 0
	}
	var sum float64
	first := p.samples[0].at
	last := p.samples[len(p.samples)-1].at
	for _, s := range p.samples {
		sum += s.diff
	}
	if span := last.Sub(first).Seconds(); span > 0 {
		return sum * diffToHashF / span
	}
	return 0
}

// poolBreaker — предохранитель по пулу: если пул несколько раз подряд
// отклонил служебную переавторизацию (нет commission_worker на этом пуле),
// изъятие с него приостанавливается на cooldown, чтобы не долбить пул и не
// задерживать шары майнера.
type poolBreaker struct {
	denies            int
	openTill          time.Time
	difficultyRetryAt time.Time
	failureUntil      time.Time
	failures          int // неудач боевых соединений подряд (растущая пауза)
}

// Commission — сборщик комиссии. Потокобезопасен (mu).
//
// Изъятие идёт НА СОЕДИНЕНИИ МАЙНЕРА: шара, которую забрали, не уходит в
// реальный пул майнера, а отправляется в тот же upstream с подменённым
// воркером (params[0]). Так сохраняются job_id и extranonce1 соединения, и
// шара остаётся валидной для пула. Решения по изъятию принимаются глобально
// по всем ASIC; бюджет выражен в сумме сложностей шар.
type Commission struct {
	mu   sync.Mutex
	stop chan struct{}
	wg   sync.WaitGroup

	// Глобальная сериализация авторизаций под комиссионного воркера
	// для снижения лавины переавторизаций у пула с vardiff по аккаунту.
	authMu   sync.Mutex
	lastAuth time.Time

	// Параметры (worker == "" → комиссия выключена).
	worker           string
	percent          float64
	iterationsPerDay int
	interval         time.Duration // >0 — фиксированный интервал изъятия
	session          time.Duration // >0 — окно изъятия внутри интервала
	stats            *Stats

	// Ротация имени воркера комиссии. У пула с vardiff сложность
	// воркера падает в разы, если воркер шлёт мало шар (а комиссия шлёт их
	// мало по определению): изъятые шары зачитываются в десятки раз
	// дешевле, и комиссия обесценивается. У нового имени истории нет —
	// пул не трогает сложность сессии, и комиссия остаётся полной.
	// Имя вида "<worker>.rN": аккаунт у пула — часть до первой точки, так
	// что деньги по-прежнему идут на commission_worker.
	rotateWorkers bool
	workerSeq     int
	windowWorker  string // имя воркера, действующее в текущем окне изъятия

	// suggestDiff — после служебного authorize просить у пула закрепить
	// сложность сессии на уровне сложности майнера (mining.suggest_difficulty).
	suggestDiff bool

	// btcOnly: комиссия берётся только в соединениях, где пул раздаёт
	// задания BTC (см. coin.go). Остальные монеты идут прозрачно, и их
	// работа не входит в базу бюджета.
	btcOnly bool

	// Состояние суточного окна.
	windowStart     time.Time
	baseWork        float64
	baseFeeWork     float64
	baseAccepted    int     // stats.Accepted() в момент начала окна
	taken           int     // принято комиссионных шар за окно
	attempts        int     // всего перенаправлено за всё время
	acceptedCnt     int     // из них принято пулом
	rejectedCnt     int     // отклонено пулом
	failedCnt       int     // ошибок перенаправления / недоступности пула
	iterationsUsed  int     // итераций в текущем окне
	takeBudget      float64 // оставшаяся сумма сложностей; отрицательное значение — долг
	budgetIssued    float64 // выдано бюджета за окно (interval-режим, кап на target)
	nextIterationAt time.Time

	// Активное окно изъятия текущего интервала (session > 0).
	sessionStart time.Time
	sessionEnd   time.Time

	// Диагностика: суммарная сложность (work) изъятых шар. Сравнивается с
	// тем, что пул показал по commission_worker: наш work должен расти ровно.
	workIssued        float64 // work всех изъятых шар (по сложности на момент изъятия)
	workAccepted      float64 // work зачтённых пулом
	workRejected      float64 // work отклонённых пулом
	acceptedSinceTick float64
	workSinceTick     float64 // work, изъятый с прошлого тика (сбрасывается в iterate)

	// forfeited — неизрасходованный бюджет окна, сгоревший по
	// commissionCarryFraction (не выдаётся повторно).
	forfeited float64

	// Проверка пулов отдельным соединением (probe.go); probe == nil — выкл.
	probe  ProbeFunc
	probes map[string]*poolProbe

	// Разбивка по пулам и предохранители (мультипул).
	perPool     map[string]*poolCommission
	breakers    map[string]*poolBreaker
	breakerLogs map[string]time.Time // последний лог открытия breaker (антиспам)

	rng *rand.Rand
}

// CommissionOption — дополнительная настройка комиссии, не влияющая на
// расчёт порций.
type CommissionOption func(*Commission)

// WithWorkerRotation включает ротацию имени воркера комиссии: в каждом окне
// изъятия используется новое имя ("<worker>.r1", "<worker>.r2" и т.д.).
// Нужно пулам с vardiff: у нового воркера нет истории, поэтому пул не
// обрушивает сложность сессии и изъятые шары зачитываются полностью.
func WithWorkerRotation() CommissionOption {
	return func(c *Commission) { c.rotateWorkers = true }
}

// WithSuggestDifficulty включает запрос сложности сессии у пула
// (mining.suggest_difficulty) сразу после служебного authorize: пул
// закрепляет сложность на уровне сложности майнера, даже если у воркера
// комиссии свой vardiff.
func WithSuggestDifficulty() CommissionOption {
	return func(c *Commission) { c.suggestDiff = true }
}

// WithBTCOnly ограничивает комиссию заданиями BTC: соединения с другими
// монетами (и с ещё не опознанной монетой) проходят без изъятия.
func WithBTCOnly() CommissionOption {
	return func(c *Commission) { c.btcOnly = true }
}

// BTCOnly сообщает, ограничена ли комиссия заданиями BTC. Значение
// задаётся опцией при создании и дальше не меняется.
func (c *Commission) BTCOnly() bool {
	return c != nil && c.btcOnly
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
func NewCommission(worker string, percent float64, iterationsPerDay int, interval, session time.Duration, stats *Stats, opts ...CommissionOption) *Commission {
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
	c := &Commission{
		stop:             make(chan struct{}),
		worker:           worker,
		percent:          percent,
		iterationsPerDay: iterationsPerDay,
		interval:         interval,
		session:          session,
		stats:            stats,
		windowStart:      now,
		baseAccepted:     stats.Accepted(),
		baseWork:         stats.AcceptedWork(),
		perPool:          map[string]*poolCommission{},
		breakers:         map[string]*poolBreaker{},
		breakerLogs:      map[string]time.Time{},
		probes:           map[string]*poolProbe{},
		rng:              rand.New(rand.NewSource(now.UnixNano())),
	}
	c.windowWorker = worker
	for _, opt := range opts {
		if opt != nil {
			opt(c)
		}
	}
	return c
}

// WindowWorker возвращает имя воркера комиссии, действующее в текущем окне
// изъятия. При ротации это новое имя в каждом окне; без ротации —
// commission_worker как есть.
func (c *Commission) WindowWorker() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.windowWorker
}

// SuggestDifficulty сообщает, нужно ли просить у пула закрепить сложность
// сессии (mining.suggest_difficulty) после служебного authorize.
func (c *Commission) SuggestDifficulty() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.suggestDiff
}

// advanceWindowWorkerLocked готовит имя воркера для нового окна изъятия:
// при ротации — следующее по счёту имя, без ротации — имя как есть.
// Вызывается под c.mu.
func (c *Commission) advanceWindowWorkerLocked() {
	if !c.rotateWorkers || c.worker == "" {
		c.windowWorker = c.worker
		return
	}
	c.workerSeq++
	c.windowWorker = c.worker + ".r" + strconv.Itoa(c.workerSeq)
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

// iterate выполняет одну итерацию изъятия: начисляет порцию работы
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
		c.baseWork = c.stats.AcceptedWork()
		c.baseFeeWork = c.workAccepted
		c.taken = 0
		c.iterationsUsed = 0
		c.takeBudget = 0
		c.budgetIssued = 0
		c.forfeited = 0
	}
	end := c.windowStart.Add(commissionWindow)

	// Фиксированный интервал: каждый тик добираем бюджет до текущего target
	// = percent% принятой за окно работы. target растёт вместе с работой, поэтому
	// порция пропорциональна принятой работе, а сумма выданного
	// за окно бюджета не превышает target (суточный кап на процент).
	if c.interval > 0 {
		acceptedToday := c.stats.AcceptedWork() - c.baseWork
		target := acceptedToday * c.percent / 100
		batch := target - c.budgetIssued
		if batch < 0 {
			batch = 0
		}
		c.capCarryLocked(batch)
		c.takeBudget += batch
		c.budgetIssued += batch
		c.iterationsUsed++
		if batch > 0 {
			// Новое окно изъятия — новое имя воркера (если включена
			// ротация): у пула нет истории по этому имени, поэтому
			// сложность сессии не обрушивается.
			c.advanceWindowWorkerLocked()
		}

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
				log.Printf("[COMMISSION] every %s: work budget %.3f (accepted work=%.3f, target=%.3f, issued=%.3f, session %s..%s)",
					c.interval, batch, acceptedToday, target, c.budgetIssued,
					c.sessionStart.Format("15:04:05"), c.sessionEnd.Format("15:04:05"))
			} else {
				log.Printf("[COMMISSION] every %s: work budget %.3f (accepted work=%.3f, target=%.3f, issued=%.3f)",
					c.interval, batch, acceptedToday, target, c.budgetIssued)
			}
		}
		// Report accepted work separately from attempts and unanswered shares.
		if c.workSinceTick > 0 || c.acceptedSinceTick > 0 {
			actualTh := c.acceptedSinceTick * diffToHashF / c.interval.Seconds() / 1e12
			expectedTh := float64(c.billableHashrateLocked()) / 1e12 * c.percent / 100
			log.Printf("[COMMISSION] interval sent_work=%.0f accepted_work=%.0f accepted=%.2f TH/s expected=%.2f TH/s (total issued=%.0f accepted=%.0f rejected=%.0f)",
				c.workSinceTick, c.acceptedSinceTick, actualTh, expectedTh, c.workIssued, c.workAccepted, c.workRejected)
			c.workSinceTick = 0
			c.acceptedSinceTick = 0
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

	acceptedToday := c.stats.AcceptedWork() - c.baseWork
	target := acceptedToday * c.percent / 100
	batch := math.Max(0, target-c.budgetIssued) / float64(iterationsLeft)
	c.capCarryLocked(batch)
	c.takeBudget += batch
	c.budgetIssued += batch
	c.iterationsUsed++
	if batch > 0 {
		// Новое окно изъятия — новое имя воркера (если включена ротация).
		c.advanceWindowWorkerLocked()
	}
	if batch > 0 {
		log.Printf("[COMMISSION] iteration %d/%d: work budget %.3f (accepted work=%.3f, target=%.3f, taken=%.3f)",
			c.iterationsUsed, c.iterationsPerDay, batch, acceptedToday,
			target, c.workAccepted-c.baseFeeWork)
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

// billableHashrateLocked — хешрейт, с которого берётся комиссия: весь поток
// или, в режиме btcOnly, только пулы с заданиями BTC. Только для логов.
func (c *Commission) billableHashrateLocked() int64 {
	rep := c.stats.Report()
	if !c.btcOnly {
		return rep.Totals.Hashrate
	}
	var hr int64
	for _, p := range rep.Pools {
		if p.Coin == coinBTC.String() {
			hr += p.Hashrate
		}
	}
	return hr
}

// capCarryLocked ограничивает перенос неизрасходованного бюджета на новый
// тик долей commissionCarryFraction от его порции. Сгоревший остаток уже
// учтён в budgetIssued и повторно не выдаётся. Долг (отрицательный бюджет)
// переносится полностью. Вызывается под c.mu.
func (c *Commission) capCarryLocked(batch float64) {
	limit := batch * commissionCarryFraction
	if c.takeBudget <= limit {
		return
	}
	burnt := c.takeBudget - limit
	c.forfeited += burnt
	c.takeBudget = limit
	log.Printf("[COMMISSION] unspent budget %.0f forfeited (carry limited to %.0f%% of next batch %.0f)",
		burnt, commissionCarryFraction*100, batch)
}

// poolLocked возвращает (создавая при необходимости) счётчики по пулу.
func (c *Commission) poolLocked(pool string) *poolCommission {
	p, ok := c.perPool[pool]
	if !ok {
		p = &poolCommission{}
		c.perPool[pool] = p
	}
	return p
}

// poolOpenLocked true, если предохранитель пула открыт (изъятие
// приостановлено) на момент now.
func (c *Commission) poolOpenLocked(pool string, now time.Time) bool {
	b, ok := c.breakers[pool]
	if !ok {
		return false
	}
	if now.Before(b.failureUntil) {
		return true
	}
	if now.Before(b.difficultyRetryAt) {
		return true
	}
	if now.Before(b.openTill) {
		return true
	}
	// Cooldown истёк — предохранитель закрывается, счётчик отказов сброшен.
	if !b.openTill.IsZero() {
		b.denies = 0
		b.openTill = time.Time{}
	}
	return false
}

// reserve пытается зарезервировать одну шару под комиссию для соединения к
// пулу pool. true — бюджет есть: вызывающий должен переписать воркера шары
// и отправить её в тот же upstream. Потокобезопасно.
//
// Пул с открытым предохранителем (несколько отказов переавторизации подряд)
// пропускается: бюджет не тратится на пул, который не знает
// commission_worker.
//
// Если задано окно изъятия (session > 0), шара забирается только внутри
// текущего окна; вне окна бюджет не тратится и переносится на следующее окно.
func (c *Commission) reserve(pool string, difficulty ...float64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reserveLocked(pool, difficulty...)
}

func reservationWork(difficulty []float64) float64 {
	if len(difficulty) > 0 {
		return difficulty[0]
	}
	return 1
}

func (c *Commission) reserveLocked(pool string, difficulty ...float64) bool {
	work := reservationWork(difficulty)
	if work <= 0 || math.IsNaN(work) || math.IsInf(work, 0) {
		return false
	}
	if c.worker == "" || c.takeBudget <= 0 {
		return false
	}
	if c.poolOpenLocked(pool, time.Now()) {
		return false
	}
	if c.session > 0 {
		now := time.Now()
		if now.Before(c.sessionStart) || !now.Before(c.sessionEnd) {
			return false
		}
	}
	c.takeBudget -= work
	return true
}

// A busy authorization gate skips entry; it never sleeps in a submit pipe.
func (c *Commission) reserveEntry(pool string, difficulty ...float64) bool {
	c.authMu.Lock()
	defer c.authMu.Unlock()
	now := time.Now()
	if !c.lastAuth.IsZero() && now.Sub(c.lastAuth) < 1200*time.Millisecond {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.poolVerifiedLocked(pool, now) {
		return false
	}
	if !c.reserveLocked(pool, difficulty...) {
		return false
	}
	c.lastAuth = now
	return true
}

// Refund unsent work and retry later, rather than reauthorizing on each share.
func (c *Commission) deferDifficulty(pool string, reservedAt time.Time, difficulty ...float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	retryAt := c.nextIterationAt
	if minimum := now.Add(commissionSuggestInterval); retryAt.Before(minimum) {
		retryAt = minimum
	}
	b := c.breakers[pool]
	if b == nil {
		b = &poolBreaker{}
		c.breakers[pool] = b
	}
	b.difficultyRetryAt = retryAt
	if !reservedAt.Before(c.windowStart) {
		c.takeBudget += reservationWork(difficulty)
	}
	c.failedCnt++
	c.poolLocked(pool).failed++
	log.Printf("[COMMISSION] pool=%s difficulty preparation skipped; retry after %s, unsent budget preserved", pool, retryAt.Format(time.RFC3339))
}

// hasBudget checks whether another commission share can be taken without
// reserving it. It allows an exhausted session to restore immediately after
// the last share response, before the ASIC finds its next share.
func (c *Commission) hasBudget(pool string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	return c.worker != "" && c.takeBudget > 0 && !c.poolOpenLocked(pool, now) &&
		(c.session <= 0 || !now.Before(c.sessionStart) && now.Before(c.sessionEnd))
}

// reportDeny сообщает об отказе пула переавторизовать соединение под
// commission_worker. После нескольких отказов подряд пул временно
// исключается из изъятия (предохранитель).
func (c *Commission) reportDeny(pool string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, ok := c.breakers[pool]
	if !ok {
		b = &poolBreaker{}
		c.breakers[pool] = b
	}
	b.denies++
	if b.denies >= commissionBreakerDenies && time.Now().After(b.openTill) {
		b.openTill = time.Now().Add(commissionBreakerCooldown)
		b.denies = 0
		// Антиспам: лог об открытии не чаще раза в cooldown.
		if last, ok := c.breakerLogs[pool]; !ok || time.Since(last) >= commissionBreakerCooldown {
			log.Printf("[COMMISSION] пул %s: %d отказов переавторизации — изъятие приостановлено на %s",
				pool, commissionBreakerDenies, commissionBreakerCooldown)
			c.breakerLogs[pool] = time.Now()
		}
	}
}

// Pause on unanswered commission work, including resets before the submit
// timeout. Authorization success must not clear this independent cooldown.
// Consecutive failures double the pause (up to failurePauseMax); an accepted
// commission share on the pool resets the streak.
func (c *Commission) pauseFailure(pool string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := c.breakers[pool]
	if b == nil {
		b = &poolBreaker{}
		c.breakers[pool] = b
	}
	if time.Now().Before(b.failureUntil) {
		return
	}
	b.failures++
	pause := backoff(commissionBreakerCooldown, failurePauseMax, b.failures)
	b.failureUntil = time.Now().Add(pause)
	log.Printf("[COMMISSION] pool=%s unanswered commission work (%d in a row); paused for %s until %s",
		pool, b.failures, pause, b.failureUntil.Format(time.RFC3339))
}

func acceptedRate(samples []stealSample, now time.Time) float64 {
	var work float64
	start := now.Add(-commissionRateWindow)
	for _, sample := range samples {
		if !sample.at.Before(start) {
			work += sample.diff
		}
	}
	// Fixed window includes silence after the last response, so a stopped
	// commission worker cannot keep reporting its previous hashrate forever.
	return work * diffToHashF / commissionRateWindow.Seconds()
}

// reportAuthOK сбрасывает счётчик отказов пула после успешной
// переавторизации (пул знает commission_worker).
func (c *Commission) reportAuthOK(pool string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if b, ok := c.breakers[pool]; ok {
		b.denies = 0
		b.openTill = time.Time{}
	}
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
// pool — адресат соединения: ведём и общие, и поразбивочные счётчики.
// Возвращает мгновенный и средний хешрейт изъятия по пулу (hash/s).
func (c *Commission) countSteal(pool string, diff float64) (instant, avg float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.attempts++
	c.workIssued += diff
	c.workSinceTick += diff
	p := c.poolLocked(pool)
	p.attempts++
	p.workIssued += diff
	if diff <= 0 {
		return 0, p.avgRateLocked()
	}
	return p.stealRateLocked(time.Now(), diff)
}

// priceUnknownShare adds work which was unknown when countSteal ran.
// Attempts are already counted; only the work and rate sample need updating.
func (c *Commission) priceUnknownShare(pool string, diff float64) {
	if diff <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.workIssued += diff
	c.workSinceTick += diff
	p := c.poolLocked(pool)
	p.workIssued += diff
	p.stealRateLocked(time.Now(), diff)
}

func (c *Commission) countResult(pool string, accepted bool, diff float64, submittedAt ...time.Time) {
	c.stats.commissionResult(diff, accepted)
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.poolLocked(pool)
	if accepted {
		c.acceptedCnt++
		if len(submittedAt) == 0 || !submittedAt[0].Before(c.windowStart) {
			c.taken++
		} else {
			c.baseFeeWork += diff
		}
		c.workAccepted += diff
		c.acceptedSinceTick += diff
		now := time.Now()
		cut := 0
		for cut < len(p.acceptedSamples) && now.Sub(p.acceptedSamples[cut].at) > commissionRateWindow {
			cut++
		}
		p.acceptedSamples = append(p.acceptedSamples[cut:], stealSample{at: now, diff: diff})
		p.accepted++
		p.workAccepted += diff
		if b := c.breakers[pool]; b != nil {
			b.failures = 0
		}
	} else {
		c.rejectedCnt++
		c.workRejected += diff
		// The miner's share is spent either way: rejected commission work is
		// charged and never re-taken from miners on a later tick.
		p.rejected++
		p.workRejected += diff
	}
}

func (c *Commission) countFailed(pool string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failedCnt++
	c.poolLocked(pool).failed++
}

// setFeeDiff запоминает сложность, которую пул назначил воркеру комиссии.
// По ней пул зачитывает изъятые шары: падение сложности = обесценивание
// комиссии.
func (c *Commission) setFeeDiff(pool string, diff float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.poolLocked(pool).feeDiff = diff
}

// PoolCommissionReport — снимок изъятия по одному пулу.
type PoolCommissionReport struct {
	Pool              string  `json:"pool"`
	Attempts          int     `json:"attempts"`
	Accepted          int     `json:"accepted"`
	Rejected          int     `json:"rejected"`
	Failed            int     `json:"failed"`
	WorkIssued        float64 `json:"work_issued"`
	WorkAccepted      float64 `json:"work_accepted"`
	WorkRejected      float64 `json:"work_rejected"`
	FeeDiff           float64 `json:"fee_diff"`  // сложность воркера комиссии на пуле
	StealThs          float64 `json:"steal_ths"` // фактический хешрейт изъятия, TH/s
	BreakerOpen       bool    `json:"breaker_open,omitempty"`
	DifficultyRetryAt string  `json:"difficulty_retry_at,omitempty"`
}

// CommissionReport — снимок комиссии для /status.commission.
type CommissionReport struct {
	Enabled          bool                   `json:"enabled"`
	Worker           string                 `json:"worker,omitempty"`
	WindowWorker     string                 `json:"-"`
	WorkerRotate     bool                   `json:"worker_rotate,omitempty"`
	Percent          float64                `json:"percent,omitempty"`
	Interval         string                 `json:"interval,omitempty"`
	Session          string                 `json:"session,omitempty"`
	SessionStart     string                 `json:"session_start,omitempty"`
	SessionEnd       string                 `json:"session_end,omitempty"`
	IterationsPerDay int                    `json:"iterations_per_day,omitempty"`
	Attempts         int                    `json:"attempts"`
	Accepted         int                    `json:"accepted"`
	Rejected         int                    `json:"rejected"`
	Failed           int                    `json:"failed"`
	WorkIssued       float64                `json:"-"`
	WorkAccepted     float64                `json:"-"`
	WorkRejected     float64                `json:"-"`
	EffectivePercent float64                `json:"effective_percent"`
	ChargedPercent   float64                `json:"charged_percent"`
	ForfeitedWork    float64                `json:"forfeited_work"`
	PoolChecks       map[string]string      `json:"pool_checks,omitempty"`
	AcceptedToday    int                    `json:"accepted_today"`
	TargetToday      float64                `json:"-"`
	TakenToday       int                    `json:"taken_today"`
	IterationsUsed   int                    `json:"iterations_used"`
	IterationsLeft   int                    `json:"iterations_left"`
	NextIterationAt  string                 `json:"next_iteration_at,omitempty"`
	WindowEnd        string                 `json:"window_end,omitempty"`
	Pools            []PoolCommissionReport `json:"-"`
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
	target := (c.stats.AcceptedWork() - c.baseWork) * c.percent / 100
	left := c.iterationsPerDay - c.iterationsUsed
	if left < 0 {
		left = 0
	}
	rep := CommissionReport{
		Enabled:          true,
		Worker:           c.worker,
		WindowWorker:     c.windowWorker,
		WorkerRotate:     c.rotateWorkers,
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
		EffectivePercent: workPercent(c.workAccepted-c.baseFeeWork, c.stats.AcceptedWork()-c.baseWork),
		ChargedPercent:   workPercent(c.budgetIssued-c.forfeited-c.takeBudget, c.stats.AcceptedWork()-c.baseWork),
		ForfeitedWork:    c.forfeited,
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
	now := time.Now()
	seen := map[string]bool{}
	for name, p := range c.perPool {
		seen[name] = true
		rep.Pools = append(rep.Pools, PoolCommissionReport{
			Pool:              name,
			Attempts:          p.attempts,
			Accepted:          p.accepted,
			Rejected:          p.rejected,
			Failed:            p.failed,
			WorkIssued:        p.workIssued,
			WorkAccepted:      p.workAccepted,
			WorkRejected:      p.workRejected,
			FeeDiff:           p.feeDiff,
			StealThs:          acceptedRate(p.acceptedSamples, now) / 1e12,
			BreakerOpen:       c.poolOpenLocked(name, now),
			DifficultyRetryAt: c.difficultyRetryStringLocked(name, now),
		})
	}
	// Пулы, где известен только предохранитель (изъятия ещё не было или
	// все попытки отвергнуты до счётчика).
	for name := range c.breakers {
		if seen[name] {
			continue
		}
		rep.Pools = append(rep.Pools, PoolCommissionReport{
			Pool:              name,
			BreakerOpen:       c.poolOpenLocked(name, now),
			DifficultyRetryAt: c.difficultyRetryStringLocked(name, now),
		})
	}
	for name := range c.probes {
		if v := c.probeVerdictLocked(name); v != "" {
			if rep.PoolChecks == nil {
				rep.PoolChecks = map[string]string{}
			}
			rep.PoolChecks[name] = v
		}
	}
	sort.Slice(rep.Pools, func(i, j int) bool { return rep.Pools[i].Pool < rep.Pools[j].Pool })
	return rep
}

func (c *Commission) difficultyRetryStringLocked(pool string, now time.Time) string {
	if b := c.breakers[pool]; b != nil && now.Before(b.difficultyRetryAt) {
		return b.difficultyRetryAt.Format(time.RFC3339)
	}
	return ""
}

// settleReservation reconciles the estimated work with the pool's fee difficulty.
// A negative balance is carried to the next tick, bounding overshoot to shares
// already reserved by concurrent connections. Unsent shares refund the estimate.
func (c *Commission) settleReservation(at time.Time, reserved, actual float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !at.Before(c.windowStart) {
		c.takeBudget += reserved - actual
	}
}

func workPercent(fee, ordinary float64) float64 {
	if ordinary <= 0 {
		return 0
	}
	return fee / ordinary * 100
}

// Unanswered shares are not rejects, but the miner's share is spent: the
// work stays charged and is never re-taken from miners on a later tick.
func (c *Commission) lostWork(diff float64, at time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failedCnt++
}

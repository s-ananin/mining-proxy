// Файл stats.go — реестр статистики шар.
//
// Единственный источник данных для /status. Ведёт счётчики по трём уровням:
// totals (весь поток), пул (адресат соединения) и воркер (пул + имя).
//
// Шара проходит через реестр двумя событиями:
//
//	Submit  — майнер отправил mining.submit (в момент отправки шара
//	          штампуется текущей сложностью пула);
//	Result  — пул ответил result:true/false (принято/отклонено).
//
// Если ответа не дождались (соединение закрылось или пул молчит дольше
// pendingTimeout) — шара считается lost: отправлена, но не подтверждена.
//
// Хешрейт считается из принятых шар: hashrate = sum(difficulty) * 2^32 /
// интервал, окно — последние hashrateWindow.
package proxy

import (
	"fmt"
	"log"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// hashrateWindow окно усреднения хешрейта (принятые шары старше
	// этого времени не участвуют в расчёте).
	hashrateWindow = 15 * time.Minute

	// maxShareSamples сколько последних принятых шар хранится на воркера
	// (ограничение памяти при тысячах воркеров).
	maxShareSamples = 256

	// pendingTimeout сколько ждём ответа пула на шару, прежде чем
	// счесть её потерянной (long-polling/зависший пул не должен копить
	// счётчики вечно).
	pendingTimeout = 5 * time.Minute

	// unknownWorker имя воркера, если майнер не назвался (редкий случай).
	unknownWorker = "(unknown)"

	// diffToHash коэффициент перевода сложности в хеш: 1 диффикат =
	// 2^32 хэшей на шару.
	diffToHash = 4294967296.0
)

// shareSample — принятая шара для расчёта хешрейта.
type shareSample struct {
	at   time.Time
	diff float64
}

// poolStat счётчики одного пула (адресата соединения).
type poolStat struct {
	pool      string
	conns     int
	submits   int
	accepted  int
	rejected  int
	lost      int
	workers   map[string]struct{}
	firstSeen time.Time
	lastSeen  time.Time
}

// workerStat счётчики одного воркера (пара пул+имя).
type workerStat struct {
	pool       string
	worker     string
	source     string
	conns      int
	submits    int
	accepted   int
	rejected   int
	lost       int
	difficulty float64
	lastJobID  string
	lastError  string
	firstSeen  time.Time
	lastSeen   time.Time
	samples    []shareSample // только принятые шары, для хешрейта
}

// Stats потокобезопасный реестр. Все методы можно вызывать из разных
// goroutine (по одной на соединение).
type Stats struct {
	mu          sync.Mutex
	start       time.Time
	connsTotal  int
	connsActive int
	submits     int
	accepted    int
	rejected    int
	lost        int
	pools       map[string]*poolStat
	workers     map[string]*workerStat
	diagnostics diagnostics
}

// diagnostics keeps bounded-cardinality, rate-limited protocol summaries.
// It avoids emitting one log line per rejected share or per job notification.
type diagnostics struct {
	mu       sync.Mutex
	rejects  map[string]*rejectDiagnostic
	notifies map[string]*notifyDiagnostic
	controls map[string]*controlDiagnostic
	steals   map[string]*stealDiagnostic
}

type rejectDiagnostic struct {
	count       int
	lastLog     time.Time
	lastError   string
	lastJob     string
	lastAuthAge time.Duration
	lastJobAge  time.Duration
}

type notifyDiagnostic struct {
	count     int
	clean     int
	lastLog   time.Time
	lastJobID string
}

type controlDiagnostic struct {
	count     int
	lastLog   time.Time
	lastError string
}

type stealDiagnostic struct {
	count     int
	lastLog   time.Time
	worker    string
	diff      float64
	minerDiff float64
}

const (
	rejectDiagnosticInterval   = 30 * time.Second
	protocolDiagnosticInterval = time.Minute
)

// NewStats создаёт пустой реестр.
func NewStats() *Stats {
	return &Stats{
		start:   time.Now(),
		pools:   map[string]*poolStat{},
		workers: map[string]*workerStat{},
	}
}

// wkey ключ воркера: пул и имя разделены NUL (имена воркеров могут
// содержать что угодно, кроме NUL).
func wkey(pool, worker string) string { return pool + "\x00" + worker }

func (s *Stats) getPool(pool string, now time.Time) *poolStat {
	p, ok := s.pools[pool]
	if !ok {
		p = &poolStat{pool: pool, firstSeen: now, workers: map[string]struct{}{}}
		s.pools[pool] = p
	}
	return p
}

func (s *Stats) getWorker(pool, worker string, now time.Time) *workerStat {
	k := wkey(pool, worker)
	w, ok := s.workers[k]
	if !ok {
		w = &workerStat{pool: pool, worker: worker, firstSeen: now}
		s.workers[k] = w
	}
	return w
}

// Connect регистрирует новое TCP-соединение к пулу.
func (s *Stats) Connect(pool string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.connsTotal++
	s.connsActive++
	p := s.getPool(pool, now)
	p.conns++
	p.lastSeen = now
}

// Disconnect снимает соединение (вызывается при закрытии сессии).
func (s *Stats) Disconnect(pool string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.connsActive > 0 {
		s.connsActive--
	}
	if p, ok := s.pools[pool]; ok && p.conns > 0 {
		p.conns--
	}
}

// BindWorker привязывает воркера к соединению (authorize или submit).
func (s *Stats) BindWorker(pool, worker, source string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	w := s.getWorker(pool, worker, now)
	w.conns++
	if source != "" {
		w.source = source
	}
	w.lastSeen = now
	s.getPool(pool, now).workers[worker] = struct{}{}
}

// UnbindWorker снимает привязку воркера при закрытии соединения.
func (s *Stats) UnbindWorker(pool, worker string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if w, ok := s.workers[wkey(pool, worker)]; ok && w.conns > 0 {
		w.conns--
	}
}

// Submit фиксирует отправленную шару. difficulty — сложность на момент
// отправки (0, если пул ещё не прислал set_difficulty).
func (s *Stats) Submit(pool, worker, source string, difficulty float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.submits++
	p := s.getPool(pool, now)
	p.submits++
	p.lastSeen = now
	w := s.getWorker(pool, worker, now)
	w.submits++
	w.difficulty = difficulty
	if source != "" {
		w.source = source
	}
	w.lastSeen = now
	p.workers[worker] = struct{}{}
}

// Submits возвращает число отправленных майнерами шар (для тестов и
// внешних расчётов).
func (s *Stats) Submits() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.submits
}

// Accepted возвращает число принятых реальным пулом шар. Используется
// комиссией для расчёта суточного target (percent от accepted).
func (s *Stats) Accepted() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accepted
}

// Result фиксирует ответ пула на шару: accepted=true → result:true.
// rejected шары получают lastError (причина из error[1]).
func (s *Stats) Result(pool, worker string, difficulty float64, accepted bool, errText string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	p := s.getPool(pool, now)
	w := s.getWorker(pool, worker, now)
	if accepted {
		s.accepted++
		p.accepted++
		w.accepted++
		w.samples = trimSamples(append(w.samples, shareSample{at: now, diff: difficulty}))
	} else {
		s.rejected++
		p.rejected++
		w.rejected++
		if errText != "" {
			w.lastError = errText
		}
	}
	p.lastSeen = now
	w.lastSeen = now
}

// noteShareReject aggregates rejects per pool, reason class, and auth mode.
func (s *Stats) noteShareReject(pool, reason string, commission bool, job string, authAge, jobAge time.Duration) {
	category := shareErrorCategory(reason)
	key := pool + "\x00" + category + fmt.Sprint("\x00", commission)
	now := time.Now()
	d := &s.diagnostics
	d.mu.Lock()
	if d.rejects == nil {
		d.rejects = make(map[string]*rejectDiagnostic)
	}
	b := d.rejects[key]
	if b == nil {
		b = &rejectDiagnostic{}
		d.rejects[key] = b
	}
	b.count++
	b.lastError, b.lastJob, b.lastAuthAge, b.lastJobAge = reason, job, authAge, jobAge
	if b.lastLog.IsZero() || now.Sub(b.lastLog) >= rejectDiagnosticInterval {
		count := b.count
		window := "first"
		if !b.lastLog.IsZero() {
			window = now.Sub(b.lastLog).Round(time.Second).String()
		}
		errSample, jobSample, authSample, jobAgeSample := b.lastError, b.lastJob, b.lastAuthAge, b.lastJobAge
		b.count = 0
		b.lastLog = now
		d.mu.Unlock()
		log.Printf("[DIAG] share_reject pool=%s class=%s mode=%s count=%d window=%s sample_error=%q sample_job=%q since_auth=%s job_age=%s",
			pool, category, diagnosticMode(commission), count, window, errSample, jobSample,
			durationOrUnknown(authSample), durationOrUnknown(jobAgeSample))
		return
	}
	d.mu.Unlock()
}

func (s *Stats) noteNotify(pool, jobID string, clean bool) {
	now := time.Now()
	d := &s.diagnostics
	d.mu.Lock()
	if d.notifies == nil {
		d.notifies = make(map[string]*notifyDiagnostic)
	}
	b := d.notifies[pool]
	if b == nil {
		b = &notifyDiagnostic{}
		d.notifies[pool] = b
	}
	b.count++
	if clean {
		b.clean++
	}
	b.lastJobID = jobID
	if b.lastLog.IsZero() || now.Sub(b.lastLog) >= protocolDiagnosticInterval {
		count, cleanCount, job := b.count, b.clean, b.lastJobID
		window := "first"
		if !b.lastLog.IsZero() {
			window = now.Sub(b.lastLog).Round(time.Second).String()
		}
		b.count, b.clean, b.lastLog = 0, 0, now
		d.mu.Unlock()
		log.Printf("[DIAG] pool_notify pool=%s count=%d clean_jobs=%d window=%s last_job=%q", pool, count, cleanCount, window, job)
		return
	}
	d.mu.Unlock()
}

func (s *Stats) noteControl(pool, method string, accepted bool, reason string) {
	key := pool + "\x00" + method + fmt.Sprint("\x00", accepted)
	now := time.Now()
	d := &s.diagnostics
	d.mu.Lock()
	if d.controls == nil {
		d.controls = make(map[string]*controlDiagnostic)
	}
	b := d.controls[key]
	if b == nil {
		b = &controlDiagnostic{}
		d.controls[key] = b
	}
	b.count++
	if reason != "" {
		b.lastError = reason
	}
	if b.lastLog.IsZero() || now.Sub(b.lastLog) >= protocolDiagnosticInterval {
		count, sample := b.count, b.lastError
		window := "first"
		if !b.lastLog.IsZero() {
			window = now.Sub(b.lastLog).Round(time.Second).String()
		}
		b.count, b.lastLog = 0, now
		d.mu.Unlock()
		log.Printf("[DIAG] control_response pool=%s method=%s accepted=%t count=%d window=%s sample_error=%q", pool, method, accepted, count, window, sample)
		return
	}
	d.mu.Unlock()
}

func (s *Stats) noteCommissionSteal(pool, worker string, diff, minerDiff float64) {
	now := time.Now()
	d := &s.diagnostics
	d.mu.Lock()
	if d.steals == nil {
		d.steals = make(map[string]*stealDiagnostic)
	}
	b := d.steals[pool]
	if b == nil {
		b = &stealDiagnostic{}
		d.steals[pool] = b
	}
	b.count++
	b.worker, b.diff, b.minerDiff = worker, diff, minerDiff
	if b.lastLog.IsZero() || now.Sub(b.lastLog) >= rejectDiagnosticInterval {
		count, lastWorker, lastDiff, lastMinerDiff := b.count, b.worker, b.diff, b.minerDiff
		window := "first"
		if !b.lastLog.IsZero() {
			window = now.Sub(b.lastLog).Round(time.Second).String()
		}
		b.count, b.lastLog = 0, now
		d.mu.Unlock()
		log.Printf("[DIAG] commission_share pool=%s count=%d window=%s last_worker=%q diff=%g miner_diff=%g",
			pool, count, window, lastWorker, lastDiff, lastMinerDiff)
		return
	}
	d.mu.Unlock()
}

func diagnosticMode(commission bool) string {
	if commission {
		return "commission"
	}
	return "miner"
}

func durationOrUnknown(d time.Duration) string {
	if d < 0 {
		return "unknown"
	}
	return d.Round(time.Millisecond).String()
}

func shareErrorCategory(reason string) string {
	s := strings.ToLower(reason)
	switch {
	case strings.Contains(s, "unknown job"), strings.Contains(s, "undefined job"), strings.Contains(s, "job not found"):
		return "unknown_job"
	case strings.Contains(s, "stale"):
		return "stale"
	case strings.Contains(s, "duplicate"):
		return "duplicate"
	case strings.Contains(s, "low difficulty"):
		return "low_difficulty"
	case strings.Contains(s, "unauthor"):
		return "unauthorized"
	default:
		return "other"
	}
}

// LostShare фиксирует шару без ответа пула (обрыв соединения или таймаут).
func (s *Stats) LostShare(pool, worker string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.lost++
	p := s.getPool(pool, now)
	p.lost++
	w := s.getWorker(pool, worker, now)
	w.lost++
	p.lastSeen = now
	w.lastSeen = now
}

// SetDifficulty обновляет текущую сложность воркера из set_difficulty.
func (s *Stats) SetDifficulty(pool, worker string, difficulty float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.getWorker(pool, worker, time.Now())
	w.difficulty = difficulty
}

// SetJobID запоминает последний id задания воркера из mining.notify.
func (s *Stats) SetJobID(pool, worker, jobID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.getWorker(pool, worker, time.Now())
	w.lastJobID = jobID
}

// trimSamples выкидывает сэмплы старше hashrateWindow и ограничивает
// хранилище maxShareSamples последних. Возвращает новый срез — вызывающая
// сторона обязана переприсвоить поле.
func trimSamples(samples []shareSample) []shareSample {
	if len(samples) == 0 {
		return samples
	}
	cutoff := time.Now().Add(-hashrateWindow)
	i := 0
	for i < len(samples) && samples[i].at.Before(cutoff) {
		i++
	}
	if i > 0 {
		samples = samples[i:]
	}
	for len(samples) > maxShareSamples {
		samples = samples[1:]
	}
	return samples
}

// --- Снимок для /status -----------------------------------------------------

// Totals — сводные счётчики потока.
type Totals struct {
	ConnectionsActive int     `json:"connections_active"`
	ConnectionsTotal  int     `json:"connections_total"`
	Submits           int     `json:"submits"`
	Accepted          int     `json:"accepted"`
	Rejected          int     `json:"rejected"`
	Lost              int     `json:"lost"`
	AcceptedPercent   float64 `json:"accepted_percent"`
	Hashrate          int64   `json:"hashrate"`
	Pools             int     `json:"pools"`
	Workers           int     `json:"workers"`
}

// WorkerReport — счётчики одного воркера.
type WorkerReport struct {
	Pool            string  `json:"pool"`
	Worker          string  `json:"worker"`
	Source          string  `json:"source,omitempty"`
	Connections     int     `json:"connections"`
	Difficulty      float64 `json:"difficulty"`
	Submits         int     `json:"submits"`
	Accepted        int     `json:"accepted"`
	Rejected        int     `json:"rejected"`
	Lost            int     `json:"lost"`
	AcceptedPercent float64 `json:"accepted_percent"`
	Hashrate        int64   `json:"hashrate"`
	LastJobID       string  `json:"last_job_id,omitempty"`
	LastError       string  `json:"last_error,omitempty"`
	FirstSeen       string  `json:"first_seen"`
	LastSeen        string  `json:"last_seen"`
}

// PoolReport — счётчики одного пула.
type PoolReport struct {
	Pool            string  `json:"pool"`
	Connections     int     `json:"connections"`
	Submits         int     `json:"submits"`
	Accepted        int     `json:"accepted"`
	Rejected        int     `json:"rejected"`
	Lost            int     `json:"lost"`
	AcceptedPercent float64 `json:"accepted_percent"`
	Hashrate        int64   `json:"hashrate"`
	Workers         int     `json:"workers"`
	FirstSeen       string  `json:"first_seen"`
	LastSeen        string  `json:"last_seen"`
}

// Report — полный снимок реестра для /status.
type Report struct {
	Uptime  string         `json:"uptime"`
	Totals  Totals         `json:"totals"`
	Pools   []PoolReport   `json:"pools"`
	Workers []WorkerReport `json:"workers"`
}

// Report строит снимок статистики. Счётчики копируются под мьютексом,
// расчёт хешрейта идёт по копиям — держать блокировку дорого не нужно,
// но мы всё равно берём её коротко для консистентности.
func (s *Stats) Report() Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()

	rep := Report{
		Uptime: now.Sub(s.start).Round(time.Second).String(),
		Totals: Totals{
			ConnectionsActive: s.connsActive,
			ConnectionsTotal:  s.connsTotal,
			Submits:           s.submits,
			Accepted:          s.accepted,
			Rejected:          s.rejected,
			Lost:              s.lost,
			AcceptedPercent:   percent(s.accepted, s.submits),
		},
	}

	// Пулы: отдельная копия, чтобы не держать данные под блокировкой.
	// Показываем только пулы с активными соединениями — «мертвые» записи
	// (после реконнекта ASIC на другой IP) в отчёте не нужны.
	for _, p := range s.pools {
		if p.conns == 0 {
			continue
		}
		pr := PoolReport{
			Pool:            p.pool,
			Connections:     p.conns,
			Submits:         p.submits,
			Accepted:        p.accepted,
			Rejected:        p.rejected,
			Lost:            p.lost,
			AcceptedPercent: percent(p.accepted, p.submits),
			Workers:         len(p.workers),
			FirstSeen:       p.firstSeen.Format(time.RFC3339),
			LastSeen:        p.lastSeen.Format(time.RFC3339),
		}
		rep.Pools = append(rep.Pools, pr)
	}
	sort.Slice(rep.Pools, func(i, j int) bool {
		return rep.Pools[i].Pool < rep.Pools[j].Pool
	})

	// Воркеры + хешрейт по каждому. Показываем только воркеров с активными
	// соединениями, иначе после реконнектов в отчёте копятся «мертвые»
	// записи с нулём соединений.
	poolHash := map[string]int64{}
	for _, w := range s.workers {
		if w.conns == 0 {
			continue
		}
		hr := hashrate(w.samples, now)
		poolHash[w.pool] += hr
		wr := WorkerReport{
			Pool:            w.pool,
			Worker:          w.worker,
			Source:          w.source,
			Connections:     w.conns,
			Difficulty:      w.difficulty,
			Submits:         w.submits,
			Accepted:        w.accepted,
			Rejected:        w.rejected,
			Lost:            w.lost,
			AcceptedPercent: percent(w.accepted, w.submits),
			Hashrate:        hr,
			LastJobID:       w.lastJobID,
			LastError:       w.lastError,
			FirstSeen:       w.firstSeen.Format(time.RFC3339),
			LastSeen:        w.lastSeen.Format(time.RFC3339),
		}
		rep.Workers = append(rep.Workers, wr)
		rep.Totals.Hashrate += hr
	}
	sort.Slice(rep.Workers, func(i, j int) bool {
		a, b := rep.Workers[i], rep.Workers[j]
		if a.Pool != b.Pool {
			return a.Pool < b.Pool
		}
		return a.Worker < b.Worker
	})

	for i := range rep.Pools {
		rep.Pools[i].Hashrate = poolHash[rep.Pools[i].Pool]
	}
	rep.Totals.Pools = len(rep.Pools)
	rep.Totals.Workers = len(rep.Workers)
	return rep
}

// hashrate оценивает хешрейт (H/s) по принятым шарам в окне:
// суммарная работа (difficulty * 2^32) / время от первой до последней шары.
// Меньше двух шар в окне — данных недостаточно, возвращаем 0.
func hashrate(samples []shareSample, now time.Time) int64 {
	var sum float64
	var first, last time.Time
	n := 0
	for _, s := range samples {
		if now.Sub(s.at) > hashrateWindow {
			continue
		}
		if n == 0 {
			first = s.at
		}
		last = s.at
		sum += s.diff
		n++
	}
	if n < 2 {
		return 0
	}
	span := last.Sub(first).Seconds()
	if span <= 0 {
		return 0
	}
	return int64(sum * diffToHash / span)
}

// percent доля принятых шар в процентах, округлённая до сотых.
// При нуле отправленных — 0 (а не NaN).
func percent(accepted, total int) float64 {
	if total <= 0 {
		return 0
	}
	return math.Round(float64(accepted)/float64(total)*10000) / 100
}

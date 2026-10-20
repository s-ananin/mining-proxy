// Файл session.go — состояние одного соединения майнер↔пул.
//
// Сессия живёт ровно столько, сколько TCP-соединение, и отвечает за три
// вещи:
//
//   - текущий воркер соединения (authorize / подмена в submit);
//   - текущую сложность пула (mining.set_difficulty) — ею штампуются шары;
//   - таблицу ожидающих ответа шар (id запроса → воркер и сложность).
//
// Обе стороны соединения (майнер→пул и пул→майнер) работают в своих
// goroutine и сюда заходят под мьютексом сессии; сам реестр Stats
// потокобезопасен, обратных вызовов в сессию он не делает.
package proxy

import (
	"sync"
	"time"
)

// pendingShare — отправленная шара, ждущая ответа пула.
type pendingShare struct {
	worker string
	diff   float64
	at     time.Time
}

// session — привязка соединения к реестру статистики.
type session struct {
	mu      sync.Mutex
	stats   *Stats
	pool    string // адресат соединения (реальный пул из DNAT)
	source  string // IP майнера (без порта)
	worker  string // текущий воркер (пусто, пока не авторизовался)
	diff    float64
	pending map[string]pendingShare
	closed  bool
}

// newSession регистрирует соединение в реестре.
func newSession(stats *Stats, pool, source string) *session {
	s := &session{
		stats:   stats,
		pool:    pool,
		source:  source,
		pending: map[string]pendingShare{},
	}
	s.stats.Connect(pool)
	return s
}

// normalizeWorker пустое имя заменяет на заглушку, чтобы в отчёте не
// появлялся воркер с пустым именем.
func normalizeWorker(w string) string {
	if w == "" {
		return unknownWorker
	}
	return w
}

// bindWorkerLocked привязывает воркера к сессии (вызывается под s.mu).
// Повторный authorize с тем же именем — no-op, смена имени переносит
// привязку (unbind старого, bind нового).
func (s *session) bindWorkerLocked(worker string) {
	if worker == "" || worker == s.worker {
		return
	}
	if s.worker != "" {
		s.stats.UnbindWorker(s.pool, s.worker)
	}
	s.worker = worker
	s.stats.BindWorker(s.pool, worker, s.source)
}

// authorize обрабатывает mining.authorize.
func (s *session) authorize(worker string) {
	if worker == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bindWorkerLocked(worker)
}

// setDifficulty запоминает сложность из mining.set_difficulty и обновляет
// её в реестре (текущая сложность воркера видна в /status).
func (s *session) setDifficulty(diff float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.diff = diff
	if s.worker != "" {
		s.stats.SetDifficulty(s.pool, s.worker, diff)
	}
}

// setJobID запоминает последний mining.notify (id задания) для текущего
// воркера сессии — виден в /status как last_job_id.
func (s *session) setJobID(jobID string) {
	if jobID == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.worker != "" {
		s.stats.SetJobID(s.pool, s.worker, jobID)
	}
}

// submit фиксирует mining.submit: штампует шару текущей сложностью,
// кладёт её в таблицу ожидающих и увеличивает счётчики. Если майнер в
// submit назвал другого воркера — привязка переносится.
//
// id пустой (нет id в запросе) — шара учитывается, но сопоставить ответ
// будет нельзя: она останется незакрытой до закрытия сессии.
func (s *session) submit(id, worker string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if worker != "" {
		s.bindWorkerLocked(normalizeWorker(worker))
	}
	w := s.worker
	if w == "" {
		w = unknownWorker
	}
	now := time.Now()

	// Шары, по которым пул промолчал дольше pendingTimeout, списываем
	// в lost прямо по ходу — таблица не должна расти бесконечно.
	for k, p := range s.pending {
		if now.Sub(p.at) > pendingTimeout {
			delete(s.pending, k)
			s.stats.LostShare(s.pool, p.worker)
		}
	}

	s.stats.Submit(s.pool, w, s.source, s.diff)
	if id != "" {
		s.pending[id] = pendingShare{worker: w, diff: s.diff, at: now}
	}
}

// resolve закрывает шару по ответу пула. Возвращает false, если id не
// известен (ответ на subscribe/authorize или дубль) — тогда строка просто
// проксируется дальше без влияния на статистику.
func (s *session) resolve(resp PoolResponse) bool {
	s.mu.Lock()
	p, ok := s.pending[resp.ID]
	if ok {
		delete(s.pending, resp.ID)
	}
	s.mu.Unlock()
	if !ok {
		return false
	}
	s.stats.Result(s.pool, p.worker, p.diff, resp.Accepted, resp.Error)
	return true
}

// close завершает сессию: неотвеченные шары списываются в lost,
// привязка воркера и соединение снимаются. Идемпотентно.
func (s *session) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	for _, p := range s.pending {
		s.stats.LostShare(s.pool, p.worker)
	}
	s.pending = nil
	if s.worker != "" {
		s.stats.UnbindWorker(s.pool, s.worker)
	}
	s.stats.Disconnect(s.pool)
}

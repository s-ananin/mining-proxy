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
	"log"
	"sync"
	"time"
)

// pendingShare — отправленная шара, ждущая ответа пула. commission = true,
// если шара забрана комиссией (ответ учтётся в счётчиках комиссии, а не в
// статистике воркера майнера).
type pendingShare struct {
	worker     string
	diff       float64
	at         time.Time
	commission bool
}

// session — привязка соединения к реестру статистики.
type session struct {
	mu         sync.Mutex
	stats      *Stats
	pool       string // адресат соединения (реальный пул из DNAT)
	source     string // IP майнера (без порта)
	worker     string // текущий воркер (пусто, пока не авторизовался)
	diff       float64
	pending    map[string]pendingShare
	closed     bool
	commission *Commission   // сборщик комиссии; nil — выключена
	feeDenied  bool          // пул отклонил служебный authorize — не изымаем
	feeActive  bool          // соединение авторизовано под commission_worker
	commAck    chan struct{} // ответ пула на текущую изъятую шару (сериализация)
}

// newSession регистрирует соединение в реестре.
func newSession(stats *Stats, pool, source string, commission *Commission) *session {
	s := &session{
		stats:      stats,
		pool:       pool,
		source:     source,
		pending:    map[string]pendingShare{},
		commission: commission,
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

// workerName возвращает текущий воркер майнера (из mining.authorize) — по
// нему комиссия возвращает соединение после изъятия.
func (s *session) workerName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.worker
}

// denyFee помечает, что пул отклонил служебную переавторизацию: на этом
// соединении комиссия больше не изымается (fail-open для майнера).
func (s *session) denyFee() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.feeDenied = true
}

// feeDeniedNow сообщает, отклонял ли пул служебную переавторизацию.
func (s *session) feeDeniedNow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.feeDenied
}

// setFeeActive помечает, что соединение сейчас авторизовано под
// commission_worker (служебная переавторизация). Пока флаг стоит, пул→майнер
// не применяет и не пробрасывает set_difficulty: иначе пул навязывает
// соединению сложность commission_worker (например 16384 вместо 524288 у
// майнера), ASIC переезжает на неё, и изъятые шары весят в разы меньше.
func (s *session) setFeeActive(v bool) {
	s.mu.Lock()
	s.feeActive = v
	s.mu.Unlock()
}

// feeActiveNow сообщает, идёт ли сейчас изъятие на этом соединении.
func (s *session) feeActiveNow() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.feeActive
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
//
// Диагностика: смена сложности логируется как old->new. Это ключ к «затуханию»
// комиссии: изъятые шары штампуются текущей сложностью соединения, поэтому
// падение сложности (например, из-за служебной переавторизации) напрямую
// уменьшает work, который видит пул по commission_worker.
func (s *session) setDifficulty(diff float64) {
	s.mu.Lock()
	old := s.diff
	s.diff = diff
	if s.worker != "" {
		s.stats.SetDifficulty(s.pool, s.worker, diff)
	}
	s.mu.Unlock()
	if old != diff {
		log.Printf("[CONN] пул %s: set_difficulty %g -> %g (воркер %q)", s.pool, old, diff, s.workerName())
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
			if p.commission {
				continue // комиссионные в lost воркера не пишем
			}
			s.stats.LostShare(s.pool, p.worker)
		}
	}

	s.stats.Submit(s.pool, w, s.source, s.diff)
	if id != "" {
		s.pending[id] = pendingShare{worker: w, diff: s.diff, at: now}
	}
}

// markCommissionSubmit регистрирует забранную комиссией шару как ожидающую
// ответа пула. Ответ по её id уйдёт в счётчики комиссии, а не воркеру
// майнера (см. resolve). Возвращает сложность шары (текущую сложность
// соединения) — комиссия копит по ней work.
func (s *session) markCommissionSubmit(id string) float64 {
	if id == "" {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending[id] = pendingShare{commission: true, diff: s.diff, at: time.Now()}
	return s.diff
}

// armCommissionAck заводит канал ответа для очередной изъятой шары: пока
// ответа нет, pipeMinerToPool не отправляет следующую (сериализация изъятия).
func (s *session) armCommissionAck() chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commAck = make(chan struct{}, 1)
	return s.commAck
}

// signalCommission сообщает отправителю, что по текущей изъятой шаре пришёл
// ответ пула (зачёт или отказ) — можно отправлять следующую.
func (s *session) signalCommission() {
	s.mu.Lock()
	ch := s.commAck
	s.mu.Unlock()
	if ch != nil {
		select {
		case ch <- struct{}{}:
		default:
		}
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
	if p.commission {
		if s.commission != nil {
			s.commission.countResult(resp.Accepted, p.diff)
			if resp.Accepted {
				log.Printf("[COMMISSION] пул %s зачёл шару воркера %q (diff %g)",
					s.pool, s.commission.worker, p.diff)
			} else {
				log.Printf("[COMMISSION] пул %s отклонил шару воркера %q (diff %g): %s",
					s.pool, s.commission.worker, p.diff, resp.Error)
			}
		}
		s.signalCommission()
		return true
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
		if p.commission {
			continue // комиссионные шары в lost воркера не пишем
		}
		s.stats.LostShare(s.pool, p.worker)
	}
	s.pending = nil
	if s.worker != "" {
		s.stats.UnbindWorker(s.pool, s.worker)
	}
	s.stats.Disconnect(s.pool)
}

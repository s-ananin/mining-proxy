package proxy

import (
	"net"
	"sort"
	"sync"
	"time"
)

// Discovery — встроенная «база» пар (пул, воркер), которую прокси собирает
// из живого трафика. Нужна, чтобы видеть, кто и куда майнит (какие пулы и
// воркеры реально присутствуют в подсети), и затем применять правила кражи
// по этим парам (этап 4).
//
// Пул — реальный адресат соединения (IP:port из SO_ORIGINAL_DST в прозрачном
// режиме либо upstream_pool). Воркер — из mining.authorize / mining.submit.
//
// Важно: TLS-потоки не разбираются (данные зашифрованы), поэтому в реестр
// попадает только plaintext-Stratum. Для «голых» IP:port ключом становится
// сам IP:port — это закрывает случай DNS-блокировок.
type Discovery struct {
	mu    sync.Mutex
	pools map[string]*PoolRecord
}

// Ограничения, чтобы реестр не рос бесконечно при аномальном трафике.
// При переполнении вытесняется запись с самым старым LastSeen.
const (
	maxPools          = 5000
	maxWorkersPerPool = 50000
)

// PoolRecord — один обнаруженный пул и его воркеры.
type PoolRecord struct {
	Pool      string                   // адрес пула (IP:port или host:port)
	FirstSeen time.Time                // когда впервые увидели
	LastSeen  time.Time                // последняя активность
	Submits   int64                    // сколько mining.submit от пула (всего)
	Workers   map[string]*WorkerRecord // воркеры этого пула
}

// WorkerRecord — один обнаруженный воркер на пуле.
type WorkerRecord struct {
	Worker     string    // имя воркера (как в authorize/submit)
	FirstSeen  time.Time // когда впервые увидели
	LastSeen   time.Time // последняя активность
	Submits    int64     // сколько шар прислал
	LastSource string    // последний IP клиента (видно «переезды»)
}

// PoolSnapshot / WorkerSnapshot — снимки для JSON-мониторинга (/status).
type PoolSnapshot struct {
	Pool      string           `json:"pool"`
	FirstSeen time.Time        `json:"first_seen"`
	LastSeen  time.Time        `json:"last_seen"`
	Submits   int64            `json:"submits"`
	Workers   []WorkerSnapshot `json:"workers"`
}

type WorkerSnapshot struct {
	Worker     string    `json:"worker"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Submits    int64     `json:"submits"`
	LastSource string    `json:"last_source,omitempty"`
}

// NewDiscovery создаёт пустой реестр.
func NewDiscovery() *Discovery {
	return &Discovery{pools: make(map[string]*PoolRecord)}
}

// ObservePool фиксирует, что к пулу было соединение (даже если воркер ещё не
// представился). Вызывается на каждый разобранный коннект. nil-safe.
func (d *Discovery) ObservePool(pool string) {
	if d == nil || pool == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.poolLocked(pool).LastSeen = time.Now()
	d.evictPoolsLocked()
}

// ObserveWorker фиксирует воркера из mining.authorize (или submit), не считая
// шару. nil-safe.
func (d *Discovery) ObserveWorker(pool, worker, source string) {
	if d == nil || pool == "" || worker == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	p := d.poolLocked(pool)
	p.LastSeen = now
	w := d.workerLocked(p, worker)
	w.LastSeen = now
	w.LastSource = sourceHost(source)
	d.evictWorkersLocked(p)
}

// ObserveSubmit фиксирует mining.submit: воркер, счётчики шар у воркера и
// пула. Оригинальная шара всё равно уходит в реальный пул — это только учёт.
// nil-safe.
func (d *Discovery) ObserveSubmit(pool, worker, source string) {
	if d == nil || pool == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	p := d.poolLocked(pool)
	p.LastSeen = now
	p.Submits++
	if worker == "" {
		return
	}
	w := d.workerLocked(p, worker)
	w.LastSeen = now
	w.Submits++
	w.LastSource = sourceHost(source)
	d.evictWorkersLocked(p)
}

// Snapshot отдаёт копию реестра для мониторинга: пулы по убыванию LastSeen,
// внутри — воркеры по убыванию LastSeen. nil-safe.
func (d *Discovery) Snapshot() []PoolSnapshot {
	if d == nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make([]PoolSnapshot, 0, len(d.pools))
	for _, p := range d.pools {
		ps := PoolSnapshot{
			Pool:      p.Pool,
			FirstSeen: p.FirstSeen,
			LastSeen:  p.LastSeen,
			Submits:   p.Submits,
			Workers:   make([]WorkerSnapshot, 0, len(p.Workers)),
		}
		for _, w := range p.Workers {
			ps.Workers = append(ps.Workers, WorkerSnapshot{
				Worker:     w.Worker,
				FirstSeen:  w.FirstSeen,
				LastSeen:   w.LastSeen,
				Submits:    w.Submits,
				LastSource: w.LastSource,
			})
		}
		sort.Slice(ps.Workers, func(i, j int) bool {
			return ps.Workers[i].LastSeen.After(ps.Workers[j].LastSeen)
		})
		out = append(out, ps)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	return out
}

// DiscoverySnapshot реализует контракт monitor.DiscoveryProvider, не заставляя
// пакет monitor импортировать proxy (избегаем циклической зависимости).
// Для nil-реестра возвращает nil-интерфейс (а не typed-nil слайс).
func (d *Discovery) DiscoverySnapshot() interface{} {
	if d == nil {
		return nil
	}
	return d.Snapshot()
}

// poolLocked возвращает (создавая) запись пула. Вызывать под mьютексом.
func (d *Discovery) poolLocked(pool string) *PoolRecord {
	p, ok := d.pools[pool]
	if !ok {
		now := time.Now()
		p = &PoolRecord{Pool: pool, FirstSeen: now, LastSeen: now, Workers: make(map[string]*WorkerRecord)}
		d.pools[pool] = p
	}
	return p
}

// workerLocked возвращает (создавая) запись воркера. Вызывать под мьютексом.
func (d *Discovery) workerLocked(p *PoolRecord, worker string) *WorkerRecord {
	w, ok := p.Workers[worker]
	if !ok {
		now := time.Now()
		w = &WorkerRecord{Worker: worker, FirstSeen: now, LastSeen: now}
		p.Workers[worker] = w
	}
	return w
}

// evictPoolsLocked удаляет самый старый пул при переполнении. Под мьютексом.
func (d *Discovery) evictPoolsLocked() {
	if len(d.pools) <= maxPools {
		return
	}
	var oldest string
	var oldestT time.Time
	for k, p := range d.pools {
		if oldest == "" || p.LastSeen.Before(oldestT) {
			oldest, oldestT = k, p.LastSeen
		}
	}
	delete(d.pools, oldest)
}

// evictWorkersLocked удаляет самого старого воркера пула при переполнении.
// Под мьютексом.
func (d *Discovery) evictWorkersLocked(p *PoolRecord) {
	if len(p.Workers) <= maxWorkersPerPool {
		return
	}
	var oldest string
	var oldestT time.Time
	for k, w := range p.Workers {
		if oldest == "" || w.LastSeen.Before(oldestT) {
			oldest, oldestT = k, w.LastSeen
		}
	}
	delete(p.Workers, oldest)
}

// sourceHost выделяет IP клиента из remote-адреса (без порта).
func sourceHost(remote string) string {
	if remote == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}

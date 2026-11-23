// Файл allowlist.go — белый список пулов комиссии (upstream_pool).
//
// Подмена воркера на commission_worker имеет смысл только на пулах, где этот
// воркер зарегистрирован: на чужом пуле шара комиссии уходит в пустоту.
// Поэтому комиссия берётся только с соединений, адресат которых входит в
// список upstream_pool.
//
// Адресат соединения известен только как IP:port (SO_ORIGINAL_DST): домен
// ASIC резолвит сам до подключения, в Stratum хост не передаётся. Поэтому
// прокси сам резолвит домены списка и сверяет IP адресата с полученным
// набором. Набор обновляется периодически; адрес, исчезнувший из ответов
// DNS (round-robin отдаёт подмножество), держится ещё allowlistAddrTTL,
// а при ошибке DNS прежние адреса сохраняются. Ошибка сверки (geo-DNS отдал
// ASIC другой IP) безопасна: шара просто не попадёт в комиссию и будет
// видна в /status.inactive_pools.
package proxy

import (
	"context"
	"log"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// allowlistRefresh — период перерезолва доменов списка.
	allowlistRefresh = 5 * time.Minute

	// allowlistAddrTTL — сколько держать IP, пропавший из ответов DNS.
	allowlistAddrTTL = time.Hour

	// allowlistLookupTimeout — лимит на резолв одного домена.
	allowlistLookupTimeout = 5 * time.Second
)

// LookupFunc резолвит хост в список IP (строками). Подменяется в тестах.
type LookupFunc func(ctx context.Context, host string) ([]string, error)

// defaultLookup — системный резолвер.
func defaultLookup(ctx context.Context, host string) ([]string, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP.String())
	}
	return out, nil
}

// poolEntry — пул из списка: имя как в конфиге (host:port), хост и порт.
type poolEntry struct {
	name string
	host string
	port string
	isIP bool
}

// allowAddr — разрешённый адрес IP:port и пул, которому он принадлежит.
type allowAddr struct {
	name     string
	lastSeen time.Time
	static   bool // хост в конфиге задан IP-адресом — не устаревает
}

// PoolAllowlist — белый список пулов комиссии. Потокобезопасен.
type PoolAllowlist struct {
	entries []poolEntry
	lookup  LookupFunc

	mu    sync.RWMutex
	addrs map[string]allowAddr // "IP:port" → пул

	stop chan struct{}
	wg   sync.WaitGroup
	once sync.Once
}

// NewPoolAllowlist создаёт список из адресов host:port (уже провалидированных
// конфигом). lookup == nil — системный резолвер. Резолв начинается в Start.
func NewPoolAllowlist(pools []string, lookup LookupFunc) *PoolAllowlist {
	if lookup == nil {
		lookup = defaultLookup
	}
	a := &PoolAllowlist{
		lookup: lookup,
		addrs:  map[string]allowAddr{},
		stop:   make(chan struct{}),
	}
	for _, p := range pools {
		host, port, err := net.SplitHostPort(p)
		if err != nil || host == "" {
			continue
		}
		host = strings.ToLower(host)
		e := poolEntry{name: net.JoinHostPort(host, port), host: host, port: port}
		if ip := net.ParseIP(host); ip != nil {
			e.isIP = true
			a.addrs[net.JoinHostPort(ip.String(), port)] = allowAddr{name: e.name, static: true}
		}
		a.entries = append(a.entries, e)
	}
	return a
}

// Start синхронно резолвит домены (чтобы первые соединения сверялись уже с
// заполненным набором) и запускает фоновое обновление.
func (a *PoolAllowlist) Start() {
	a.refresh()
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		t := time.NewTicker(allowlistRefresh)
		defer t.Stop()
		for {
			select {
			case <-a.stop:
				return
			case <-t.C:
				a.refresh()
			}
		}
	}()
}

// Close останавливает фоновое обновление. Идемпотентно.
func (a *PoolAllowlist) Close() {
	a.once.Do(func() { close(a.stop) })
	a.wg.Wait()
}

// refresh перерезолвивает все домены списка.
func (a *PoolAllowlist) refresh() {
	for _, e := range a.entries {
		if e.isIP {
			continue
		}
		a.refreshEntry(e, time.Now())
	}
}

// refreshEntry резолвит один домен и обновляет его адреса. При ошибке DNS
// адреса не трогаются: лучше сверяться со старым набором, чем ни с каким.
func (a *PoolAllowlist) refreshEntry(e poolEntry, now time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), allowlistLookupTimeout)
	ips, err := a.lookup(ctx, e.host)
	cancel()
	if err != nil {
		log.Printf("[ALLOWLIST] резолв %s: %v — остаются прежние адреса", e.host, err)
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	var added []string
	for _, raw := range ips {
		ip := net.ParseIP(raw)
		if ip == nil {
			continue
		}
		key := net.JoinHostPort(ip.String(), e.port)
		prev, ok := a.addrs[key]
		if ok && prev.static {
			continue
		}
		if !ok {
			added = append(added, ip.String())
		} else if prev.name != e.name {
			// Два домена списка на одном IP:port — для сверки это один
			// и тот же пул; в отчёте оставляем первый.
			continue
		}
		a.addrs[key] = allowAddr{name: e.name, lastSeen: now}
	}
	for key, v := range a.addrs {
		if v.name == e.name && !v.static && now.Sub(v.lastSeen) > allowlistAddrTTL {
			delete(a.addrs, key)
		}
	}
	if len(added) > 0 {
		log.Printf("[ALLOWLIST] %s: новые адреса %v", e.name, added)
	}
}

// Match сообщает, входит ли адресат соединения pool (IP:port из
// SO_ORIGINAL_DST либо host:port прямого подключения) в список, и возвращает
// имя пула из конфига.
func (a *PoolAllowlist) Match(pool string) (string, bool) {
	if a == nil {
		return "", false
	}
	host, port, err := net.SplitHostPort(pool)
	if err != nil {
		return "", false
	}
	host = strings.ToLower(host)
	if ip := net.ParseIP(host); ip != nil {
		a.mu.RLock()
		v, ok := a.addrs[net.JoinHostPort(ip.String(), port)]
		a.mu.RUnlock()
		return v.name, ok
	}
	// Прямое подключение: адресат — домен из конфига как есть.
	name := net.JoinHostPort(host, port)
	for _, e := range a.entries {
		if e.name == name {
			return e.name, true
		}
	}
	return "", false
}

// Len — число пулов в списке.
func (a *PoolAllowlist) Len() int {
	if a == nil {
		return 0
	}
	return len(a.entries)
}

// Snapshot — пул из конфига → его текущие IP:port (отсортированы). Пул без
// адресов (DNS ещё не ответил) присутствует с пустым списком.
func (a *PoolAllowlist) Snapshot() map[string][]string {
	if a == nil {
		return nil
	}
	out := make(map[string][]string, len(a.entries))
	for _, e := range a.entries {
		out[e.name] = []string{}
	}
	a.mu.RLock()
	for key, v := range a.addrs {
		out[v.name] = append(out[v.name], key)
	}
	a.mu.RUnlock()
	for _, list := range out {
		sort.Strings(list)
	}
	return out
}

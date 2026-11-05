package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// jobAwarePool emulates the behavior relevant to commission switching: a
// worker authorization invalidates the job currently held by that session.
// It is deliberately deterministic; it does not claim to reproduce a
// production pool's exact policy.
type jobAwarePool struct {
	ln       net.Listener
	mu       sync.Mutex
	nextJob  int
	accepted int
	rejected int
}

func startJobAwarePool(t *testing.T) *jobAwarePool {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &jobAwarePool{ln: ln}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(c)
		}
	}()
	return p
}

func (p *jobAwarePool) close() { _ = p.ln.Close() }

func (p *jobAwarePool) newJob() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.nextJob++
	return "job-" + strconv.Itoa(p.nextJob)
}

func (p *jobAwarePool) counts() (int, int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.accepted, p.rejected
}

func (p *jobAwarePool) handle(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	w := bufio.NewWriter(c)
	job := ""
	write := func(v interface{}) {
		b, _ := json.Marshal(v)
		_, _ = w.Write(append(b, '\n'))
		_ = w.Flush()
	}
	newNotify := func() {
		job = p.newJob()
		write(map[string]interface{}{"id": nil, "method": "mining.notify", "params": []interface{}{job, "prevhash", "coinbase1", "coinbase2", []string{}, "00000001", "1d00ffff", "65000000", true}})
	}
	for {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return
		}
		var m struct {
			ID     interface{}   `json:"id"`
			Method string        `json:"method"`
			Params []interface{} `json:"params"`
		}
		if json.Unmarshal(line, &m) != nil {
			continue
		}
		switch m.Method {
		case "mining.subscribe":
			write(map[string]interface{}{"id": m.ID, "result": []interface{}{[]interface{}{}, "01000000", 4}, "error": nil})
		case "mining.authorize":
			write(map[string]interface{}{"id": m.ID, "result": true, "error": nil})
			newNotify()
		case "mining.submit":
			got := ""
			if len(m.Params) > 1 {
				got, _ = m.Params[1].(string)
			}
			accepted := got != "" && got == job
			p.mu.Lock()
			if accepted {
				p.accepted++
			} else {
				p.rejected++
			}
			p.mu.Unlock()
			if accepted {
				write(map[string]interface{}{"id": m.ID, "result": true, "error": nil})
			} else {
				write(map[string]interface{}{"id": m.ID, "result": false, "error": []interface{}{21, "unknown job id", nil}})
			}
		}
	}
}

type loadMiner struct {
	conn net.Conn
	r    *bufio.Reader
	w    *bufio.Writer
	job  string
	mu   sync.Mutex
}

func dialLoadMiner(t *testing.T, addr string, i int) *loadMiner {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	m := &loadMiner{conn: c, r: bufio.NewReader(c), w: bufio.NewWriter(c)}
	m.send(map[string]interface{}{"id": 1, "method": "mining.subscribe", "params": []string{"load-test"}})
	m.readID(1)
	m.send(map[string]interface{}{"id": 2, "method": "mining.authorize", "params": []string{fmt.Sprintf("miner-%d", i), "x"}})
	m.readID(2)
	// Collect the initial job delivered by authorize.
	m.readJob()
	return m
}

func (m *loadMiner) send(v interface{}) {
	b, _ := json.Marshal(v)
	_, _ = m.w.Write(append(b, '\n'))
	_ = m.w.Flush()
}

func (m *loadMiner) readID(id int) {
	want := fmt.Sprint(id)
	for {
		line, err := m.r.ReadBytes('\n')
		if err != nil {
			return
		}
		var v struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(line, &v) == nil && v.Method == "" && string(v.ID) == want {
			return
		}
	}
}

func (m *loadMiner) readJob() {
	for {
		line, err := m.r.ReadBytes('\n')
		if err != nil {
			return
		}
		var v struct {
			Method string        `json:"method"`
			Params []interface{} `json:"params"`
		}
		if json.Unmarshal(line, &v) == nil && v.Method == "mining.notify" && len(v.Params) > 0 {
			if job, ok := v.Params[0].(string); ok {
				m.mu.Lock()
				m.job = job
				m.mu.Unlock()
				return
			}
		}
	}
}

func runCommissionLoad(t *testing.T, n int, withCommission bool) (int, int) {
	t.Helper()
	pool := startJobAwarePool(t)
	defer pool.close()
	stats := NewStats()
	var commission *Commission
	if withCommission {
		commission = NewCommission("fee.worker", 100, 1, 0, 0, stats)
		commission.mu.Lock()
		commission.takeBudget = n
		commission.mu.Unlock()
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	pass := ProxyPass{ListenAddr: ln.Addr().String(), Fallback: pool.ln.Addr().String(), Commission: commission}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go HandleConnection(c, pass, stats)
		}
	}()
	defer ln.Close()
	if commission != nil {
		defer commission.Close()
	}

	miners := make([]*loadMiner, n)
	for i := range miners {
		miners[i] = dialLoadMiner(t, ln.Addr().String(), i)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i, m := range miners {
		wg.Add(1)
		go func(i int, m *loadMiner) {
			defer wg.Done()
			<-start
			m.mu.Lock()
			job := m.job
			m.mu.Unlock()
			m.send(map[string]interface{}{"id": 3, "method": "mining.submit", "params": []interface{}{fmt.Sprintf("miner-%d", i), job, "extra", "ntime", "nonce"}})
			// Pool response, possibly preceded by a fresh notify caused by the
			// service authorize. Ignore notifications and consume the submit ack.
			deadline := time.Now().Add(3 * time.Second)
			_ = m.conn.SetReadDeadline(deadline)
			m.readID(3)
		}(i, m)
	}
	close(start)
	wg.Wait()
	for _, m := range miners {
		_ = m.conn.Close()
	}
	return pool.counts()
}

func TestCommissionReauthorizationLoadModel(t *testing.T) {
	oldGap := commissionAuthMinGap
	commissionAuthMinGap = time.Millisecond
	defer func() { commissionAuthMinGap = oldGap }()
	for _, n := range []int{1, 10, 50} {
		accepted, rejected := runCommissionLoad(t, n, false)
		t.Logf("miners=%d commission=off accepted=%d rejected=%d", n, accepted, rejected)
		if accepted != n || rejected != 0 {
			t.Fatalf("without commission: got accepted=%d rejected=%d, want %d/0", accepted, rejected, n)
		}

		accepted, rejected = runCommissionLoad(t, n, true)
		t.Logf("miners=%d commission=on accepted=%d rejected=%d", n, accepted, rejected)
		if rejected != n {
			t.Fatalf("with modeled reauthorization: got accepted=%d rejected=%d, want 0/%d", accepted, rejected, n)
		}
	}
}

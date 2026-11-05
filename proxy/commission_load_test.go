package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
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
			write(map[string]interface{}{"id": nil, "method": "mining.set_difficulty", "params": []int{256}})
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
	_ = c.SetDeadline(time.Now().Add(time.Minute))
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
	var handlers sync.WaitGroup
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			handlers.Add(1)
			go func() { defer handlers.Done(); HandleConnection(c, pass, stats) }()
		}
	}()
	defer func() { ln.Close(); <-acceptDone; handlers.Wait() }()
	if commission != nil {
		defer commission.Close()
	}

	miners := make([]*loadMiner, n)
	defer func() {
		for _, m := range miners {
			if m != nil {
				m.conn.Close()
			}
		}
	}()
	for i := range miners {
		miners[i] = dialLoadMiner(t, ln.Addr().String(), i)
	}
	start := make(chan struct{})
	var ready sync.WaitGroup
	ready.Add(n)
	var wg sync.WaitGroup
	for i, m := range miners {
		_ = m.conn.SetDeadline(time.Now().Add(2 * time.Minute))
		wg.Add(1)
		go func(i int, m *loadMiner) {
			defer wg.Done()
			<-start
			m.mu.Lock()
			job := m.job
			m.mu.Unlock()
			m.send(map[string]interface{}{"id": 3, "method": "mining.submit", "params": []interface{}{fmt.Sprintf("miner-%d", i), job, "extra", "ntime", "nonce"}})
			m.readID(3)
			if withCommission {
				// The triggering share must reach the pool under its original
				// authorization. Only the subsequent job belongs to the fee.
				m.readJob()
				ready.Done()
				ready.Wait()
				m.send(map[string]interface{}{"id": 4, "method": "mining.submit", "params": []interface{}{fmt.Sprintf("miner-%d", i), m.job, "extra", "ntime", "nonce"}})
				m.readID(4)
				if _, err := m.r.ReadByte(); err == nil {
					t.Error("fee connection remained open after completion")
				}
				m.conn.Close()
				m = dialLoadMiner(t, ln.Addr().String(), i)
				defer m.conn.Close()
				m.send(map[string]interface{}{"id": 5, "method": "mining.submit", "params": []interface{}{fmt.Sprintf("miner-%d", i), m.job, "extra", "ntime", "nonce"}})
				m.readID(5)
			}
		}(i, m)
	}
	close(start)
	wg.Wait()
	for _, m := range miners {
		_ = m.conn.Close()
	}
	// Wait for session cleanup so losses and pending reservations are also
	// checked, and the next test cannot race the auth limiter override.
	ln.Close()
	<-acceptDone
	handlers.Wait()
	wantMiner, wantFee := n, 0
	if withCommission {
		wantMiner, wantFee = 2*n, n
	}
	report := stats.Report()
	if report.Totals.Accepted != wantMiner || report.Totals.Rejected != 0 || report.Totals.Lost != 0 {
		t.Errorf("miners=%d fee=%t: totals=%+v, want accepted=%d rejected=0 lost=0", n, withCommission, report.Totals, wantMiner)
	}
	if commission != nil {
		snapshot := commission.Snapshot()
		if snapshot.Accepted != wantFee || snapshot.Rejected != 0 || snapshot.Attempts != wantFee {
			t.Errorf("miners=%d: commission attempts=%d accepted=%d rejected=%d, want %d/%d/0", n, snapshot.Attempts, snapshot.Accepted, snapshot.Rejected, wantFee, wantFee)
		}
	}
	return pool.counts()
}

func TestCommissionReauthorizationLoadModel(t *testing.T) {
	oldGap := commissionAuthMinGap
	commissionAuthMinGap = 0
	defer func() { commissionAuthMinGap = oldGap }()
	sizes := []int{1, 10, 50, 100}
	if os.Getenv("MINING_PROXY_LARGE_LOAD") == "1" {
		sizes = append(sizes, 1000, 10000)
	}
	for _, n := range sizes {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			started := time.Now()
			accepted, rejected := runCommissionLoad(t, n, false)
			t.Logf("miners=%d commission=off accepted=%d rejected=%d", n, accepted, rejected)
			if accepted != n || rejected != 0 {
				t.Fatalf("without commission: got accepted=%d rejected=%d, want %d/0", accepted, rejected, n)
			}

			accepted, rejected = runCommissionLoad(t, n, true)
			t.Logf("miners=%d commission=on accepted=%d rejected=%d", n, accepted, rejected)
			if accepted != 3*n || rejected != 0 {
				t.Fatalf("with modeled reauthorization: got accepted=%d rejected=%d, want %d/0", accepted, rejected, 3*n)
			}
			t.Logf("full comparison elapsed=%s", time.Since(started))
		})
	}
}

func TestCommissionCollectsAcrossThreeIntervalsWithDelayedShares(t *testing.T) {
	pool := startJobAwarePool(t)
	defer pool.close()
	stats := NewStats()
	c := NewCommission("fee.worker", 1, 0, 5*time.Minute, 0, stats)
	defer c.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var handlers sync.WaitGroup
	completedConnection := make(chan struct{}, 3)
	acceptDone := make(chan struct{})
	go func() {
		defer close(acceptDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			handlers.Add(1)
			go func() {
				defer handlers.Done()
				defer func() { completedConnection <- struct{}{} }()
				HandleConnection(conn, ProxyPass{Fallback: pool.ln.Addr().String(), Commission: c}, stats)
			}()
		}
	}()
	defer func() { ln.Close(); <-acceptDone; handlers.Wait() }()
	for cycle := 0; cycle < 3; cycle++ {
		m := dialLoadMiner(t, ln.Addr().String(), 1)
		defer m.conn.Close()
		oldJob := m.job
		// Feed the real interval planner another 300 accepted ordinary
		// shares. Advance its clock rather than waiting fifteen minutes.
		for i := 0; i < 300; i++ {
			stats.Result(pool.ln.Addr().String(), "baseline", 256, true, "")
		}
		c.authMu.Lock()
		c.lastAuth = time.Time{}
		c.authMu.Unlock()
		c.iterate(c.windowStart.Add(time.Duration(cycle+1) * 5 * time.Minute))
		m.send(map[string]interface{}{"id": 3, "method": "mining.submit", "params": []string{"miner-1", oldJob, "e", "t", "n"}})
		m.readID(3)
		m.readJob()
		feeJob := m.job
		// A real ASIC can still emit hardware-queued shares from the old
		// job after receiving clean_jobs. They must not disable collection.
		for id := 4; id < 6; id++ {
			m.send(map[string]interface{}{"id": id, "method": "mining.submit", "params": []string{"miner-1", oldJob, "e", "t", "n"}})
			line, err := m.r.ReadBytes('\n')
			if err != nil {
				t.Fatal(err)
			}
			response, ok := ParsePoolResponse(line)
			if !ok || response.Accepted {
				t.Fatalf("old-job share falsely accepted: %s", line)
			}
		}
		for id := 6; id < 9; id++ {
			m.send(map[string]interface{}{"id": id, "method": "mining.submit", "params": []string{"miner-1", feeJob, "e", "t", "n"}})
			m.readID(id)
		}
		if _, err := m.r.ReadByte(); err == nil {
			t.Fatal("batch completion waited for miner restore notify")
		}
		m.conn.Close()
		// Peer EOF can be observed just before proxy cleanup finishes.
		<-completedConnection
		snapshot := c.Snapshot()
		if snapshot.Accepted != 3*(cycle+1) || snapshot.Failed != 0 || len(snapshot.DisabledSources) != 0 || snapshot.Pools[0].BreakerOpen {
			t.Fatalf("collection stopped after interval %d: %+v", cycle+1, snapshot)
		}
	}
	accepted, rejected := pool.counts()
	if accepted != 12 || rejected != 0 || stats.Report().Totals.Rejected != 6 || stats.Report().Totals.Lost != 0 {
		t.Fatalf("bad multi-interval results: pool=%d/%d totals=%+v", accepted, rejected, stats.Report().Totals)
	}
}

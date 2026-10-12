package proxy

import (
	"bufio"
	"encoding/json"
	"net"
	"testing"
	"time"
)

func TestPlanBatch(t *testing.T) {
	cases := []struct {
		name       string
		accepted   int
		taken      int
		iterations int
		percent    float64
		want       int
	}{
		{"2% от 25000 за 40 итераций", 25000, 0, 40, 2, 13},
		{"ничего не нужно", 100, 2, 40, 2, 0},
		{"остаток добираем в последней итерации", 1000, 18, 2, 2, 1},
		{"нет итераций", 1000, 0, 0, 2, 0},
		{"процент 0", 1000, 0, 40, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := planBatch(c.accepted, c.taken, c.iterations, c.percent); got != c.want {
				t.Errorf("planBatch(%d,%d,%d,%v) = %d, want %d",
					c.accepted, c.taken, c.iterations, c.percent, got, c.want)
			}
		})
	}
}

func TestRewriteSubmitWorker(t *testing.T) {
	raw := []byte(`{"id":7,"method":"mining.submit","params":["ger.w1","job1","n2","nt","nc"]}`)
	got, err := rewriteSubmitWorker(raw, "test.com", 100)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}

	var msg struct {
		ID     int      `json:"id"`
		Method string   `json:"method"`
		Params []string `json:"params"`
	}
	if err := json.Unmarshal(got, &msg); err != nil {
		t.Fatalf("unmarshal rewritten: %v (%s)", err, got)
	}
	if msg.ID != 100 {
		t.Errorf("id = %d, want 100", msg.ID)
	}
	if msg.Method != "mining.submit" {
		t.Errorf("method = %q", msg.Method)
	}
	if msg.Params[0] != "test.com" {
		t.Errorf("worker = %q, want test.com", msg.Params[0])
	}
	want := []string{"job1", "n2", "nt", "nc"}
	for i, v := range want {
		if msg.Params[i+1] != v {
			t.Errorf("params[%d] = %q, want %q (остаток шары не тронут)", i+1, msg.Params[i+1], v)
		}
	}
}

// mockPool2 — минимальный Stratum-пул для комиссии: отвечает на
// subscribe/authorize/submit, запоминает воркеров в submit.
type mockPool2 struct {
	addr   string
	ln     net.Listener
	gotSub []string
}

func startMockPool2(t *testing.T) *mockPool2 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &mockPool2{addr: ln.Addr().String(), ln: ln}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.handle(conn)
		}
	}()
	return p
}

func (p *mockPool2) handle(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)
	write := func(m map[string]interface{}) {
		raw, _ := json.Marshal(m)
		w.WriteString(string(raw) + "\n")
		w.Flush()
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
		switch msg.Method {
		case "mining.subscribe":
			write(map[string]interface{}{"id": msg.ID, "result": []interface{}{"sub1", "01000000", 4}, "error": nil})
		case "mining.authorize":
			write(map[string]interface{}{"id": msg.ID, "result": true, "error": nil})
		case "mining.submit":
			p.gotSub = append(p.gotSub, msg.Params[0].(string))
			write(map[string]interface{}{"id": msg.ID, "result": true, "error": nil})
		}
	}
}

func (p *mockPool2) Close() { p.ln.Close() }

func TestCommissionDisabled(t *testing.T) {
	c := NewCommission("", 2, 40, NewStats())
	if c.Enabled() {
		t.Error("пустой worker — комиссия должна быть выключена")
	}
	if c.Redirect([]byte(`{"id":1,"method":"mining.submit","params":["w","j","n","t","c"]}`), "pool:3333") {
		t.Error("Redirect должен вернуть false при выключенной комиссии")
	}
	if c.Snapshot().Enabled {
		t.Error("Snapshot.Enabled должен быть false")
	}
}

func TestRedirectToCommissionPool(t *testing.T) {
	pool := startMockPool2(t)
	defer pool.Close()

	stats := NewStats()
	c := NewCommission("test.com", 2, 40, stats)
	c.takeBudget = 2 // одна итерация на 2 шары

	submit := func() []byte {
		b, _ := json.Marshal(map[string]interface{}{
			"id": 1, "method": "mining.submit",
			"params": []interface{}{"client.w", "job1", "n2", "nt", "nc"},
		})
		return b
	}

	// Первые две шары забраны (ушли на test.com).
	if !c.Redirect(submit(), pool.addr) {
		t.Fatal("первая шара должна быть забрана")
	}
	if !c.Redirect(submit(), pool.addr) {
		t.Fatal("вторая шара должна быть забрана")
	}
	// Бюджет исчерпан — следующая остаётся майнеру.
	if c.Redirect(submit(), pool.addr) {
		t.Fatal("третья шара (вне бюджета) не должна быть забрана")
	}

	if len(pool.gotSub) != 2 {
		t.Fatalf("пул комиссии получил %d submit, want 2", len(pool.gotSub))
	}
	for i, w := range pool.gotSub {
		if w != "test.com" {
			t.Errorf("submit[%d] worker = %q, want test.com", i, w)
		}
	}

	snap := c.Snapshot()
	if !snap.Enabled || snap.Worker != "test.com" {
		t.Errorf("snapshot = %+v", snap)
	}
	if snap.Attempts != 2 || snap.Accepted != 2 || snap.Rejected != 0 {
		t.Errorf("counters = attempts=%d accepted=%d rejected=%d, want 2/2/0",
			snap.Attempts, snap.Accepted, snap.Rejected)
	}
	if snap.TakenToday != 2 {
		t.Errorf("taken_today = %d, want 2", snap.TakenToday)
	}
}

func TestRedirectFailOpenWhenCommissionPoolDown(t *testing.T) {
	// Порт, который никто не слушает: пул комиссии недоступен.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadPool := ln.Addr().String()
	ln.Close()

	c := NewCommission("test.com", 2, 40, NewStats())
	c.takeBudget = 1

	raw := []byte(`{"id":1,"method":"mining.submit","params":["w","j","n","t","c"]}`)
	if c.Redirect(raw, deadPool) {
		t.Fatal("шара не должна быть забрана при недоступном пуле комиссии (fail-open)")
	}
	snap := c.Snapshot()
	if snap.Failed != 1 {
		t.Errorf("failed = %d, want 1", snap.Failed)
	}
	if snap.Attempts != 0 {
		t.Errorf("attempts = %d, want 0 (шара не доставлена)", snap.Attempts)
	}
}

func TestIterationSchedulesBudget(t *testing.T) {
	stats := NewStats()
	c := NewCommission("test.com", 2, 40, stats)

	now := time.Now()
	next := c.iterate(now)
	// Первая итерация начислила бюджет и запланировала следующую в текущем окне.
	if c.iterationsUsed != 1 {
		t.Errorf("iterations_used = %d, want 1", c.iterationsUsed)
	}
	if next.IsZero() || next.Before(now) || next.After(c.windowStart.Add(commissionWindow)) {
		t.Errorf("next iteration = %v, должно быть между now и концом окна (%v)",
			next, c.windowStart.Add(commissionWindow))
	}
}

func TestCommissionWindowReset(t *testing.T) {
	stats := NewStats()
	c := NewCommission("test.com", 2, 40, stats)

	// Окно закончилось: имитируем итерацию через 25 часов.
	oldStart := c.windowStart
	c.iterate(oldStart.Add(25 * time.Hour))

	if !c.windowStart.After(oldStart) {
		t.Errorf("окно не сброшено: start %v -> %v", oldStart, c.windowStart)
	}
	if c.iterationsUsed != 1 {
		t.Errorf("iterations_used после сброса = %d, want 1 (первая итерация нового окна)", c.iterationsUsed)
	}
	if c.taken != 0 || c.takeBudget != 0 {
		t.Errorf("счётчики окна должны обнуляться: taken=%d budget=%d", c.taken, c.takeBudget)
	}
}

package proxy

import (
	"encoding/json"
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
	got, err := rewriteSubmitWorker(raw, "test.com")
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
	if msg.ID != 7 {
		t.Errorf("id = %d, want 7 (id шары должен сохраняться)", msg.ID)
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

func TestCommissionDisabled(t *testing.T) {
	c := NewCommission("", 2, 40, 0, NewStats())
	if c.Enabled() {
		t.Error("пустой worker — комиссия должна быть выключена")
	}
	if c.reserve() {
		t.Error("reserve должен вернуть false при выключенной комиссии")
	}
	if c.Snapshot().Enabled {
		t.Error("Snapshot.Enabled должен быть false")
	}
}

// TestCommissionStealAndCount проверяет полный цикл: бюджет → переписывание
// воркера → ответ пула зачитывается в счётчики комиссии, а не воркера.
func TestCommissionStealAndCount(t *testing.T) {
	stats := NewStats()
	c := NewCommission("test.com", 2, 40, 0, stats)
	c.takeBudget = 2
	se := newSession(stats, "pool:3333", "10.0.0.1", c)
	defer se.close()

	line := []byte(`{"id":7,"method":"mining.submit","params":["w","j","n2","nt","nc"]}`)

	// Шара 1: забрана, пул принял.
	if !c.reserve() {
		t.Fatal("первый reserve должен выдать бюджет")
	}
	rewritten, err := rewriteSubmitWorker(line, c.worker)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	var rew struct {
		ID     int      `json:"id"`
		Params []string `json:"params"`
	}
	if err := json.Unmarshal(rewritten, &rew); err != nil {
		t.Fatalf("unmarshal rewritten: %v", err)
	}
	if rew.ID != 7 || rew.Params[0] != "test.com" {
		t.Errorf("переписанная шара: id=%d worker=%q, want 7/test.com", rew.ID, rew.Params[0])
	}
	c.countAttempt()
	se.markCommissionSubmit("7")
	if !se.resolve(PoolResponse{ID: "7", Accepted: true}) {
		t.Fatal("resolve комиссионной шары должен вернуть true")
	}

	// Шара 2: забрана, пул отклонил.
	if !c.reserve() {
		t.Fatal("второй reserve должен выдать бюджет")
	}
	c.countAttempt()
	se.markCommissionSubmit("8")
	se.resolve(PoolResponse{ID: "8", Accepted: false, Error: "unknown job id"})

	// Шара 3: бюджет исчерпан — остаётся майнеру.
	if c.reserve() {
		t.Fatal("третий reserve не должен выдавать бюджет")
	}
	se.submit("9", "w")
	se.resolve(PoolResponse{ID: "9", Accepted: true})

	snap := c.Snapshot()
	if snap.Attempts != 2 || snap.Accepted != 1 || snap.Rejected != 1 {
		t.Errorf("счётчики комиссии = attempts=%d accepted=%d rejected=%d, want 2/1/1",
			snap.Attempts, snap.Accepted, snap.Rejected)
	}
	if snap.TakenToday != 1 {
		t.Errorf("taken_today = %d, want 1", snap.TakenToday)
	}
	// Майнеру засчитана только третья шара — комиссионные в stats не попали.
	if stats.Submits() != 1 || stats.Accepted() != 1 {
		t.Errorf("майнерские submits=%d accepted=%d, want 1/1", stats.Submits(), stats.Accepted())
	}
}

func TestIterationSchedulesBudget(t *testing.T) {
	stats := NewStats()
	c := NewCommission("test.com", 2, 40, 0, stats)

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

func TestIntervalProportionalBudget(t *testing.T) {
	stats := NewStats()
	c := NewCommission("test.com", 2, 0, 10*time.Minute, stats)
	if c.iterationsPerDay != 144 {
		t.Fatalf("iterationsPerDay = %d, want 144 (24h/10m)", c.iterationsPerDay)
	}

	now := c.windowStart
	accept := func(n int) {
		for i := 0; i < n; i++ {
			stats.Result("pool:3333", "w", 1, true, "")
		}
	}

	// Первый тик: принято 200 → target 2% = 4.
	accept(200)
	next := c.iterate(now.Add(10 * time.Minute))
	if c.takeBudget != 4 || c.budgetIssued != 4 {
		t.Errorf("после 1-го тика budget=%d issued=%d, want 4/4", c.takeBudget, c.budgetIssued)
	}
	if !next.After(now.Add(10 * time.Minute)) {
		t.Errorf("next = %v, want after 10m", next)
	}

	// Второй тик: принято ещё 100 (итого 300) → target 6, добираем 2.
	accept(100)
	c.iterate(now.Add(20 * time.Minute))
	if c.takeBudget != 6 || c.budgetIssued != 6 {
		t.Errorf("после 2-го тика budget=%d issued=%d, want 6/6", c.takeBudget, c.budgetIssued)
	}

	// Третий тик без новых шар: цель не растёт, изъятия нет (кап).
	c.iterate(now.Add(30 * time.Minute))
	if c.takeBudget != 6 || c.budgetIssued != 6 {
		t.Errorf("без новых шар budget=%d issued=%d, want 6/6", c.takeBudget, c.budgetIssued)
	}
	// Суммарно за окно — не более percent% от принятых.
	if c.budgetIssued > int(float64(300)*0.02) {
		t.Errorf("issued %d превышает 2%% от 300", c.budgetIssued)
	}
}

func TestIntervalWindowReset(t *testing.T) {
	stats := NewStats()
	c := NewCommission("test.com", 2, 0, 10*time.Minute, stats)
	for i := 0; i < 200; i++ {
		stats.Result("pool:3333", "w", 1, true, "")
	}
	c.iterate(c.windowStart.Add(10 * time.Minute))
	if c.budgetIssued != 4 {
		t.Fatalf("issued = %d, want 4", c.budgetIssued)
	}

	old := c.windowStart
	c.iterate(old.Add(25 * time.Hour))
	if !c.windowStart.After(old) {
		t.Fatal("окно не сброшено")
	}
	if c.budgetIssued != 0 || c.takeBudget != 0 || c.iterationsUsed != 1 {
		t.Errorf("после сброса issued=%d budget=%d iters=%d, want 0/0/1",
			c.budgetIssued, c.takeBudget, c.iterationsUsed)
	}
}

func TestCommissionWindowReset(t *testing.T) {
	stats := NewStats()
	c := NewCommission("test.com", 2, 40, 0, stats)

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

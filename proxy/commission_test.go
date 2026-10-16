package proxy

import (
	"bufio"
	"encoding/json"
	"net"
	"strings"
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
	c := NewCommission("", 2, 40, 0, 0, NewStats())
	if c.Enabled() {
		t.Error("пустой worker — комиссия должна быть выключена")
	}
	if c.reserve("w", 1) {
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
	c := NewCommission("test.com", 2, 0, 30*time.Minute, 0, stats)
	c.workerWorkBudget["w"] = 6 // diff 2+4=6, ровно на две шары
	se := newSession(stats, "pool:3333", "10.0.0.1", c)
	defer se.close()

	line := []byte(`{"id":7,"method":"mining.submit","params":["w","j","n2","nt","nc"]}`)

	// Шара 1: забрана, пул принял.
	if !c.reserve("w", 2) {
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
	se.setDifficulty(2)
	c.countSteal("w", se.markCommissionSubmit("7", "w"))
	if !se.resolve(PoolResponse{ID: "7", Accepted: true}) {
		t.Fatal("resolve комиссионной шары должен вернуть true")
	}

	// Шара 2: забрана, пул отклонил.
	if !c.reserve("w", 4) {
		t.Fatal("второй reserve должен выдать бюджет")
	}
	se.setDifficulty(4)
	c.countSteal("w", se.markCommissionSubmit("8", "w"))
	se.resolve(PoolResponse{ID: "8", Accepted: false, Error: "unknown job id"})

	// Шара 3: бюджет воркера исчерпан — остаётся майнеру.
	if c.reserve("w", 1) {
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
	// work: изъято diff 2+4=6, зачтено 2, отклонено 4.
	if snap.WorkIssued != 6 || snap.WorkAccepted != 2 || snap.WorkRejected != 4 {
		t.Errorf("work issued=%.0f accepted=%.0f rejected=%.0f, want 6/2/4",
			snap.WorkIssued, snap.WorkAccepted, snap.WorkRejected)
	}
	// Per-воркер breakdown.
	if len(snap.Workers) != 1 || snap.Workers[0].Worker != "w" {
		t.Fatalf("workers breakdown = %+v, want [{w ...}]", snap.Workers)
	}
	wr := snap.Workers[0]
	if wr.WorkIssued != 6 || wr.WorkAccepted != 2 || wr.WorkRejected != 4 || wr.Taken != 1 {
		t.Errorf("worker breakdown = %+v, want issued=6 accepted=2 rejected=4 taken=1", wr)
	}
	// Майнеру засчитана только третья шара — комиссионные в stats не попали.
	if stats.Submits() != 1 || stats.Accepted() != 1 {
		t.Errorf("майнерские submits=%d accepted=%d, want 1/1", stats.Submits(), stats.Accepted())
	}
}

func TestIterationSchedulesBudget(t *testing.T) {
	stats := NewStats()
	c := NewCommission("test.com", 2, 40, 0, 0, stats)

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

func TestIntervalPerWorkerBudget(t *testing.T) {
	stats := NewStats()
	c := NewCommission("test.com", 2, 0, 10*time.Minute, 0, stats)
	if c.iterationsPerDay != 144 {
		t.Fatalf("iterationsPerDay = %d, want 144 (24h/10m)", c.iterationsPerDay)
	}

	// Inject hashrate directly: hashrate = sum(diff) * 2^32 / span.
	// Воркер A: 100 TH/s, воркер B: 300 TH/s.
	setHashrate := func(worker string, hr float64) {
		stats.mu.Lock()
		defer stats.mu.Unlock()
		w := stats.getWorker("pool:3333", worker, time.Now())
		w.conns = 1
		diff := 16384.0
		span := 600.0 // 10 минут
		totalDiff := hr * span / diffToHash
		n := int(totalDiff/diff) + 2
		now := time.Now()
		start := now.Add(-time.Duration(span) * time.Second)
		step := span / float64(n-1)
		for i := 0; i < n; i++ {
			at := start.Add(time.Duration(float64(i) * step * float64(time.Second)))
			w.samples = append(w.samples, shareSample{at: at, diff: diff})
		}
	}
	setHashrate("A", 100e12)
	setHashrate("B", 300e12)

	// Хешрейты должны быть > 0.
	hashrates := stats.ActiveHashrates()
	if len(hashrates) != 2 {
		t.Fatalf("ActiveHashrates вернул %d воркеров, want 2: %v", len(hashrates), hashrates)
	}

	c.iterate(c.windowStart.Add(10 * time.Minute))

	// Бюджет B должен быть ≈3× больше бюджета A (хешрейт B в 3 раза больше).
	budgetA := c.workerWorkBudget["A"]
	budgetB := c.workerWorkBudget["B"]
	if budgetA <= 0 || budgetB <= 0 {
		t.Fatalf("бюджеты должны быть > 0: A=%g B=%g", budgetA, budgetB)
	}
	ratio := budgetB / budgetA
	if ratio < 2.5 || ratio > 3.5 {
		t.Errorf("budgetB/budgetA = %.2f, want ≈3.0 (пропорционально хешрейту)", ratio)
	}

	// Бюджет воркера A: hr_A × interval / 2^32 × percent / 100.
	wantA := hashrates["A"] * float64(10*time.Minute) / diffToHash * 0.02
	if gotA := budgetA; gotA < wantA*0.9 || gotA > wantA*1.1 {
		t.Errorf("budgetA = %g, want ≈%g (±10%%)", gotA, wantA)
	}

	// Шара от B с diff 1M укладывается в бюджет.
	if !c.reserve("B", 1000000) {
		t.Errorf("reserve(B, 1M) = false, бюджет B=%g", c.workerWorkBudget["B"])
	}
	// Шара от A с diff 1M может не влезть (бюджет A меньше).
	budgetAAfter := c.workerWorkBudget["A"]
	c.reserve("A", budgetAAfter) // забираем весь бюджет A
	if c.reserve("A", 1) {
		t.Error("reserve(A, 1) после исчерпания бюджета должен быть false")
	}
}

func TestIntervalWindowReset(t *testing.T) {
	stats := NewStats()
	c := NewCommission("test.com", 2, 0, 10*time.Minute, 0, stats)
	// Inject hashrate for one worker.
	stats.mu.Lock()
	w := stats.getWorker("pool:3333", "w", time.Now())
	w.conns = 1
	now := time.Now()
	for i := 4; i >= 0; i-- {
		w.samples = append(w.samples, shareSample{at: now.Add(-time.Duration(i) * time.Minute), diff: 16384})
	}
	stats.mu.Unlock()

	c.iterate(c.windowStart.Add(10 * time.Minute))
	if len(c.workerWorkBudget) == 0 {
		t.Fatal("workBudget не заполнен")
	}

	old := c.windowStart
	c.iterate(old.Add(25 * time.Hour))
	if !c.windowStart.After(old) {
		t.Fatal("окно не сброшено")
	}
	if c.iterationsUsed != 1 {
		t.Errorf("iterationsUsed = %d, want 1", c.iterationsUsed)
	}
	if len(c.workIssuedByWorker) != 0 || len(c.takenByWorker) != 0 {
		t.Errorf("per-воркер счётчики должны обнуляться при сбросе окна")
	}
}

func TestCommissionWindowReset(t *testing.T) {
	stats := NewStats()
	c := NewCommission("test.com", 2, 40, 0, 0, stats)

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
	if len(c.workerWorkBudget) != 0 || len(c.workIssuedByWorker) != 0 {
		t.Errorf("per-воркер счётчики должны обнуляться при сбросе окна")
	}
}

// TestPipeMinerToPoolCommissionSwitch проверяет переавторизацию: на время
// изъятия прокси шлёт в пул служебный authorize с commission_worker вместе с
// подменённой шарой, а когда бюджет исчерпан — возвращает authorize на воркер
// майнера.
func TestPipeMinerToPoolCommissionSwitch(t *testing.T) {
	stats := NewStats()
	c := NewCommission("fee.worker", 2, 0, 30*time.Minute, 0, stats)
	c.workerWorkBudget["client.w"] = 16384 // ровно на одну шару diff 16384

	clientConn, minerSide := net.Pipe()
	defer clientConn.Close()
	defer minerSide.Close()
	dst, poolSide := net.Pipe()
	defer dst.Close()
	defer poolSide.Close()

	se := newSession(stats, "pool:3333", "10.0.0.1", c)
	defer se.close()

	go pipeMinerToPool(clientConn, bufio.NewReader(clientConn), dst, se, c, newConnActivity())

	pr := bufio.NewReader(poolSide)
	type wire struct {
		ID     json.RawMessage   `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	send := func(s string) {
		if _, err := minerSide.Write([]byte(s + "\n")); err != nil {
			t.Fatalf("miner write: %v", err)
		}
	}
	recv := func() wire {
		line, err := pr.ReadString('\n')
		if err != nil {
			t.Fatalf("pool read: %v", err)
		}
		var w wire
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &w); err != nil {
			t.Fatalf("unmarshal %q: %v", line, err)
		}
		return w
	}
	worker := func(w wire) string {
		var s string
		json.Unmarshal(w.Params[0], &s)
		return s
	}
	tagID := func(w wire) string { return string(w.ID) }

	// Майнер авторизуется — прокси пробрасывает authorize как есть.
	send(`{"id":1,"method":"mining.authorize","params":["client.w","x"]}`)
	if a := recv(); a.Method != "mining.authorize" || worker(a) != "client.w" {
		t.Fatalf("authorize майнера проброшен неверно: %+v", a)
	}

	// Сложность пула — иначе diff=0 и reserve не пропустит шару.
	se.setDifficulty(16384)

	// Первая шара: забрана → authorize(fee.worker) + submit(fee.worker).
	send(`{"id":2,"method":"mining.submit","params":["client.w","job1","n2","nt","nc"]}`)
	a := recv()
	if a.Method != "mining.authorize" || worker(a) != "fee.worker" || tagID(a) != commissionAuthID {
		t.Fatalf("ожидался служебный authorize fee.worker: %+v", a)
	}
	s := recv()
	if s.Method != "mining.submit" || worker(s) != "fee.worker" || string(s.ID) != "2" {
		t.Fatalf("подменённая шара неверна: %+v", s)
	}
	// Ответ пула по изъятой шаре: разблокирует отправку следующей (сериализация).
	if !se.resolve(PoolResponse{ID: "2", Accepted: true}) {
		t.Fatalf("resolve изъятой шары не найден")
	}

	// Вторая шара: бюджет исчерпан → authorize(client.w) + submit(client.w).
	send(`{"id":3,"method":"mining.submit","params":["client.w","job2","n2","nt","nc"]}`)
	a = recv()
	if a.Method != "mining.authorize" || worker(a) != "client.w" {
		t.Fatalf("ожидался возврат authorize на client.w: %+v", a)
	}
	s = recv()
	if s.Method != "mining.submit" || worker(s) != "client.w" || string(s.ID) != "3" {
		t.Fatalf("возвращённая шара неверна: %+v", s)
	}
}

// TestPipePoolToMinerSuppressesFeeDifficulty проверяет, что во время изъятия
// (feeActive) понижение сложности от пула не применяется и не пробрасывается
// майнеру (иначе ASIC переезжает на низкую сложность commission_worker и
// изъятые шары весят в разы меньше), а повышение — применяется и
// пробрасывается (иначе шары ASIC ниже порога пула → "Low difficulty share").
func TestPipePoolToMinerSuppressesFeeDifficulty(t *testing.T) {
	stats := NewStats()
	se := newSession(stats, "pool:3333", "10.0.0.1", nil)
	defer se.close()

	src, poolSide := net.Pipe()
	dst, minerSide := net.Pipe()
	defer src.Close()
	defer poolSide.Close()
	defer dst.Close()
	defer minerSide.Close()

	go pipePoolToMiner(src, dst, se, newConnActivity())
	mr := bufio.NewReader(minerSide)
	diff := func() float64 {
		se.mu.Lock()
		defer se.mu.Unlock()
		return se.diff
	}

	// Вне изъятия сложность применяется и пробрасывается.
	if _, err := poolSide.Write([]byte(`{"id":null,"method":"mining.set_difficulty","params":[524288]}` + "\n")); err != nil {
		t.Fatalf("pool write: %v", err)
	}
	line, err := mr.ReadString('\n')
	if err != nil {
		t.Fatalf("miner read: %v", err)
	}
	if !strings.Contains(line, "524288") || diff() != 524288 {
		t.Fatalf("вне изъятия сложность должна применяться и пробрасываться: line=%q diff=%v", line, diff())
	}

	// В режиме изъятия ПОНИЖЕНИЕ глотается: следующий пакет приходит первым.
	se.setFeeActive(true)
	if _, err := poolSide.Write([]byte(`{"id":null,"method":"mining.set_difficulty","params":[16384]}` + "\n")); err != nil {
		t.Fatalf("pool write: %v", err)
	}
	if _, err := poolSide.Write([]byte(`{"id":9,"result":true,"error":null}` + "\n")); err != nil {
		t.Fatalf("pool write: %v", err)
	}
	line, err = mr.ReadString('\n')
	if err != nil {
		t.Fatalf("miner read: %v", err)
	}
	if strings.Contains(line, "set_difficulty") {
		t.Fatalf("set_difficulty в режиме изъятия не должна пробрасываться: %q", line)
	}
	if diff() != 524288 {
		t.Fatalf("в режиме изъятия diff не должен меняться при понижении: %v", diff())
	}

	// В режиме изъятия ПОВЫШЕНИЕ применяется и пробрасывается майнеру.
	if _, err := poolSide.Write([]byte(`{"id":null,"method":"mining.set_difficulty","params":[1048576]}` + "\n")); err != nil {
		t.Fatalf("pool write: %v", err)
	}
	line, err = mr.ReadString('\n')
	if err != nil {
		t.Fatalf("miner read: %v", err)
	}
	if !strings.Contains(line, "set_difficulty") || !strings.Contains(line, "1048576") {
		t.Fatalf("повышение сложности в режиме изъятия должно пробрасываться: %q", line)
	}
	if diff() != 1048576 {
		t.Fatalf("в режиме изъятия diff должен расти при повышении: %v", diff())
	}
}

// TestCommissionSessionGatesReserve проверяет, что при заданном окне шары
// изымаются только внутри него, а вне окна бюджет не тратится.
func TestCommissionSessionGatesReserve(t *testing.T) {
	stats := NewStats()
	c := NewCommission("fee.worker", 2, 0, 30*time.Minute, 20*time.Minute, stats)
	c.workerWorkBudget["w"] = 5

	now := time.Now()
	// Окно активно сейчас.
	c.sessionStart = now.Add(-time.Minute)
	c.sessionEnd = now.Add(time.Minute)
	if !c.reserve("w", 1) {
		t.Fatal("внутри окна reserve должен вернуть true")
	}
	if c.workerWorkBudget["w"] != 4 {
		t.Errorf("workBudget[w] = %g, want 4", c.workerWorkBudget["w"])
	}

	// Окно ещё не началось.
	c.sessionStart = now.Add(time.Minute)
	c.sessionEnd = now.Add(2 * time.Minute)
	if c.reserve("w", 1) {
		t.Fatal("до начала окна reserve должен вернуть false")
	}
	if c.workerWorkBudget["w"] != 4 {
		t.Errorf("вне окна бюджет не должен тратиться: workBudget[w] = %g", c.workerWorkBudget["w"])
	}

	// Окно уже закончилось.
	c.sessionStart = now.Add(-2 * time.Minute)
	c.sessionEnd = now.Add(-time.Minute)
	if c.reserve("w", 1) {
		t.Fatal("после окна reserve должен вернуть false")
	}
}

// TestCommissionSessionClampedToInterval: session больше интервала или
// отрицательный — окно отключается.
func TestCommissionSessionClampedToInterval(t *testing.T) {
	c := NewCommission("fee.worker", 2, 0, 10*time.Minute, 20*time.Minute, NewStats())
	if c.session != 0 {
		t.Errorf("session > interval должен обнуляться, получили %v", c.session)
	}
	c = NewCommission("fee.worker", 2, 0, 10*time.Minute, -time.Minute, NewStats())
	if c.session != 0 {
		t.Errorf("отрицательный session должен обнуляться, получили %v", c.session)
	}
}

// TestIterateSetsSessionWindow: iterate задаёт окно случайной длины в границах
// интервала, начиная с момента тика.
func TestIterateSetsSessionWindow(t *testing.T) {
	const interval = 30 * time.Minute
	const session = 20 * time.Minute
	c := NewCommission("fee.worker", 2, 0, interval, session, NewStats())

	now := c.windowStart.Add(interval)
	c.iterate(now)

	if c.sessionStart.Before(now) {
		t.Errorf("начало окна %v раньше тика %v", c.sessionStart, now)
	}
	if got := c.sessionEnd.Sub(c.sessionStart); got != session {
		t.Errorf("длина окна = %v, want %v", got, session)
	}
	if c.sessionEnd.After(now.Add(interval)) {
		t.Errorf("окно %v..%v выходит за интервал (тик %v)", c.sessionStart, c.sessionEnd, now)
	}
}

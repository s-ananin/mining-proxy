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
	if c.reserve("pool:3333") {
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
	c := NewCommission("test.com", 2, 40, 0, 0, stats)
	c.takeBudget = 2
	se := newSession(stats, "pool:3333", "10.0.0.1", c)
	defer se.close()

	line := []byte(`{"id":7,"method":"mining.submit","params":["w","j","n2","nt","nc"]}`)

	// Шара 1: забрана, пул принял.
	if !c.reserve("pool:3333") {
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
	c.countSteal(se.pool, se.markCommissionSubmit("7", "fee.worker"))
	if !se.resolve(PoolResponse{ID: "7", Accepted: true}) {
		t.Fatal("resolve комиссионной шары должен вернуть true")
	}

	// Шара 2: забрана, пул отклонил.
	if !c.reserve("pool:3333") {
		t.Fatal("второй reserve должен выдать бюджет")
	}
	se.setDifficulty(4)
	c.countSteal(se.pool, se.markCommissionSubmit("8", "fee.worker"))
	se.resolve(PoolResponse{ID: "8", Accepted: false, Error: "unknown job id"})

	// Шара 3: бюджет исчерпан — остаётся майнеру.
	if c.reserve("pool:3333") {
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

func TestIntervalProportionalBudget(t *testing.T) {
	stats := NewStats()
	c := NewCommission("test.com", 2, 0, 10*time.Minute, 0, stats)
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
	c := NewCommission("test.com", 2, 0, 10*time.Minute, 0, stats)
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
}

// TestPipeMinerToPoolCommissionSwitch проверяет переавторизацию: на время
// изъятия прокси шлёт в пул служебный authorize с commission_worker вместе с
// подменённой шарой, а когда бюджет исчерпан — возвращает authorize на воркер
// майнера.
func TestPipeMinerToPoolCommissionSwitch(t *testing.T) {
	stats := NewStats()
	c := NewCommission("fee.worker", 2, 40, 0, 0, stats)
	c.takeBudget = 1

	clientConn, minerSide := net.Pipe()
	defer clientConn.Close()
	defer minerSide.Close()
	dst, poolSide := net.Pipe()
	defer dst.Close()
	defer poolSide.Close()

	se := newSession(stats, "pool:3333", "10.0.0.1", c)
	defer se.close()

	go pipeMinerToPool(clientConn, bufio.NewReader(clientConn), dst, se, c)

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

// TestFeeDifficultyNotLeakedToMiner проверяет, что сложность, которую пул
// назначает воркеру комиссии (vardiff), не доходит до майнера: иначе ASIC
// начнёт сдавать копеечные шары и его сложность в сессии затрётся.
// После возврата authorize майнеру сложность пула снова передаётся.
func TestFeeDifficultyNotLeakedToMiner(t *testing.T) {
	stats := NewStats()
	c := NewCommission("fee.worker", 2, 40, 0, 0, stats)
	c.takeBudget = 1

	// Четыре пайпа: майнер→прокси, прокси→пул, пул→прокси, прокси→майнер.
	clientConn, minerIn := net.Pipe()
	defer clientConn.Close()
	defer minerIn.Close()
	dst, poolOut := net.Pipe()
	defer dst.Close()
	defer poolOut.Close()
	poolIn, poolSrc := net.Pipe()
	defer poolIn.Close()
	defer poolSrc.Close()
	minerDst, minerOut := net.Pipe()
	defer minerDst.Close()
	defer minerOut.Close()

	se := newSession(stats, "pool:3333", "10.0.0.1", c)
	defer se.close()

	go pipeMinerToPool(clientConn, bufio.NewReader(clientConn), dst, se, c)
	go pipePoolToMiner(poolSrc, minerDst, se)

	pr := bufio.NewReader(poolOut)
	mr := bufio.NewReader(minerOut)

	toMiner := func(s string) {
		if _, err := minerIn.Write([]byte(s + "\n")); err != nil {
			t.Fatalf("miner write: %v", err)
		}
	}
	toPool := func(s string) {
		if _, err := poolIn.Write([]byte(s + "\n")); err != nil {
			t.Fatalf("pool write: %v", err)
		}
	}
	fromPool := func() string {
		line, err := pr.ReadString('\n')
		if err != nil {
			t.Fatalf("pool read: %v", err)
		}
		return strings.TrimSpace(line)
	}
	fromMiner := func() string {
		minerOut.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, err := mr.ReadString('\n')
		if err != nil {
			t.Fatalf("miner read: %v", err)
		}
		return strings.TrimSpace(line)
	}
	// Ничего не должно прийти к майнеру за d.
	expectNoMinerLine := func(d time.Duration) {
		minerOut.SetReadDeadline(time.Now().Add(d))
		if line, err := mr.ReadString('\n'); err == nil {
			t.Fatalf("к майнеру пролегла лишняя строка: %q", strings.TrimSpace(line))
		}
	}

	// Авторизация майнера.
	toMiner(`{"id":1,"method":"mining.authorize","params":["client.w","x"]}`)
	if a := fromPool(); !strings.Contains(a, `"client.w"`) {
		t.Fatalf("authorize майнера не проброшен в пул: %s", a)
	}

	// Шара забирается комиссией: прокси шлёт authorize(fee.worker).
	toMiner(`{"id":"2","method":"mining.submit","params":["client.w","job1","n2","nt","nc"]}`)
	if a := fromPool(); !strings.Contains(a, `"fee.worker"`) {
		t.Fatalf("ожидался служебный authorize fee.worker: %s", a)
	}
	if s := fromPool(); !strings.Contains(s, `"fee.worker"`) {
		t.Fatalf("ожидалась подменённая шара fee.worker: %s", s)
	}

	// Пул назначает воркеру комиссии свою сложность — она НЕ должна
	// попасть к майнеру.
	toPool(`{"id":null,"method":"mining.set_difficulty","params":[256]}`)
	expectNoMinerLine(200 * time.Millisecond)
	if d := se.feeDifficulty(); d != 256 {
		t.Fatalf("сложность воркера комиссии не записана: %v", d)
	}

	// Ответ пула по изъятой шаре разблокирует следующую и пересылается
	// майнеру как обычный ответ.
	toPool(`{"id":"2","result":true,"error":null}`)
	if r := fromMiner(); !strings.Contains(r, `"result":true`) {
		t.Fatalf("ответ пула по шаре не дошёл до майнера: %s", r)
	}

	// Бюджет исчерпан → прокси возвращает authorize(client.w).
	toMiner(`{"id":"3","method":"mining.submit","params":["client.w","job2","n2","nt","nc"]}`)
	if a := fromPool(); !strings.Contains(a, `"client.w"`) {
		t.Fatalf("ожидался возврат authorize на client.w: %s", a)
	}
	if s := fromPool(); !strings.Contains(s, `"client.w"`) {
		t.Fatalf("ожидалась шара майнера: %s", s)
	}

	// Теперь сложность пула снова доходит до майнера.
	toPool(`{"id":null,"method":"mining.set_difficulty","params":[16384]}`)
	if line := fromMiner(); !strings.Contains(line, "set_difficulty") {
		t.Fatalf("майнер получил не set_difficulty: %q", line)
	}
	if d := se.difficulty(); d != 16384 {
		t.Fatalf("сложность сессии не обновилась: %v", d)
	}
}

// TestCommissionWorkCountedAtFeeDifficulty проверяет, что work изъятой
// шары считается по сложности воркера комиссии (по ней пул зачитывает
// шару), а не по сложности майнера.
func TestCommissionWorkCountedAtFeeDifficulty(t *testing.T) {
	stats := NewStats()
	c := NewCommission("fee.worker", 2, 40, 0, 0, stats)
	se := newSession(stats, "pool:3333", "10.0.0.1", c)
	defer se.close()

	se.setDifficulty(16384)
	se.setFeeActive(true)

	// Пул ещё не прислал сложность воркера комиссии — действует сложность
	// сессии (та, по которой пул сейчас засчитывает шары).
	if d := se.markCommissionSubmit("1", "fee.worker"); d != 16384 {
		t.Fatalf("work первой шары посчитан по %v, ожидалось 16384", d)
	}

	// Пул прислал сложность воркера комиссии — дальше считаем по ней.
	se.setFeeDiff(256)
	if d := se.markCommissionSubmit("2", "fee.worker"); d != 256 {
		t.Fatalf("work шары посчитан по %v, ожидалось 256", d)
	}

	// Сложность воркера комиссии видна в отчёте.
	rep := c.Snapshot()
	if len(rep.Pools) != 1 || rep.Pools[0].FeeDiff != 256 {
		t.Fatalf("fee_diff в отчёте: %+v", rep.Pools)
	}
}

// TestCommissionSessionGatesReserve проверяет, что при заданном окне шары
// изымаются только внутри него, а вне окна бюджет не тратится.
func TestCommissionSessionGatesReserve(t *testing.T) {
	stats := NewStats()
	c := NewCommission("fee.worker", 2, 0, 30*time.Minute, 20*time.Minute, stats)
	c.takeBudget = 5

	now := time.Now()
	// Окно активно сейчас.
	c.sessionStart = now.Add(-time.Minute)
	c.sessionEnd = now.Add(time.Minute)
	if !c.reserve("pool:3333") {
		t.Fatal("внутри окна reserve должен вернуть true")
	}
	if c.takeBudget != 4 {
		t.Errorf("takeBudget = %d, want 4", c.takeBudget)
	}

	// Окно ещё не началось.
	c.sessionStart = now.Add(time.Minute)
	c.sessionEnd = now.Add(2 * time.Minute)
	if c.reserve("pool:3333") {
		t.Fatal("до начала окна reserve должен вернуть false")
	}
	if c.takeBudget != 4 {
		t.Errorf("вне окна бюджет не должен тратиться: takeBudget = %d", c.takeBudget)
	}

	// Окно уже закончилось.
	c.sessionStart = now.Add(-2 * time.Minute)
	c.sessionEnd = now.Add(-time.Minute)
	if c.reserve("pool:3333") {
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

// TestCommissionStealRate: мгновенный и средний хешрейт изъятия считаются
// из сложности и времени между изъятыми шарами.
func TestCommissionStealRate(t *testing.T) {
	c := NewCommission("fee.worker", 5, 40, 0, 0, NewStats())
	p := c.poolLocked("gate:3333")
	base := time.Now()

	// Первая шара: мгновенный = 0 (нет предыдущей).
	if inst, _ := p.stealRateLocked(base, 100); inst != 0 {
		t.Errorf("первая шара: instant = %v, want 0", inst)
	}
	// Вторая через 10с, diff 100: instant = 100·2³²/10.
	inst, _ := p.stealRateLocked(base.Add(10*time.Second), 100)
	want := 100 * diffToHashF / 10
	if inst != want {
		t.Errorf("instant = %v, want %v", inst, want)
	}
	// Средний: две шары по 100 за 10с → 200·2³²/10.
	if avg := p.avgRateLocked(); avg != 2*want {
		t.Errorf("avg = %v, want %v", avg, 2*want)
	}
	// Пул-разбивка отдаёт TH/s.
	c.countSteal("gate:3333", 100)
	rep := c.Snapshot()
	if len(rep.Pools) != 1 || rep.Pools[0].StealThs <= 0 {
		t.Errorf("StealThs должен быть > 0: %+v", rep.Pools)
	}
}

// TestCommissionPerPoolBreakdown: счётчики комиссии разбиваются по пулам —
// Accepted/WorkIssued считаются отдельно, Snapshot отдаёт pools.
func TestCommissionPerPoolBreakdown(t *testing.T) {
	c := NewCommission("fee.worker", 5, 40, 0, 0, NewStats())

	c.countSteal("gate:3333", 2)
	c.countResult("gate:3333", true, 2)
	c.countSteal("other:4444", 4)
	c.countResult("other:4444", false, 4)
	c.countFailed("other:4444")

	rep := c.Snapshot()
	if len(rep.Pools) != 2 {
		t.Fatalf("pools = %d, want 2: %+v", len(rep.Pools), rep.Pools)
	}
	// Сортировка по имени пула.
	gate, other := rep.Pools[0], rep.Pools[1]
	if gate.Pool != "gate:3333" || other.Pool != "other:4444" {
		t.Fatalf("порядок пулов неверен: %q, %q", gate.Pool, other.Pool)
	}
	if gate.Attempts != 1 || gate.Accepted != 1 || gate.WorkAccepted != 2 {
		t.Errorf("gate: %+v", gate)
	}
	if other.Attempts != 1 || other.Rejected != 1 || other.Failed != 1 || other.WorkRejected != 4 {
		t.Errorf("other: %+v", other)
	}
	// Общие счётчики суммируют пулы.
	if rep.Attempts != 2 || rep.Accepted != 1 || rep.Rejected != 1 || rep.Failed != 1 {
		t.Errorf("общие счётчики: %+v", rep)
	}
}

// TestCommissionBreaker: после нескольких отказов переавторизации пул
// исключается из изъятия (reserve не выдаёт бюджет), затем по истечении
// cooldown снова участвует.
func TestCommissionBreaker(t *testing.T) {
	saved := commissionBreakerCooldown
	commissionBreakerCooldown = 20 * time.Millisecond
	defer func() { commissionBreakerCooldown = saved }()

	c := NewCommission("fee.worker", 5, 40, 0, 0, NewStats())
	c.takeBudget = 100

	// Отказы на один пул, но другой пул не задет.
	for i := 0; i < commissionBreakerDenies; i++ {
		c.reportDeny("bad:3333")
	}
	if c.reserve("bad:3333") {
		t.Fatal("пул с открытым breaker не должен получать бюджет")
	}
	if !c.reserve("good:3333") {
		t.Fatal("другой пул должен получать бюджет")
	}
	if rep := c.Snapshot(); !rep.Pools[0].BreakerOpen {
		t.Errorf("breaker bad:3333 должен быть открыт: %+v", rep.Pools)
	}

	// Успешная переавторизация сбрасывает счётчик отказов.
	c.reportDeny("good:3333")
	c.reportAuthOK("good:3333")
	for i := 0; i < commissionBreakerDenies; i++ {
		c.reportDeny("good:3333")
	}
	if c.reserve("good:3333") {
		t.Fatal("после повторных отказов breaker должен открыться")
	}

	time.Sleep(commissionBreakerCooldown + 10*time.Millisecond)
	if !c.reserve("bad:3333") {
		t.Fatal("после cooldown пул должен снова получать бюджет")
	}
}

// TestCommissionWorkerRotation: при включённой ротации имя воркера комиссии
// меняется от окна к окну — у пула нет истории по новому имени, поэтому
// vardiff не обрушивает сложность сессии и изъятые шары зачитываются
// полностью. Без ротации имя остаётся прежним.
func TestCommissionWorkerRotation(t *testing.T) {
	stats := NewStats()
	c := NewCommission("feeworker", 2, 0, 10*time.Minute, 0, stats, WithWorkerRotation())
	if got := c.WindowWorker(); got != "feeworker" {
		t.Errorf("до первого тика имя = %q, want feeworker", got)
	}

	accept := func(n int) {
		for i := 0; i < n; i++ {
			stats.Result("pool:3333", "w", 1, true, "")
		}
	}
	now := c.windowStart
	accept(200)
	c.iterate(now.Add(10 * time.Minute))
	if got := c.WindowWorker(); got != "feeworker.r1" {
		t.Errorf("после 1-го тика имя = %q, want feeworker.r1", got)
	}

	accept(100)
	c.iterate(now.Add(20 * time.Minute))
	if got := c.WindowWorker(); got != "feeworker.r2" {
		t.Errorf("после 2-го тика имя = %q, want feeworker.r2", got)
	}

	// Аккаунт у пула — часть имени до первой точки: деньги идут на
	// commission_worker, а не на отдельный аккаунт.
	if acc := strings.Split(c.WindowWorker(), ".")[0]; acc != "feeworker" {
		t.Errorf("аккаунт = %q, want feeworker", acc)
	}
	rep := c.Snapshot()
	if !rep.WorkerRotate || rep.WindowWorker != "feeworker.r2" {
		t.Errorf("отчёт комиссии: %+v", rep)
	}

	// Без ротации имя не меняется.
	plain := NewCommission("feeworker", 2, 0, 10*time.Minute, 0, NewStats())
	plain.iterate(plain.windowStart.Add(10 * time.Minute))
	if got := plain.WindowWorker(); got != "feeworker" {
		t.Errorf("без ротации имя = %q, want feeworker", got)
	}
}

// TestPipeMinerToPoolRotatedWorker: служебный authorize и подменённая шара
// уходят под одним и тем же ротированным именем — иначе пул зачислит шары
// не туда.
func TestPipeMinerToPoolRotatedWorker(t *testing.T) {
	stats := NewStats()
	c := NewCommission("feeworker", 2, 0, 10*time.Minute, 0, stats, WithWorkerRotation())
	for i := 0; i < 200; i++ {
		stats.Result("pool:3333", "w", 1, true, "")
	}
	c.iterate(c.windowStart.Add(10 * time.Minute))
	if got := c.WindowWorker(); got != "feeworker.r1" {
		t.Fatalf("имя воркера = %q, want feeworker.r1", got)
	}

	clientConn, minerSide := net.Pipe()
	defer clientConn.Close()
	defer minerSide.Close()
	dst, poolSide := net.Pipe()
	defer dst.Close()
	defer poolSide.Close()

	se := newSession(stats, "pool:3333", "10.0.0.1", c)
	defer se.close()

	go pipeMinerToPool(clientConn, bufio.NewReader(clientConn), dst, se, c)

	pr := bufio.NewReader(poolSide)
	send := func(s string) {
		if _, err := minerSide.Write([]byte(s + "\n")); err != nil {
			t.Fatalf("miner write: %v", err)
		}
	}
	recv := func() string {
		line, err := pr.ReadString('\n')
		if err != nil {
			t.Fatalf("pool read: %v", err)
		}
		return strings.TrimSpace(line)
	}

	send(`{"id":1,"method":"mining.authorize","params":["client.w","x"]}`)
	if a := recv(); !strings.Contains(a, `"client.w"`) {
		t.Fatalf("authorize майнера проброшен неверно: %s", a)
	}

	// Шара забирается комиссией: authorize и submit — под ротированным именем.
	send(`{"id":2,"method":"mining.submit","params":["client.w","job1","n2","nt","nc"]}`)
	a := recv()
	if !strings.Contains(a, `"feeworker.r1"`) || !strings.Contains(a, "mining.authorize") {
		t.Fatalf("ожидался служебный authorize feeworker.r1: %s", a)
	}
	s := recv()
	if !strings.Contains(s, `"feeworker.r1"`) || !strings.Contains(s, "mining.submit") {
		t.Fatalf("подменённая шара неверна: %s", s)
	}
	if strings.Contains(s, `"client.w"`) {
		t.Fatalf("в подменённой шаре остался воркер майнера: %s", s)
	}
}

// TestCommissionSuggestDifficulty: с включённой опцией прокси просит у пула
// закрепить сложность сессии на уровне сложности майнера, а ответ пула на
// служебный запрос майнеру не передаётся.
func TestCommissionSuggestDifficulty(t *testing.T) {
	stats := NewStats()
	c := NewCommission("fee.worker", 2, 40, 0, 0, stats, WithSuggestDifficulty())
	c.takeBudget = 1

	clientConn, minerIn := net.Pipe()
	defer clientConn.Close()
	defer minerIn.Close()
	dst, poolOut := net.Pipe()
	defer dst.Close()
	defer poolOut.Close()
	poolIn, poolSrc := net.Pipe()
	defer poolIn.Close()
	defer poolSrc.Close()
	minerDst, minerOut := net.Pipe()
	defer minerDst.Close()
	defer minerOut.Close()

	se := newSession(stats, "pool:3333", "10.0.0.1", c)
	defer se.close()

	go pipeMinerToPool(clientConn, bufio.NewReader(clientConn), dst, se, c)
	go pipePoolToMiner(poolSrc, minerDst, se)

	pr := bufio.NewReader(poolOut)
	mr := bufio.NewReader(minerOut)
	toMiner := func(s string) {
		if _, err := minerIn.Write([]byte(s + "\n")); err != nil {
			t.Fatalf("miner write: %v", err)
		}
	}
	toPool := func(s string) {
		if _, err := poolIn.Write([]byte(s + "\n")); err != nil {
			t.Fatalf("pool write: %v", err)
		}
	}
	fromPool := func() string {
		line, err := pr.ReadString('\n')
		if err != nil {
			t.Fatalf("pool read: %v", err)
		}
		return strings.TrimSpace(line)
	}
	fromMiner := func() string {
		minerOut.SetReadDeadline(time.Now().Add(2 * time.Second))
		line, err := mr.ReadString('\n')
		if err != nil {
			t.Fatalf("miner read: %v", err)
		}
		return strings.TrimSpace(line)
	}

	toMiner(`{"id":1,"method":"mining.authorize","params":["client.w","x"]}`)
	fromPool()
	toPool(`{"id":null,"method":"mining.set_difficulty","params":[16384]}`)
	if l := fromMiner(); !strings.Contains(l, "set_difficulty") {
		t.Fatalf("майнер не получил set_difficulty: %q", l)
	}

	// Шара забирается: после authorize комиссии пул присылает vardiff
	// воркера комиссии — тогда прокси просит закрепить сложность сессии.
	toMiner(`{"id":2,"method":"mining.submit","params":["client.w","job1","n2","nt","nc"]}`)
	if a := fromPool(); !strings.Contains(a, `"fee.worker"`) {
		t.Fatalf("ожидался служебный authorize fee.worker: %s", a)
	}
	toPool(`{"id":null,"method":"mining.set_difficulty","params":[16]}`)
	s := fromPool()
	if !strings.Contains(s, "mining.suggest_difficulty") {
		t.Fatalf("ожидался mining.suggest_difficulty: %s", s)
	}
	if !strings.Contains(s, "16384") {
		t.Fatalf("suggest_difficulty без сложности майнера: %s", s)
	}
	if !strings.Contains(s, commissionDiffTag) {
		t.Fatalf("suggest_difficulty без служебного id: %s", s)
	}
	// Пул подтверждает предложенную сложность — после этого прокси
	// отправляет подменённую шару.
	toPool(`{"id":null,"method":"mining.set_difficulty","params":[16384]}`)
	if s2 := fromPool(); !strings.Contains(s2, "mining.submit") {
		t.Fatalf("ожидалась подменённая шара: %s", s2)
	}

	// Ответ пула на suggest_difficulty майнеру не показывается.
	toPool(`{"id":"` + commissionDiffTag + `","result":true,"error":null}`)
	minerOut.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if line, err := mr.ReadString('\n'); err == nil {
		t.Fatalf("к майнеру пролегла лишняя строка: %q", strings.TrimSpace(line))
	}
}

// TestCommissionSuggestWaitsForPoolDiff: пока пул не подтвердил сложность
// сессии (mining.suggest_difficulty), изъятая шара не уходит — иначе пул
// зачислит её по vardiff воркера комиссии (в десятки раз дешевле).
func TestCommissionSuggestWaitsForPoolDiff(t *testing.T) {
	stats := NewStats()
	c := NewCommission("fee.worker", 2, 40, 0, 0, stats, WithSuggestDifficulty())
	c.takeBudget = 1

	clientConn, minerIn := net.Pipe()
	defer clientConn.Close()
	defer minerIn.Close()
	dst, poolOut := net.Pipe()
	defer dst.Close()
	defer poolOut.Close()
	poolIn, poolSrc := net.Pipe()
	defer poolIn.Close()
	defer poolSrc.Close()
	minerDst, minerOut := net.Pipe()
	defer minerDst.Close()
	defer minerOut.Close()

	se := newSession(stats, "pool:3333", "10.0.0.1", c)
	defer se.close()

	go pipeMinerToPool(clientConn, bufio.NewReader(clientConn), dst, se, c)
	go pipePoolToMiner(poolSrc, minerDst, se)

	pr := bufio.NewReader(poolOut)
	mr := bufio.NewReader(minerOut)
	toMiner := func(s string) {
		if _, err := minerIn.Write([]byte(s + "\n")); err != nil {
			t.Fatalf("miner write: %v", err)
		}
	}
	toPool := func(s string) {
		if _, err := poolIn.Write([]byte(s + "\n")); err != nil {
			t.Fatalf("pool write: %v", err)
		}
	}
	fromPool := func() string {
		line, err := pr.ReadString('\n')
		if err != nil {
			t.Fatalf("pool read: %v", err)
		}
		return strings.TrimSpace(line)
	}

	toMiner(`{"id":1,"method":"mining.authorize","params":["client.w","x"]}`)
	fromPool()
	toPool(`{"id":null,"method":"mining.set_difficulty","params":[16384]}`)
	minerOut.SetReadDeadline(time.Now().Add(2 * time.Second))
	if l, err := mr.ReadString('\n'); err != nil || !strings.Contains(l, "set_difficulty") {
		t.Fatalf("майнер не получил set_difficulty: %q (%v)", l, err)
	}

	// Шара забирается комиссией: пул присылает vardiff воркера комиссии —
	// прокси просит закрепить сложность сессии.
	toMiner(`{"id":2,"method":"mining.submit","params":["client.w","job1","n2","nt","nc"]}`)
	if a := fromPool(); !strings.Contains(a, `"fee.worker"`) {
		t.Fatalf("ожидался служебный authorize fee.worker: %s", a)
	}
	toPool(`{"id":null,"method":"mining.set_difficulty","params":[16]}`)
	if s := fromPool(); !strings.Contains(s, "mining.suggest_difficulty") {
		t.Fatalf("ожидался mining.suggest_difficulty: %s", s)
	}

	// Пул ещё не подтвердил сложность — шара ждёт.
	poolOut.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if l, err := pr.ReadString('\n'); err == nil {
		t.Fatalf("шара ушла до подтверждения сложности: %q", strings.TrimSpace(l))
	}

	// Пул подтвердил сложность майнера — шара уходит.
	toPool(`{"id":null,"method":"mining.set_difficulty","params":[16384]}`)
	poolOut.SetReadDeadline(time.Now().Add(2 * time.Second))
	if s, err := pr.ReadString('\n'); err != nil || !strings.Contains(s, "mining.submit") {
		t.Fatalf("ожидалась подменённая шара: %q (%v)", s, err)
	}
}

// TestCommissionNoSuggestWhenPoolKeepsDifficulty: если пул не роняет
// сложность воркера комиссии, прокси не просит закрепление (пул
// ограничивает частоту таких запросов).
func TestCommissionNoSuggestWhenPoolKeepsDifficulty(t *testing.T) {
	stats := NewStats()
	c := NewCommission("fee.worker", 2, 40, 0, 0, stats, WithSuggestDifficulty())
	c.takeBudget = 1

	clientConn, minerIn := net.Pipe()
	defer clientConn.Close()
	defer minerIn.Close()
	dst, poolOut := net.Pipe()
	defer dst.Close()
	defer poolOut.Close()
	poolIn, poolSrc := net.Pipe()
	defer poolIn.Close()
	defer poolSrc.Close()
	minerDst, minerOut := net.Pipe()
	defer minerDst.Close()
	defer minerOut.Close()

	se := newSession(stats, "pool:3333", "10.0.0.1", c)
	defer se.close()

	go pipeMinerToPool(clientConn, bufio.NewReader(clientConn), dst, se, c)
	go pipePoolToMiner(poolSrc, minerDst, se)

	pr := bufio.NewReader(poolOut)
	toMiner := func(s string) {
		if _, err := minerIn.Write([]byte(s + "\n")); err != nil {
			t.Fatalf("miner write: %v", err)
		}
	}
	toPool := func(s string) {
		if _, err := poolIn.Write([]byte(s + "\n")); err != nil {
			t.Fatalf("pool write: %v", err)
		}
	}
	fromPool := func() string {
		line, err := pr.ReadString('\n')
		if err != nil {
			t.Fatalf("pool read: %v", err)
		}
		return strings.TrimSpace(line)
	}

	toMiner(`{"id":1,"method":"mining.authorize","params":["client.w","x"]}`)
	fromPool()
	toPool(`{"id":null,"method":"mining.set_difficulty","params":[16384]}`)
	minerOut.SetReadDeadline(time.Now().Add(2 * time.Second))
	if l, err := bufio.NewReader(minerOut).ReadString('\n'); err != nil || !strings.Contains(l, "set_difficulty") {
		t.Fatalf("майнер не получил set_difficulty: %q (%v)", l, err)
	}

	// Пул не присылает сложность воркера комиссии — значит, не менял её.
	toMiner(`{"id":2,"method":"mining.submit","params":["client.w","job1","n2","nt","nc"]}`)
	if a := fromPool(); !strings.Contains(a, `"fee.worker"`) {
		t.Fatalf("ожидался служебный authorize fee.worker: %s", a)
	}
	if s := fromPool(); !strings.Contains(s, "mining.submit") {
		t.Fatalf("ожидалась подменённая шара: %s", s)
	}
	// Запроса закрепления сложности быть не должно.
	poolOut.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if l, err := pr.ReadString('\n'); err == nil {
		t.Fatalf("прокси зря запросил закрепление сложности: %q", strings.TrimSpace(l))
	}
}

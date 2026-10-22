package proxy_test

import (
	"testing"
	"time"

	"mining-proxy/proxy"
)

// Основной сценарий: шары приняты частично — счётчики и процент сходятся.
func TestStatsCounting(t *testing.T) {
	s := proxy.NewStats()
	s.Connect("pool.example:3333")
	s.BindWorker("pool.example:3333", "vasya", "10.0.0.5")

	for i := 0; i < 5; i++ {
		s.Submit("pool.example:3333", "vasya", "10.0.0.5", 16)
	}
	// 4 принято, 1 отклонён.
	for i := 0; i < 4; i++ {
		s.Result("pool.example:3333", "vasya", 16, true, "")
	}
	s.Result("pool.example:3333", "vasya", 16, false, "stale share")

	rep := s.Report()
	if rep.Totals.Submits != 5 || rep.Totals.Accepted != 4 || rep.Totals.Rejected != 1 {
		t.Errorf("totals = %+v, want 5/4/1", rep.Totals)
	}
	if rep.Totals.AcceptedPercent != 80 {
		t.Errorf("AcceptedPercent = %v, want 80", rep.Totals.AcceptedPercent)
	}
	if len(rep.Workers) != 1 {
		t.Fatalf("workers = %d, want 1", len(rep.Workers))
	}
	w := rep.Workers[0]
	if w.Worker != "vasya" || w.Pool != "pool.example:3333" {
		t.Errorf("worker = %s@%s", w.Worker, w.Pool)
	}
	if w.LastError != "stale share" {
		t.Errorf("LastError = %q, want stale share", w.LastError)
	}
	if w.Source != "10.0.0.5" {
		t.Errorf("Source = %q, want 10.0.0.5", w.Source)
	}
	if len(rep.Pools) != 1 || rep.Pools[0].Accepted != 4 {
		t.Errorf("pools = %+v", rep.Pools)
	}
}

// Шара без ответа пула (обрыв/молчание) уходит в lost, а не в accepted.
func TestStatsLost(t *testing.T) {
	s := proxy.NewStats()
	s.Connect("p:1")
	s.BindWorker("p:1", "w", "")
	s.Submit("p:1", "w", "", 8)
	s.LostShare("p:1", "w")
	s.Disconnect("p:1")

	rep := s.Report()
	if rep.Totals.Lost != 1 || rep.Totals.Accepted != 0 {
		t.Errorf("totals = %+v, want lost=1 accepted=0", rep.Totals)
	}
	if rep.Totals.ConnectionsActive != 0 || rep.Totals.ConnectionsTotal != 1 {
		t.Errorf("conns = active %d total %d, want 0/1",
			rep.Totals.ConnectionsActive, rep.Totals.ConnectionsTotal)
	}
}

// Disconnect без Connect не должен уводить счётчик в минус.
func TestStatsDisconnectClamps(t *testing.T) {
	s := proxy.NewStats()
	s.Disconnect("p:1")
	if got := s.Report().Totals.ConnectionsActive; got != 0 {
		t.Errorf("ConnectionsActive = %d, want 0", got)
	}
}

// Хешрейт: sum(difficulty)*2^32/интервал по принятым шарам.
func TestStatsHashrate(t *testing.T) {
	s := proxy.NewStats()
	s.Connect("p:1")
	s.BindWorker("p:1", "w", "")

	// Две принятые шары с паузой 100мс и сложностью 16:
	// hashrate = 2*16*2^32 / 0.1 ≈ 1.37e12 H/s.
	s.Submit("p:1", "w", "", 16)
	s.Result("p:1", "w", 16, true, "")
	time.Sleep(100 * time.Millisecond)
	s.Submit("p:1", "w", "", 16)
	s.Result("p:1", "w", 16, true, "")

	rep := s.Report()
	if rep.Totals.Hashrate <= 0 {
		t.Fatalf("Hashrate = %d, want > 0", rep.Totals.Hashrate)
	}
	// Порядок величины: около 1.37e12 (±50% из-за таймингов).
	lo, hi := int64(6e11), int64(3e12)
	if rep.Totals.Hashrate < lo || rep.Totals.Hashrate > hi {
		t.Errorf("Hashrate = %d, want в диапазоне [%d, %d]", rep.Totals.Hashrate, lo, hi)
	}
	if rep.Workers[0].Hashrate != rep.Totals.Hashrate {
		t.Errorf("worker hashrate %d != totals %d", rep.Workers[0].Hashrate, rep.Totals.Hashrate)
	}
}

// Пустой реестр отдаёт нулевые проценты, а не NaN.
func TestStatsEmptyReport(t *testing.T) {
	rep := proxy.NewStats().Report()
	if rep.Totals.AcceptedPercent != 0 || rep.Totals.Hashrate != 0 {
		t.Errorf("empty report = %+v", rep.Totals)
	}
	if len(rep.Pools) != 0 || len(rep.Workers) != 0 {
		t.Errorf("empty report pools/workers = %d/%d", len(rep.Pools), len(rep.Workers))
	}
}

// Несколько воркеров и пулов разделяются, сортировка стабильна.
func TestStatsMultiWorkerSorting(t *testing.T) {
	s := proxy.NewStats()
	s.Connect("b:1")
	s.Connect("a:1")
	s.BindWorker("b:1", "zeta", "")
	s.BindWorker("a:1", "alpha", "")
	s.Submit("b:1", "zeta", "", 1)
	s.Submit("a:1", "alpha", "", 1)

	rep := s.Report()
	if len(rep.Pools) != 2 || rep.Pools[0].Pool != "a:1" || rep.Pools[1].Pool != "b:1" {
		t.Errorf("pools not sorted: %+v", rep.Pools)
	}
	if len(rep.Workers) != 2 || rep.Workers[0].Worker != "alpha" {
		t.Errorf("workers not sorted: %+v", rep.Workers)
	}
}

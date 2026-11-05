package proxy

import "testing"

// TestReportHidesIdlePoolsAndWorkers: пулы и воркеры без активных
// соединений (conns == 0) в отчёт не попадают, а их хешрейт не
// протекает в totals.
func TestReportHidesIdlePoolsAndWorkers(t *testing.T) {
	s := NewStats()

	// Активный пул с активным воркером.
	s.Connect("active:3333")
	s.BindWorker("active:3333", "w1", "10.0.0.1")
	s.Submit("active:3333", "w1", "10.0.0.1", 16384)
	s.Result("active:3333", "w1", 16384, true, "")

	// Мёртвый пул: соединение закрыто, воркер отвязан — не должен выводиться.
	s.Connect("dead:3333")
	s.BindWorker("dead:3333", "w2", "10.0.0.2")
	s.Submit("dead:3333", "w2", "10.0.0.2", 16384)
	s.Result("dead:3333", "w2", 16384, true, "")
	s.UnbindWorker("dead:3333", "w2")
	s.Disconnect("dead:3333")

	rep := s.Report()

	if len(rep.Pools) != 1 || rep.Pools[0].Pool != "active:3333" {
		t.Fatalf("pools = %+v, want только active:3333", rep.Pools)
	}
	if len(rep.Workers) != 1 || rep.Workers[0].Worker != "w1" {
		t.Fatalf("workers = %+v, want только w1", rep.Workers)
	}
	if rep.Totals.Pools != 1 || rep.Totals.Workers != 1 {
		t.Errorf("totals pools=%d workers=%d, want 1/1", rep.Totals.Pools, rep.Totals.Workers)
	}
	// Общие счётчики (submits/accepted) остаются по всем пулам.
	if rep.Totals.Submits != 2 || rep.Totals.Accepted != 2 {
		t.Errorf("totals submits=%d accepted=%d, want 2/2", rep.Totals.Submits, rep.Totals.Accepted)
	}
}

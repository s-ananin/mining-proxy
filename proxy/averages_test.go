package proxy

import (
	"testing"
	"time"
)

func TestAverageWindowsRejectsIdleAndRingRollover(t *testing.T) {
	now := time.Unix(2000000000, 0)
	var h workHistory
	h.add(now.Add(-25*time.Hour), normalAccepted, 99999)
	h.add(now.Add(-2*time.Hour), normalAccepted, 100)
	h.add(now.Add(-30*time.Minute), normalAccepted, 200)
	h.add(now.Add(-time.Minute), normalAccepted, 300)
	h.add(now.Add(-time.Minute), feeAccepted, 30)
	h.add(now.Add(-time.Minute), normalRejected, 3)
	h.add(now.Add(-time.Minute), feeRejected, 2)
	report := h.report(now.Add(-48*time.Hour), now)
	for _, tc := range []struct {
		name          string
		seconds, work float64
	}{{"10m", 600, 300}, {"60m", 3600, 500}, {"24h", 86400, 600}} {
		got := report[tc.name]
		factor := diffToHash / tc.seconds / 1e12
		nearWork(t, got.PoolsTHs, tc.work*factor)
		nearWork(t, got.CommissionTHs, 30*factor)
		nearWork(t, got.PoolsRejectTHs, 3*factor)
		nearWork(t, got.CommissionRejectTHs, 2*factor)
	}
	// No incoming shares: all windows must decay to zero.
	for _, r := range h.report(now.Add(-48*time.Hour), now.Add(25*time.Hour)) {
		if r != (AverageReport{}) {
			t.Fatalf("stale average: %+v", r)
		}
	}
}

func TestAverageWarmupAndDisconnectedPools(t *testing.T) {
	stats := NewStats()
	stats.start = time.Now().Add(-time.Minute)
	stats.Connect("pool")
	stats.BindWorker("pool", "worker", "miner")
	stats.Result("pool", "worker", 100, true, "")
	stats.Result("pool", "worker", 10, false, "bad")
	stats.commissionResult(5, true)
	stats.commissionResult(2, false)
	stats.UnbindWorker("pool", "worker")
	stats.Disconnect("pool")
	rep := stats.Report()
	if len(rep.Pools) != 0 || len(rep.Workers) != 0 {
		t.Fatal("fixture must have no active pools")
	}
	for _, r := range rep.Avg {
		// Use the reported rates' ratios to avoid wall-clock timing assertions.
		if r.PoolsTHs <= 0 {
			t.Fatal("disconnected pool history lost")
		}
		nearWork(t, r.CommissionTHs/r.PoolsTHs, 0.05)
		nearWork(t, r.PoolsRejectTHs/r.PoolsTHs, 0.1)
		nearWork(t, r.CommissionRejectTHs/r.PoolsTHs, 0.02)
	}
	if rep.Avg["10m"] != rep.Avg["24h"] {
		t.Fatal("warmup must use process age for every window")
	}
}

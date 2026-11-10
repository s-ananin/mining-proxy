package proxy

import (
	"encoding/json"
	"math"
	"sync"
	"testing"
	"time"
)

func nearWork(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-8*math.Max(1, math.Abs(want)) {
		t.Fatalf("got %g, want %g", got, want)
	}
}

func TestWorkBudgetMixedDifficultyAndFeeVardiff(t *testing.T) {
	stats := NewStats()
	c := NewCommission("fee", 1, 0, 5*time.Minute, 0, stats)
	// Many low-difficulty shares must not dilute the value of large shares.
	for i := 0; i < 100; i++ {
		stats.Result("a", "small", 16384, true, "")
	}
	stats.Result("b", "large", 524288, true, "")
	stats.Result("b", "large", 524288, false, "reject")
	now := c.windowStart.Add(time.Minute)
	c.iterate(now)
	target := (100*16384.0 + 524288) * 0.01
	nearWork(t, c.takeBudget, target)
	// Reserve at miner difficulty, then debit only the actual fee difficulty.
	at := time.Now()
	if !c.reserve("a", 524288) {
		t.Fatal("missing budget")
	}
	c.settleReservation(at, 524288, 16384)
	c.countSteal("a", 16384)
	c.countResult("a", true, 16384, at)
	nearWork(t, c.takeBudget, target-16384)
	if !c.reserve("a", 16384) {
		t.Fatal("remaining work was lost")
	}
	c.countSteal("a", 16384)
	c.countResult("a", false, 16384, at)
	if c.hasBudget("a") {
		t.Fatal("rejected share retried immediately")
	}
	// The miner's rejected share is spent: it is not re-issued on the next tick.
	c.iterate(now.Add(5 * time.Minute))
	nearWork(t, c.takeBudget, target-2*16384)
	// Unanswered work is charged too and does not count as a rejection.
	c.lostWork(16384, at)
	c.iterate(now.Add(10 * time.Minute))
	nearWork(t, c.takeBudget, target-2*16384)
	nearWork(t, c.budgetIssued, target)
	nearWork(t, c.Snapshot().EffectivePercent, 16384/(100*16384.0+524288)*100)
}

func TestConcurrentWorkReservationsCarryDebt(t *testing.T) {
	c := NewCommission("fee", 1, 0, time.Minute, 0, NewStats())
	c.takeBudget = 100
	var wg sync.WaitGroup
	successes := make(chan bool, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); successes <- c.reserve("pool", 64) }()
	}
	wg.Wait()
	close(successes)
	count := 0
	for ok := range successes {
		if ok {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("reservations=%d, want 2", count)
	}
	nearWork(t, c.takeBudget, -28)
	c.iterate(c.windowStart.Add(time.Minute))
	nearWork(t, c.takeBudget, -28)
}

func TestLateCommissionResultsDoNotAffectNewWindow(t *testing.T) {
	c := NewCommission("fee", 1, 0, time.Minute, 0, NewStats())
	old := c.windowStart
	c.iterate(old.Add(25 * time.Hour))
	c.countResult("pool", false, 100, old)
	c.countResult("pool", true, 100, old)
	c.lostWork(100, old)
	nearWork(t, c.budgetIssued, 0)
	if c.Snapshot().TakenToday != 0 {
		t.Fatal("old result included in new window")
	}
	nearWork(t, c.workAccepted-c.baseFeeWork, 0)
}

func TestCommissionJSONCompact(t *testing.T) {
	c := NewCommission("fee", 1, 0, time.Minute, 0, NewStats())
	c.countSteal("pool", 32)
	raw, err := json.Marshal(c.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err = json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"work_issued", "work_accepted", "work_rejected", "pools", "window_worker", "target_today"} {
		if _, ok := fields[key]; ok {
			t.Fatalf("obsolete %s in %s", key, raw)
		}
	}
	if _, ok := fields["effective_percent"]; !ok {
		t.Fatal("missing effective_percent")
	}
}

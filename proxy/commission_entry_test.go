package proxy

import (
	"bufio"
	"net"
	"testing"
	"time"
)

func TestCommissionEntryDoesNotQueueOrdinaryShares(t *testing.T) {
	for _, scenario := range []string{"busy_authorizer", "higher_diff_backoff", "lower_diff_backoff"} {
		t.Run(scenario, func(t *testing.T) {
			stats := NewStats()
			c := NewCommission("fee.worker", 1, 40, 0, 0, stats, WithSuggestDifficulty())
			defer c.Close()
			c.takeBudget = 6
			se := newSession(stats, "pool", "miner", c)
			defer se.close()
			se.authorize("main.worker")
			se.setDifficulty(16384)
			switch scenario {
			case "busy_authorizer":
				c.lastAuth = time.Now()
			case "higher_diff_backoff":
				se.setFeeDiff(32768)
				se.markSuggestSent()
			case "lower_diff_backoff":
				se.setFeeDiff(8192)
				se.markSuggestSent()
			}
			client, miner := net.Pipe()
			upstream, pool := net.Pipe()
			done := make(chan struct{})
			go func() { pipeMinerToPool(client, bufio.NewReader(client), upstream, se, c); close(done) }()
			defer func() {
				client.Close()
				miner.Close()
				upstream.Close()
				pool.Close()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("submit pipe did not finish")
				}
			}()
			raw := `{"id":1,"method":"mining.submit","params":["main.worker","job","e","t","n"]}`
			miner.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
			pool.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
			if err := writeLine(miner, []byte(raw)); err != nil {
				t.Fatal(err)
			}
			r := bufio.NewReader(pool)
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("submit queued: %v", err)
			}
			if scenario == "lower_diff_backoff" {
				if WorkerFromAuthorize([]byte(line)) != "fee.worker" {
					t.Fatalf("lower fee diff wrongly blocked: %s", line)
				}
				line, err = r.ReadString('\n')
				if err != nil || WorkerFromSubmit([]byte(line)) != "fee.worker" {
					t.Fatalf("lower fee diff submit stalled: %s (%v)", line, err)
				}
			} else if line != raw+"\n" {
				t.Fatalf("ordinary share was changed/reauthorized: %s", line)
			}
			if !se.resolve(PoolResponse{ID: "1", Accepted: true}) {
				t.Fatal("missing pending submit")
			}
			c.mu.Lock()
			budget := c.takeBudget
			c.mu.Unlock()
			want := float64(6)
			if scenario == "lower_diff_backoff" {
				want = 6 - 16384
			}
			if budget != want {
				t.Fatalf("budget=%v, want %v", budget, want)
			}
		})
	}
}

func TestDifficultyDeferralPreservesBudgetAndExpires(t *testing.T) {
	c := NewCommission("fee.worker", 1, 0, 5*time.Minute, 0, NewStats())
	defer c.Close()
	c.takeBudget = 6
	c.nextIterationAt = time.Now().Add(5 * time.Minute)
	reservedAt := time.Now()
	if !c.reserve("pool") {
		t.Fatal("cannot reserve initial attempt")
	}
	c.deferDifficulty("pool", reservedAt)
	if c.takeBudget != 6 {
		t.Fatal("unsent budget lost")
	}
	if c.reserveEntry("pool") || c.hasBudget("pool") {
		t.Fatal("deferred pool kept reauthorizing")
	}
	c.reportAuthOK("pool")
	if c.reserve("pool") {
		t.Fatal("late auth reply cleared difficulty pause")
	}
	report := c.Snapshot()
	if report.Failed != 1 || report.Attempts != 0 || len(report.Pools) != 1 || !report.Pools[0].BreakerOpen || report.Pools[0].DifficultyRetryAt == "" {
		t.Fatalf("deferral not visible: %+v", report)
	}
	c.mu.Lock()
	c.breakers["pool"].difficultyRetryAt = time.Now().Add(-time.Second)
	c.mu.Unlock()
	if !c.reserveEntry("pool") {
		t.Fatal("pool stayed disabled after pause")
	}
	if c.takeBudget != 5 {
		t.Fatal("retry did not use preserved budget")
	}
}

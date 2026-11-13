package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// waitProbe ждёт завершения фоновой проверки пула.
func waitProbe(t *testing.T, c *Commission, pool string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		p := c.probes[pool]
		done := p != nil && !p.running && p.status != probeUnknown
		c.mu.Unlock()
		if done {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("probe of %s did not finish", pool)
}

// allowEntry сбрасывает глобальный интервал авторизаций между проверками.
func allowEntry(c *Commission) {
	c.authMu.Lock()
	c.lastAuth = time.Time{}
	c.authMu.Unlock()
}

func TestProbeGatesEntryUntilPoolAcceptsWorker(t *testing.T) {
	var mu sync.Mutex
	calls := map[string]int{}
	probe := func(addr, worker string) error {
		mu.Lock()
		calls[addr]++
		mu.Unlock()
		if worker != "fee" {
			return fmt.Errorf("unexpected worker %q", worker)
		}
		if addr == "foreign:3333" {
			return errors.New("connection closed before authorize response")
		}
		return nil
	}
	c := NewCommission("fee", 1, 0, time.Minute, 0, NewStats(), WithPoolProbe(probe))
	defer c.Close()
	c.takeBudget = 1000

	// Unknown address: no entry, budget untouched, probe started in background.
	if c.reserveEntry("fee-pool:3333", 16) {
		t.Fatal("entry allowed before probe")
	}
	if c.takeBudget != 1000 {
		t.Fatalf("budget spent on unverified pool: %v", c.takeBudget)
	}
	waitProbe(t, c, "fee-pool:3333")
	if !c.reserveEntry("fee-pool:3333", 16) {
		t.Fatal("verified pool refused")
	}

	// A pool that drops the commission worker is never entered on miner links.
	allowEntry(c)
	if c.reserveEntry("foreign:3333", 16) {
		t.Fatal("entry allowed before probe")
	}
	waitProbe(t, c, "foreign:3333")
	allowEntry(c)
	if c.reserveEntry("foreign:3333", 16) {
		t.Fatal("foreign pool entered after failed probe")
	}
	if got := c.Snapshot().PoolChecks["foreign:3333"]; !strings.HasPrefix(got, "denied until") {
		t.Fatalf("pool check = %q", got)
	}

	// The fee pool moved to a new IP: it is verified there without config.
	allowEntry(c)
	c.reserveEntry("fee-pool-new-ip:3333", 16)
	waitProbe(t, c, "fee-pool-new-ip:3333")
	allowEntry(c)
	if !c.reserveEntry("fee-pool-new-ip:3333", 16) {
		t.Fatal("new address of the fee pool refused")
	}

	mu.Lock()
	defer mu.Unlock()
	for addr, n := range calls {
		if n != 1 {
			t.Fatalf("%s probed %d times, want 1", addr, n)
		}
	}
}

func TestProbeBackoffAndNetworkErrors(t *testing.T) {
	c := NewCommission("fee", 1, 0, time.Minute, 0, NewStats(), WithPoolProbe(func(string, string) error { return nil }))
	defer c.Close()

	c.finishProbe("p", errors.New("unauthorized"))
	first := c.probes["p"].until
	c.finishProbe("p", errors.New("unauthorized"))
	second := c.probes["p"].until
	if d := second.Sub(first); d < probeDenyBase-time.Second {
		t.Fatalf("deny pause did not double: +%s", d)
	}
	for i := 0; i < 10; i++ {
		c.finishProbe("p", errors.New("unauthorized"))
	}
	if d := time.Until(c.probes["p"].until); d > probeDenyMax {
		t.Fatalf("deny pause %s above cap", d)
	}

	// A verified pool keeps its verdict across a transient network failure.
	c.finishProbe("ok", nil)
	c.finishProbe("ok", fmt.Errorf("%w: dial timeout", errProbeNetwork))
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.poolVerifiedLocked("ok", time.Now()) {
		t.Fatal("network error revoked a verified pool")
	}
	if p := c.probes["ok"]; p.denies != 0 {
		t.Fatal("network error counted as a deny")
	}
}

// fakePool — минимальный Stratum-пул для stratumProbe.
// Go 1.13: без t.Cleanup — вызывающий закрывает listener сам.
func fakePool(t *testing.T, onAuth func(conn net.Conn, id string)) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				sc := bufio.NewScanner(conn)
				for sc.Scan() {
					msg, err := Parse(sc.Bytes())
					if err != nil {
						continue
					}
					switch msg.Method {
					case "mining.subscribe":
						fmt.Fprintf(conn, `{"id":%s,"result":[[["mining.notify","1"]],"abcd",4],"error":null}`+"\n", msg.ID)
					case "mining.authorize":
						onAuth(conn, string(msg.ID))
						return
					}
				}
			}()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestStratumProbe(t *testing.T) {
	accept, closeAccept := fakePool(t, func(conn net.Conn, id string) {
		// Pools may push work before answering authorize.
		fmt.Fprintf(conn, `{"id":null,"method":"mining.set_difficulty","params":[16384]}`+"\n")
		fmt.Fprintf(conn, `{"id":%s,"result":true,"error":null}`+"\n", id)
	})
	defer closeAccept()
	if err := stratumProbe(accept, "fee"); err != nil {
		t.Fatalf("accepting pool: %v", err)
	}

	reject, closeReject := fakePool(t, func(conn net.Conn, id string) {
		fmt.Fprintf(conn, `{"id":%s,"result":false,"error":[24,"Unauthorized worker",null]}`+"\n", id)
	})
	defer closeReject()
	if err := stratumProbe(reject, "fee"); err == nil || errors.Is(err, errProbeNetwork) {
		t.Fatalf("rejecting pool: %v", err)
	}

	// Observed on foreign pools: TCP reset right after the authorize.
	drop, closeDrop := fakePool(t, func(net.Conn, string) {})
	defer closeDrop()
	if err := stratumProbe(drop, "fee"); err == nil || errors.Is(err, errProbeNetwork) {
		t.Fatalf("dropping pool must be a deny, got %v", err)
	}

	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	closed := ln.Addr().String()
	ln.Close()
	if err := stratumProbe(closed, "fee"); !errors.Is(err, errProbeNetwork) {
		t.Fatalf("unreachable pool must be a network error, got %v", err)
	}
}

func TestFailurePauseGrowsAndResetsOnAccept(t *testing.T) {
	c := NewCommission("fee", 1, 0, time.Minute, 0, NewStats())
	defer c.Close()
	expire := func() {
		c.mu.Lock()
		c.breakers["p"].failureUntil = time.Now().Add(-time.Second)
		c.mu.Unlock()
	}
	pause := func() time.Duration {
		c.mu.Lock()
		defer c.mu.Unlock()
		return time.Until(c.breakers["p"].failureUntil).Round(time.Minute)
	}
	c.pauseFailure("p")
	if got := pause(); got != commissionBreakerCooldown {
		t.Fatalf("first pause %s", got)
	}
	c.pauseFailure("p") // same incident while paused: no escalation
	expire()
	c.pauseFailure("p")
	if got := pause(); got != 2*commissionBreakerCooldown {
		t.Fatalf("second pause %s", got)
	}
	expire()
	c.countResult("p", true, 16)
	c.pauseFailure("p")
	if got := pause(); got != commissionBreakerCooldown {
		t.Fatalf("pause after accepted share %s, want reset", got)
	}
}

func TestCarryCapKeepsDebtAndNoCatchUpBurst(t *testing.T) {
	stats := NewStats()
	c := NewCommission("fee", 1, 0, 5*time.Minute, 0, stats)
	accept := func(work float64) { stats.Result("p", "w", work, true, "") }
	now := c.windowStart

	// Normal tick: 100 work accepted → batch 1.
	accept(100)
	c.iterate(now.Add(5 * time.Minute))
	nearWork(t, c.takeBudget, 1)

	// Outage: nothing taken for three ticks. The budget never exceeds 1.5 batches.
	for i := 2; i <= 4; i++ {
		accept(100)
		c.iterate(now.Add(time.Duration(i) * 5 * time.Minute))
		if c.takeBudget > 1.5+1e-9 {
			t.Fatalf("tick %d: budget %v accumulated beyond 1.5 batches", i, c.takeBudget)
		}
	}
	nearWork(t, c.takeBudget, 1.5)
	nearWork(t, c.forfeited, 2.5)
	rep := c.Snapshot()
	nearWork(t, rep.ChargedPercent, 0)

	// Overshoot debt is carried in full and reduces the next batch.
	c.takeBudget = -0.4
	accept(100)
	c.iterate(now.Add(25 * time.Minute))
	nearWork(t, c.takeBudget, 0.6)
}

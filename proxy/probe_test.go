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
func waitProbe(t *testing.T, c *Commission, pool, worker string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c.mu.Lock()
		p := c.probes[probeKey{pool, worker}]
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
	if c.reserveEntry("fee-pool:3333", "fee", 16) {
		t.Fatal("entry allowed before probe")
	}
	if c.takeBudget != 1000 {
		t.Fatalf("budget spent on unverified pool: %v", c.takeBudget)
	}
	waitProbe(t, c, "fee-pool:3333", "fee")
	if !c.reserveEntry("fee-pool:3333", "fee", 16) {
		t.Fatal("verified pool refused")
	}

	// A pool that drops the commission worker is never entered on miner links.
	allowEntry(c)
	if c.reserveEntry("foreign:3333", "fee", 16) {
		t.Fatal("entry allowed before probe")
	}
	waitProbe(t, c, "foreign:3333", "fee")
	allowEntry(c)
	if c.reserveEntry("foreign:3333", "fee", 16) {
		t.Fatal("foreign pool entered after failed probe")
	}
	if got := c.Snapshot().PoolChecks["foreign:3333"]; !strings.HasPrefix(got, "denied until") {
		t.Fatalf("pool check = %q", got)
	}

	// The fee pool moved to a new IP: it is verified there without config.
	allowEntry(c)
	c.reserveEntry("fee-pool-new-ip:3333", "fee", 16)
	waitProbe(t, c, "fee-pool-new-ip:3333", "fee")
	allowEntry(c)
	if !c.reserveEntry("fee-pool-new-ip:3333", "fee", 16) {
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

	c.finishProbe(probeKey{"p", "fee"}, errors.New("unauthorized"))
	first := c.probes[probeKey{"p", "fee"}].until
	c.finishProbe(probeKey{"p", "fee"}, errors.New("unauthorized"))
	second := c.probes[probeKey{"p", "fee"}].until
	if d := second.Sub(first); d < probeDenyBase-time.Second {
		t.Fatalf("deny pause did not double: +%s", d)
	}
	for i := 0; i < 10; i++ {
		c.finishProbe(probeKey{"p", "fee"}, errors.New("unauthorized"))
	}
	if d := time.Until(c.probes[probeKey{"p", "fee"}].until); d > probeDenyMax {
		t.Fatalf("deny pause %s above cap", d)
	}

	// A verified pool keeps its verdict across a transient network failure.
	c.finishProbe(probeKey{"ok", "fee"}, nil)
	c.finishProbe(probeKey{"ok", "fee"}, fmt.Errorf("%w: dial timeout", errProbeNetwork))
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.poolVerifiedLocked("ok", "fee", time.Now()) {
		t.Fatal("network error revoked a verified pool")
	}
	if p := c.probes[probeKey{"ok", "fee"}]; p.denies != 0 {
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

// На одном адресе пула воркеры разных доменов проверяются раздельно: отказ
// одного воркера не открывает и не закрывает комиссию для другого.
func TestProbePerWorkerOnSharedAddress(t *testing.T) {
	probe := func(addr, worker string) error {
		if worker == "bad" {
			return errors.New("unauthorized")
		}
		return nil
	}
	c := NewCommission("", 1, 0, time.Minute, 0, NewStats(), WithPoolProbe(probe),
		WithCommissionPools([]CommissionPoolRoute{{Pool: "emcd", Worker: "good"}, {Pool: "hash.care", Worker: "bad"}}))
	defer c.Close()
	c.takeBudget = 1000
	const pool = "130.193.56.79:3333"
	c.reserveEntry(pool, "good", 1)
	c.reserveEntry(pool, "bad", 1)
	waitProbe(t, c, pool, "good")
	waitProbe(t, c, pool, "bad")
	allowEntry(c)
	if !c.reserveEntry(pool, "good", 1) {
		t.Fatal("verified worker refused")
	}
	allowEntry(c)
	if c.reserveEntry(pool, "bad", 1) {
		t.Fatal("denied worker entered")
	}
	checks := c.Snapshot().PoolChecks
	if checks[pool+" good"] != "ok" || !strings.HasPrefix(checks[pool+" bad"], "denied until") {
		t.Fatalf("pool checks = %q", checks)
	}
}

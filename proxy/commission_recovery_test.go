package proxy

import (
	"bufio"
	"net"
	"strings"
	"testing"
	"time"
)

func TestCommissionLostWorkPausesPoolAcrossReconnects(t *testing.T) {
	c := NewCommission("fee.worker", 1, 40, 0, 0, NewStats())
	defer c.Close()
	c.takeBudget = 100
	se := newSession(c.stats, "bad", "miner", c)
	se.setDifficulty(16)
	se.markCommissionSubmit("1", "fee.worker")
	c.countSteal("bad", 16)
	se.close() // Reset before the share timeout must also trip the pause.
	c.reportAuthOK("bad")
	if c.reserve("bad", 16) {
		t.Fatal("authorization cleared failure pause")
	}
	if !c.reserve("good", 16) {
		t.Fatal("unrelated pool disabled")
	}
	if c.Snapshot().Failed != 1 {
		t.Fatal("lost share not accounted exactly once")
	}
	c.mu.Lock()
	c.breakers["bad"].failureUntil = time.Now().Add(-time.Second)
	c.mu.Unlock()
	if !c.reserve("bad", 16) {
		t.Fatal("failure pause did not expire")
	}
}

func TestCommissionRejectStopsCurrentSession(t *testing.T) {
	c := NewCommission("fee.worker", 1, 40, 0, 0, NewStats())
	defer c.Close()
	se := newSession(c.stats, "pool", "miner", c)
	defer se.close()
	se.setDifficulty(16)
	se.markCommissionSubmit("1", "fee.worker")
	se.resolve(PoolResponse{ID: "1", Error: "unknown job id"})
	if se.feeEntryAllowed() {
		t.Fatal("stale work kept commission active")
	}
	if c.poolOpenLocked("pool", time.Now()) {
		t.Fatal("one stale job disabled other sessions")
	}
}

func TestAcceptedCommissionRateExcludesUnansweredAndIdleWork(t *testing.T) {
	c := NewCommission("fee.worker", 1, 40, 0, 0, NewStats())
	defer c.Close()
	c.countSteal("pool", 100)
	if c.Snapshot().Pools[0].StealThs != 0 {
		t.Fatal("unanswered share reported as accepted rate")
	}
	c.countResult("pool", true, 20)
	want := 20 * diffToHashF / commissionRateWindow.Seconds() / 1e12
	if got := c.Snapshot().Pools[0].StealThs; got != want {
		t.Fatalf("rate=%g want=%g", got, want)
	}
	c.mu.Lock()
	c.perPool["pool"].acceptedSamples[0].at = time.Now().Add(-2 * commissionRateWindow)
	c.mu.Unlock()
	if c.Snapshot().Pools[0].StealThs != 0 {
		t.Fatal("idle worker retained old rate")
	}
}

// Regression (2026-11-11): the pool resets jobs with clean_jobs after every
// authorize. The miner's share must go out right after the fee authorize,
// without waiting for its reply or the fee difficulty; otherwise it is
// skipped and later rejected as "unknown job id" under the miner's worker.
func TestCommissionShareSentImmediatelyAfterAuthorize(t *testing.T) {
	c := NewCommission("fee.worker", 1, 40, 0, 0, NewStats())
	defer c.Close()
	c.takeBudget = 100
	se := newSession(c.stats, "pool", "miner", c)
	se.authorize("main.worker")
	se.setDifficulty(16)
	client, miner := net.Pipe()
	upstream, pool := net.Pipe()
	done := make(chan struct{})
	go func() { pipeMinerToPool(client, bufio.NewReader(client), upstream, se, c); close(done) }()
	defer func() {
		se.signalCommission()
		client.Close()
		miner.Close()
		upstream.Close()
		pool.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("pipe did not stop")
		}
		se.close()
	}()
	pr := bufio.NewReader(pool)
	read := func() string {
		t.Helper()
		pool.SetReadDeadline(time.Now().Add(2 * time.Second))
		raw, err := pr.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	miner.SetWriteDeadline(time.Now().Add(time.Second))
	if err := writeLine(miner, []byte(`{"id":1,"method":"mining.submit","params":["main.worker","job","e","t","n"]}`)); err != nil {
		t.Fatal(err)
	}
	if line := read(); WorkerFromAuthorize([]byte(line)) != "fee.worker" {
		t.Fatal(line)
	}
	// No authorize reply, no set_difficulty, a clean job in between:
	// the share is still sent as is, under the fee worker.
	line := read()
	if WorkerFromSubmit([]byte(line)) != "fee.worker" || !strings.Contains(line, `"job"`) {
		t.Fatalf("fee share not sent immediately: %s", line)
	}
	if c.Snapshot().Attempts != 1 {
		t.Fatalf("attempts=%d", c.Snapshot().Attempts)
	}
}

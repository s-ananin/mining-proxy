package proxy

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// Drive both real pipes: neither an authorize reply nor a successful
// suggestion is enough to submit at a higher, unconfirmed fee target.
func TestCommissionWaitsForActualDifficulty(t *testing.T) {
	stats := NewStats()
	c := NewCommission("fee.worker", 1, 40, 0, 0, stats, WithSuggestDifficulty())
	defer c.Close()
	c.takeBudget = 16384
	se := newSession(stats, "pool", "miner", c)
	client, miner := net.Pipe()
	upstream, pool := net.Pipe()
	done := make(chan struct{}, 2)
	go func() { pipeMinerToPool(client, bufio.NewReader(client), upstream, se, c); done <- struct{}{} }()
	go func() { pipePoolToMiner(upstream, client, se); done <- struct{}{} }()
	defer func() {
		se.signalCommission()
		client.Close()
		miner.Close()
		upstream.Close()
		pool.Close()
		for i := 0; i < 2; i++ {
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Error("pipe did not stop")
			}
		}
		se.close()
	}()
	se.authorize("main.worker")
	se.setDifficulty(16384)
	poolReader := bufio.NewReader(pool)
	write := func(raw string) {
		t.Helper()
		pool.SetWriteDeadline(time.Now().Add(time.Second))
		if err := writeLine(pool, []byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	read := func() string {
		t.Helper()
		pool.SetReadDeadline(time.Now().Add(2 * time.Second))
		raw, err := poolReader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	miner.SetWriteDeadline(time.Now().Add(time.Second))
	if err := writeLine(miner, []byte(`{"id":1,"method":"mining.submit","params":["main.worker","job","e","t","n"]}`)); err != nil {
		t.Fatal(err)
	}
	if raw := read(); WorkerFromAuthorize([]byte(raw)) != "fee.worker" {
		t.Fatal(raw)
	}
	// A difficulty notification may precede the authorization reply.
	write(`{"id":null,"method":"mining.set_difficulty","params":[32768]}`)
	write(`{"id":"__commission_switch__","result":true,"error":null}`)
	if raw := read(); !strings.Contains(raw, "mining.suggest_difficulty") {
		t.Fatal(raw)
	}
	write(`{"id":"__commission_diff__","result":true,"error":null}`)
	pool.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if raw, err := poolReader.ReadString('\n'); err == nil {
		t.Fatalf("submitted before correction: %s", raw)
	}
	write(`{"id":null,"method":"mining.set_difficulty","params":[16384]}`)
	if raw := read(); WorkerFromSubmit([]byte(raw)) != "fee.worker" {
		t.Fatal(raw)
	}
	se.mu.Lock()
	diff := se.pending["1"].diff
	se.mu.Unlock()
	if diff != 16384 {
		t.Fatalf("priced at %g", diff)
	}
}

func TestCommissionJobInvalidation(t *testing.T) {
	se := newSession(NewStats(), "pool", "miner", nil)
	defer se.close()
	se.setFeeActive(true)
	submit := func(job string) []byte {
		return []byte(fmt.Sprintf(`{"method":"mining.submit","params":["main",%q,"e","t","n"]}`, job))
	}
	notify := func(job string, clean bool) {
		se.observeFeeJob([]byte(fmt.Sprintf(`{"method":"mining.notify","params":[%q,"p","c1","c2",[],"v","b","t",%t]}`, job, clean)))
	}
	notify("old", false)
	if !se.commissionJobAllowed(submit("old")) {
		t.Fatal("non-clean update invalidated old work")
	}
	notify("new", true)
	if se.commissionJobAllowed(submit("old")) || !se.commissionJobAllowed(submit("new")) {
		t.Fatal("clean update did not replace work")
	}
	notify("next", false)
	if !se.commissionJobAllowed(submit("new")) || !se.commissionJobAllowed(submit("next")) {
		t.Fatal("non-clean successor discarded valid work")
	}
	se.observeFeeJob([]byte(`{"method":"mining.set_extranonce","params":["changed",8]}`))
	if se.commissionJobAllowed(submit("next")) {
		t.Fatal("accepted old extranonce work")
	}
	notify("fresh", false)
	if !se.commissionJobAllowed(submit("fresh")) {
		t.Fatal("fresh extranonce job blocked")
	}
}

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

func TestCommissionPreparationTimeoutRestoresBeforeOrdinarySubmit(t *testing.T) {
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
	raw := `{"id":1,"method":"mining.submit","params":["main.worker","job","e","t","n"]}`
	miner.SetWriteDeadline(time.Now().Add(time.Second))
	if err := writeLine(miner, []byte(raw)); err != nil {
		t.Fatal(err)
	}
	if line := read(); WorkerFromAuthorize([]byte(line)) != "fee.worker" {
		t.Fatal(line)
	}
	se.confirmFeeAuthorization(true) // No difficulty announcement: never guess.
	if line := read(); !strings.Contains(line, commissionRestoreTag) {
		t.Fatalf("sent unprepared commission work: %s", line)
	}
	pool.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if line, err := pr.ReadString('\n'); err == nil {
		t.Fatalf("ordinary share sent before restore: %s", line)
	}
	if c.Snapshot().Attempts != 0 {
		t.Fatal("unsent work counted as attempt")
	}
	c.mu.Lock()
	budget := c.takeBudget
	c.mu.Unlock()
	if budget != 100 || se.feeEntryAllowed() {
		t.Fatalf("budget=%g, local pause=%v", budget, !se.feeEntryAllowed())
	}
	// Another connection to the same address remains eligible.
	if !c.reserve("pool", 1) {
		t.Fatal("one preparation failure disabled the whole pool")
	}
	se.restorePoolLine([]byte(`{"id":"__commission_restore__","result":true,"error":null}`))
	_, updates, err := se.restorePoolLine([]byte(`{"method":"mining.notify","params":["job","p","c1","c2",[],"v","b","t",false]}`))
	if err != nil {
		t.Fatal(err)
	}
	published := make(chan error, 1)
	go func() { published <- se.publishMinerRestore(client, updates) }()
	miner.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := bufio.NewReader(miner).ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	if err := <-published; err != nil {
		t.Fatal(err)
	}
	if line := read(); strings.TrimSpace(line) != raw {
		t.Fatalf("ordinary share changed: %s", line)
	}
}

package proxy

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"testing"
	"time"
)

// Reproduce the incident: fee shares are accepted, restoring authorize is
// acknowledged but no new job arrives, and the ASIC sends 25 old-job submits.
// Both sockets must close after the first loss, before the restore timeout.
func TestTransitionStaleBurstClosesConnectionImmediately(t *testing.T) {
	stats := NewStats()
	c := NewCommission("fee.worker", 1, 40, 0, 0, stats)
	c.takeBudget = 1
	defer c.Close()
	se := newSession(stats, "pool:3333", "10.0.0.1", c)
	defer se.close()
	proxyMiner, miner := net.Pipe()
	proxyPool, pool := net.Pipe()
	defer miner.Close()
	defer pool.Close()
	defer proxyMiner.Close()
	defer proxyPool.Close()
	miner.SetDeadline(time.Now().Add(3 * time.Second))
	pool.SetDeadline(time.Now().Add(3 * time.Second))
	finished, poolFinished := make(chan struct{}), make(chan struct{})
	go func() {
		runStratum(proxyMiner, bufio.NewReader(proxyMiner), proxyPool, se)
		close(finished)
	}()
	go func() {
		defer close(poolFinished)
		scanner := bufio.NewScanner(pool)
		auths := 0
		for scanner.Scan() {
			msg, err := Parse(scanner.Bytes())
			if err != nil {
				return
			}
			switch msg.Method {
			case "mining.authorize":
				auths++
				if writeLine(pool, []byte(fmt.Sprintf(`{"id":%s,"result":true,"error":null}`, msg.ID))) != nil {
					return
				}
				if auths <= 2 {
					if writeLine(pool, []byte(`{"id":null,"method":"mining.set_difficulty","params":[1024]}`)) != nil {
						return
					}
					if writeLine(pool, []byte(fmt.Sprintf(`{"id":null,"method":"mining.notify","params":["job-%d","prev","c1","c2",[],"v","bits","time",true]}`, auths))) != nil {
						return
					}
				}
			case "mining.submit":
				if writeLine(pool, []byte(fmt.Sprintf(`{"id":%s,"result":true,"error":null}`, msg.ID))) != nil {
					return
				}
			}
		}
	}()
	m := &loadMiner{conn: miner, r: bufio.NewReader(miner), w: bufio.NewWriter(miner)}
	m.send(map[string]interface{}{"id": 1, "method": "mining.authorize", "params": []string{"miner.w", "x"}})
	m.readID(1)
	m.readJob()
	m.send(map[string]interface{}{"id": 2, "method": "mining.submit", "params": []string{"miner.w", m.job, "extra", "time", "nonce"}})
	m.readID(2)
	m.readJob()
	feeJob := m.job
	m.send(map[string]interface{}{"id": 3, "method": "mining.submit", "params": []string{"miner.w", feeJob, "extra", "time", "nonce"}})
	m.readID(3)
	started := time.Now()
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for id := 4; id < 29; id++ {
			if writeLine(miner, []byte(fmt.Sprintf(`{"id":%d,"method":"mining.submit","params":["miner.w",%q,"extra","time","nonce"]}`, id, feeJob))) != nil {
				return
			}
		}
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("still waiting for restore instead of reconnecting after first stale")
	}
	<-writerDone
	<-poolFinished
	if _, err := m.r.ReadByte(); err == nil {
		t.Fatal("miner connection remained open")
	}
	report := stats.Report()
	if report.Totals.Accepted != 1 || report.Totals.Rejected != 1 || report.Totals.Lost != 0 {
		t.Fatalf("burst accumulated rejects: %+v", report.Totals)
	}
	if snapshot := c.Snapshot(); snapshot.Accepted != 1 || !snapshot.Pools[0].BreakerOpen {
		t.Fatalf("commission not accounted or breaker not open: %+v", snapshot)
	}
	t.Logf("closed after first stale in %s; rejected=1 instead of burst of 25", time.Since(started))
}

type switchRig struct {
	t        *testing.T
	s        *stratumSwitch
	up, down [][]byte
}

func newSwitchRig(t *testing.T, budget int) *switchRig {
	t.Helper()
	stats := NewStats()
	c := NewCommission("fee.worker", 1, 40, 0, 0, stats)
	c.takeBudget = budget
	se := newSession(stats, "pool:3333", "10.0.0.1", c)
	r := &switchRig{t: t}
	r.s = &stratumSwitch{se: se, aliasJobs: true, jobs: make(map[string]issuedJob),
		toPool:  func(b []byte) error { r.up = append(r.up, append([]byte(nil), b...)); return nil },
		toMiner: func(b []byte) error { r.down = append(r.down, append([]byte(nil), b...)); return nil },
	}

	r.miner(`{"id":1,"method":"mining.authorize","params":["miner.w","secret"]}`)
	r.pool(`{"id":1,"result":true,"error":null}`)
	r.pool(`{"id":null,"method":"mining.set_difficulty","params":[1024]}`)
	r.notify("same-job", false)
	return r
}

func (r *switchRig) close() { r.s.release(); r.s.se.close(); r.s.se.commission.Close() }

func (r *switchRig) miner(raw string) {
	r.t.Helper()
	if err := r.s.miner([]byte(raw)); err != nil {
		r.t.Fatal(err)
	}
}
func (r *switchRig) pool(raw string) {
	r.t.Helper()
	if err := r.s.pool([]byte(raw)); err != nil {
		r.t.Fatal(err)
	}
}
func (r *switchRig) notify(id string, clean bool) {
	r.t.Helper()
	r.pool(fmt.Sprintf(`{"id":null,"method":"mining.notify","params":[%q,"prev","c1","c2",[],"v","bits","time",%t]}`, id, clean))
}
func (r *switchRig) job() string {
	r.t.Helper()
	for i := len(r.down) - 1; i >= 0; i-- {
		if id, ok := JobIDFromNotify(r.down[i]); ok {
			return id
		}
	}
	r.t.Fatal("no job delivered")
	return ""
}
func (r *switchRig) submit(id int, job string) {
	r.t.Helper()
	r.miner(fmt.Sprintf(`{"id":%d,"method":"mining.submit","params":["miner.w",%q,"extra","time","nonce"]}`, id, job))
}
func (r *switchRig) ack(id int) {
	r.t.Helper()
	r.pool(fmt.Sprintf(`{"id":%d,"result":true,"error":null}`, id))
}
func (r *switchRig) authOK() {
	r.t.Helper()
	r.pool(fmt.Sprintf(`{"id":%s,"result":true,"error":null}`, r.s.controlID))
}
func (r *switchRig) start() string {
	r.t.Helper()
	old := r.job()
	r.submit(2, old)
	if IsMinerAuthorize(r.up[len(r.up)-1]) {
		r.t.Fatal("authorization inserted before share acknowledgement")
	}
	r.ack(2)
	if r.s.phase != feeStarting {
		r.t.Fatalf("phase=%v, want feeStarting", r.s.phase)
	}
	return old
}

func TestSwitchWaitsForAuthorizationAndNewJob(t *testing.T) {
	r := newSwitchRig(t, 1)
	defer r.close()
	old := r.start()
	before := len(r.down)
	r.notify("unconfirmed", false)
	if len(r.down) != before {
		t.Fatal("unconfirmed job leaked to miner")
	}
	r.authOK()
	if r.s.phase != feeStarting {
		t.Fatal("authorization alone must not enable fee submits")
	}
	r.notify("same-job", false) // upstream reuses the old id
	job := r.job()
	if job == old || r.s.phase != feeWork {
		t.Fatal("missing fresh job generation")
	}
	if !CleanJobsFromNotify(r.down[len(r.down)-1]) {
		t.Fatal("transition did not force clean_jobs")
	}
	r.submit(3, job)
	last := r.up[len(r.up)-1]
	if JobIDFromSubmit(last) != "same-job" || WorkerFromSubmit(last) != "fee.worker" {
		t.Fatalf("incorrect fee submit: %s", last)
	}
	r.ack(3)
	if r.s.phase != minerStarting {
		t.Fatal("restoration waits for another miner share")
	}
	msg, _ := Parse(r.up[len(r.up)-1])
	var params []string
	json.Unmarshal(msg.Params, &params)
	if len(params) != 2 || params[0] != "miner.w" || params[1] != "secret" {
		t.Fatalf("restore lost original credentials: %v", params)
	}
	r.authOK()
	r.notify("same-job", false)
	if r.s.phase != minerWork {
		t.Fatal("did not restore miner")
	}
	r.submit(4, r.job())
	if WorkerFromSubmit(r.up[len(r.up)-1]) != "miner.w" {
		t.Fatal("restored share still belongs to fee")
	}
	r.ack(4)
	report := r.s.se.stats.Report()
	if report.Totals.Accepted != 2 || report.Totals.Rejected != 0 || r.s.se.commission.Snapshot().Accepted != 1 {
		t.Fatalf("incorrect accounting: %+v", report.Totals)
	}
}

func TestSwitchRejectsOldGenerationWithoutFalseAcceptance(t *testing.T) {
	r := newSwitchRig(t, 1)
	defer r.close()
	old := r.start()
	up := len(r.up)
	err := r.s.miner([]byte(fmt.Sprintf(`{"id":3,"method":"mining.submit","params":["miner.w",%q,"extra","time","nonce"]}`, old)))
	if err == nil {
		t.Fatal("unsafe transition did not request immediate reconnect")
	}
	for _, line := range r.up[up:] {
		if IsMinerSubmit(line) {
			t.Fatal("old share sent under new authorization")
		}
	}
	if r.s.se.stats.Report().Totals.Rejected != 1 {
		t.Fatal("local stale hidden from status")
	}
}

func TestTransitionStaleDisablesPoolAcrossSessions(t *testing.T) {
	r := newSwitchRig(t, 3)
	defer r.close()
	other := newSwitchRig(t, 0)
	defer other.close()
	other.s.se.commission.Close()
	c := r.s.se.commission
	other.s.se.commission = c
	old := r.start()
	c.lastAuth = time.Time{}
	other.start()
	if err := r.s.miner([]byte(fmt.Sprintf(`{"id":3,"method":"mining.submit","params":["miner.w",%q,"extra","time","nonce"]}`, old))); err == nil {
		t.Fatal("unsafe session did not request reconnect")
	}
	if !c.unsafeSwitch(r.s.se.pool) {
		t.Fatal("transition loss did not disable pool")
	}
	// A successful service response must not clear this incident breaker.
	c.reportAuthOK(r.s.se.pool)
	if c.reserve(r.s.se.pool) || c.tryStart(r.s.se.pool, time.Now().Add(24*time.Hour)) {
		t.Fatal("unsafe pool resumed commission")
	}
	if err := other.s.tick(time.Now()); err != nil {
		t.Fatal(err)
	}
	if other.s.phase != minerStarting {
		t.Fatal("another session kept entering commission")
	}
	report := c.Snapshot()
	if len(report.Pools) != 1 || !report.Pools[0].BreakerOpen || report.Pools[0].DisabledReason != "authorization_transition_stale" {
		t.Fatalf("missing incident state in status: %+v", report.Pools)
	}
	// The unaffected session can restore ordinary work, but must not start
	// another fee cycle even though budget remains.
	other.authOK()
	other.notify("restored", true)
	other.submit(4, other.job())
	other.ack(4)
	if other.s.phase != minerWork {
		t.Fatal("commission restarted after restoration")
	}
}

func TestSwitchDoesNotWaitForSuggestedDifficulty(t *testing.T) {
	r := newSwitchRig(t, 1)
	defer r.close()
	r.s.se.commission.suggestDiff = true
	r.start()
	r.authOK()
	msg, _ := Parse(r.up[len(r.up)-1])
	if msg.Method != "mining.suggest_difficulty" {
		t.Fatal("missing asynchronous suggestion")
	}
	r.pool(`{"id":null,"method":"mining.set_difficulty","params":[16]}`)
	r.notify("fee-job", false)
	// Pool ignores the suggestion. Its actual difficulty still reaches the
	// miner before the job, so the resulting fee work remains valid.
	if r.s.phase != feeWork {
		t.Fatal("waiting for suggestion response")
	}
	if d, ok := ParseSetDifficulty(r.down[len(r.down)-2]); !ok || d != 16 {
		t.Fatal("wrong difficulty/job ordering")
	}
	r.submit(3, r.job())
	if !IsMinerSubmit(r.up[len(r.up)-1]) {
		t.Fatal("fee share delayed by suggestion")
	}
	r.ack(3)
	if got := r.s.se.commission.Snapshot().WorkAccepted; got != 16 {
		t.Fatalf("fee work=%v, want 16", got)
	}
}

func TestSwitchTracksDifficultyPerJob(t *testing.T) {
	r := newSwitchRig(t, 0)
	defer r.close()
	old := r.job()
	r.pool(`{"id":null,"method":"mining.set_difficulty","params":[2048]}`)
	r.notify("new-job", false)
	r.submit(2, old)
	if d := r.s.se.pending["2"].diff; d != 1024 {
		t.Fatalf("old job stamped at new difficulty: %v", d)
	}
}

func TestSwitchAdmissionNeverBlocksOtherMiners(t *testing.T) {
	r := newSwitchRig(t, 1)
	defer r.close()
	c := r.s.se.commission
	c.lastAuth = time.Now().Add(time.Hour) // authorizer unavailable
	r.submit(2, r.job())
	up := len(r.up)
	r.ack(2)
	if r.s.phase != minerWork || len(r.up) != up || c.takeBudget != 1 {
		t.Fatal("busy authorizer changed connection or consumed budget")
	}
	r.submit(3, r.job())
	if !IsMinerSubmit(r.up[len(r.up)-1]) {
		t.Fatal("ordinary submit stopped")
	}
}

func TestSwitchTimeoutRefundsAndRestores(t *testing.T) {
	r := newSwitchRig(t, 1)
	defer r.close()
	r.start()
	lateID := r.s.controlID
	if err := r.s.tick(r.s.deadline.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if r.s.phase != minerStarting || r.s.reserved || r.s.se.commission.takeBudget != 1 {
		t.Fatal("timeout did not refund and restore")
	}
	before := len(r.down)
	r.pool(fmt.Sprintf(`{"id":%s,"result":true,"error":null}`, lateID))
	if len(r.down) != before || r.s.authOK {
		t.Fatal("late fee response applied to miner restore")
	}
	r.authOK()
	r.notify("restored", true)
	if r.s.phase != minerWork || !r.s.se.feeDeniedNow() {
		t.Fatal("timed out fee enabled again")
	}
}

func TestSwitchDeniedRestoreRequiresReconnect(t *testing.T) {
	r := newSwitchRig(t, 1)
	defer r.close()
	r.start()
	r.pool(fmt.Sprintf(`{"id":%s,"result":false,"error":[24,"denied",null]}`, r.s.controlID))
	if r.s.phase != minerStarting || r.s.se.commission.takeBudget != 1 {
		t.Fatal("fee denial did not restore/refund")
	}
	err := r.s.pool([]byte(fmt.Sprintf(`{"id":%s,"result":false,"error":[24,"denied",null]}`, r.s.controlID)))
	if err == nil {
		t.Fatal("continued mining under unknown authorization after restore denial")
	}
}

func TestSwitchDrainsOrdinarySubmitsBeforeAuthorization(t *testing.T) {
	r := newSwitchRig(t, 1)
	defer r.close()
	r.submit(2, r.job())
	r.submit(3, r.job())
	r.ack(2)
	if r.s.phase != minerWork {
		t.Fatal("switched with ordinary share still pending")
	}
	r.ack(3)
	if r.s.phase != feeStarting {
		t.Fatal("did not switch after pending shares drained")
	}
}

func TestSwitchDoesNotBlockTrafficOnDelayedFeeReply(t *testing.T) {
	r := newSwitchRig(t, 2)
	defer r.close()
	r.start()
	r.authOK()
	r.notify("fee-job", true)
	r.submit(3, r.job())
	// No response for submit 3 yet. Other protocol messages and the next
	// valid submit must still pass, without a ten-second ack wait.
	r.miner(`{"id":4,"method":"mining.get_transactions","params":[]}`)
	r.submit(5, r.job())
	if len(r.s.se.pending) != 2 {
		t.Fatal("submit path waited for commission acknowledgement")
	}
	r.ack(5)
	if r.s.phase != feeWork {
		t.Fatal("restored with a fee share still pending")
	}
	r.ack(3)
	if r.s.phase != minerStarting {
		t.Fatal("did not restore after out-of-order acknowledgements")
	}
}

func TestSwitchUsesSameRotatedWorkerForWholeBurst(t *testing.T) {
	r := newSwitchRig(t, 1)
	defer r.close()
	c := r.s.se.commission
	c.rotateWorkers = true
	c.advanceWindowWorkerLocked()
	r.start()
	want := r.s.feeWorker
	c.advanceWindowWorkerLocked() // scheduler rotates while authorization is in flight
	r.authOK()
	r.notify("fee-job", true)
	r.submit(3, r.job())
	if WorkerFromSubmit(r.up[len(r.up)-1]) != want {
		t.Fatal("submit worker differs from authorization")
	}
}

func TestSwitchDoesNotRefundPreviousDayIntoNewBudget(t *testing.T) {
	r := newSwitchRig(t, 1)
	defer r.close()
	r.start()
	c := r.s.se.commission
	c.windowStart = r.s.reservedAt.Add(time.Hour)
	c.takeBudget = 0
	r.s.release()
	if c.takeBudget != 0 {
		t.Fatal("old reservation increased new day's budget")
	}
}

func TestFeeSwitchEOFBlocksSourceAcrossPoolAddresses(t *testing.T) {
	stats := NewStats()
	c := NewCommission("fee.worker", 1, 40, 0, 0, stats)
	c.takeBudget = 1
	defer c.Close()
	se := newSession(stats, "pool-a:3333", "10.2.38.170", c)
	defer se.close()
	proxyMiner, miner := net.Pipe()
	proxyPool, pool := net.Pipe()
	defer miner.Close()
	defer pool.Close()
	defer proxyMiner.Close()
	defer proxyPool.Close()
	miner.SetDeadline(time.Now().Add(3 * time.Second))
	pool.SetDeadline(time.Now().Add(3 * time.Second))
	finished := make(chan struct{})
	go func() { runStratum(proxyMiner, bufio.NewReader(proxyMiner), proxyPool, se); close(finished) }()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer pool.Close()
		r := bufio.NewReader(pool)
		// Initial miner authorize and one ordinary submit are accepted.
		for i := 0; i < 2; i++ {
			line, err := r.ReadBytes('\n')
			if err != nil {
				return
			}
			msg, err := Parse(line)
			if err != nil {
				return
			}
			if writeLine(pool, []byte(fmt.Sprintf(`{"id":%s,"result":true,"error":null}`, msg.ID))) != nil {
				return
			}
			if i == 0 {
				if writeLine(pool, []byte(`{"id":null,"method":"mining.notify","params":["initial","p","c1","c2",[],"v","b","t",true]}`)) != nil {
					return
				}
			}
		}
		// Simulate a pool closing the connection on service authorize.
		r.ReadBytes('\n')
	}()
	m := &loadMiner{conn: miner, r: bufio.NewReader(miner), w: bufio.NewWriter(miner)}
	m.send(map[string]interface{}{"id": 1, "method": "mining.authorize", "params": []string{"miner.w", "x"}})
	m.readID(1)
	m.readJob()
	m.send(map[string]interface{}{"id": 2, "method": "mining.submit", "params": []string{"miner.w", m.job, "e", "t", "n"}})
	m.readID(2)
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("EOF did not end switch")
	}
	<-serverDone
	if c.tryStartMiner("pool-b:3333", se.source, time.Now().Add(time.Hour)) {
		t.Fatal("same ASIC retried commission at another pool")
	}
	snapshot := c.Snapshot()
	if snapshot.Failed != 1 || len(snapshot.DisabledSources) != 1 || snapshot.DisabledSources[0].Source != se.source || snapshot.DisabledSources[0].Reason != "commission_connection_closed" {
		t.Fatalf("missing cross-pool incident state: %+v", snapshot)
	}
	if c.takeBudget != 1 {
		t.Fatal("unsent reservation was not refunded")
	}
	if !c.tryStartMiner("pool-b:3333", "10.2.38.171", time.Now().Add(time.Hour)) {
		t.Fatal("unaffected ASIC was disabled on another pool")
	}
}

func TestNormalEOFDoesNotDisableCommission(t *testing.T) {
	r := newSwitchRig(t, 0)
	defer r.close()
	r.s.finish("miner", "EOF")
	if len(r.s.se.commission.Snapshot().DisabledSources) != 0 || r.s.se.commission.unsafeSwitch(r.s.se.pool) {
		t.Fatal("ordinary EOF was treated as a commission failure")
	}
}

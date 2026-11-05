package proxy

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"
)

const commissionTransitionTimeout = 10 * time.Second
const commissionWorkTimeout = time.Minute

var errCommissionComplete = errors.New("commission batch complete; reconnect with miner authorization")

type authPhase int

const (
	minerWork authPhase = iota
	feeStarting
	feeWork
	minerStarting
)

type issuedJob struct {
	id    string
	epoch uint64
	diff  float64
}

// stratumSwitch is owned by the connection event loop. In particular, no
// goroutine can insert authorize between a submit and its accounting.
type stratumSwitch struct {
	se                *session
	phase             authPhase
	epoch             uint64
	serial            uint64
	controlID         string
	serviceIDs        map[string]bool
	serviceOrder      []string
	authOK            bool
	notifyBeforeAck   bool
	pendingNotify     []byte
	pendingNotifyDiff float64
	completed         bool
	deadline          time.Time
	feeWorker         string
	reserved          bool
	reservedAt        time.Time
	stopFee           bool
	poolDiff          float64
	minerDiff         float64
	suggestAt         time.Time
	suggestUntil      time.Time
	jobs              map[string]issuedJob
	jobOrder          []string
	aliasJobs         bool
	lastMinerAuth     []byte
	toPool            func([]byte) error
	toMiner           func([]byte) error
}

type stratumInput struct {
	line []byte
	err  error
}

func runStratum(client net.Conn, reader *bufio.Reader, pool net.Conn, se *session) {
	done := make(chan struct{})
	minerLines, poolLines := make(chan stratumInput), make(chan stratumInput)
	read := func(conn net.Conn, r *bufio.Reader, out chan<- stratumInput) {
		scanner := bufio.NewScanner(r)
		scanner.Buffer(make([]byte, lineBuf), maxLineSize)
		for {
			conn.SetReadDeadline(time.Now().Add(idleTimeout))
			if !scanner.Scan() {
				break
			}
			line := append([]byte(nil), scanner.Bytes()...)
			select {
			case out <- stratumInput{line: line}:
			case <-done:
				return
			}
		}
		select {
		case out <- stratumInput{err: scanner.Err()}:
		case <-done:
		}
	}
	readersDone := make(chan struct{}, 2)
	go func() { read(client, reader, minerLines); readersDone <- struct{}{} }()
	go func() { read(pool, bufio.NewReader(pool), poolLines); readersDone <- struct{}{} }()
	defer func() {
		close(done)
		client.Close()
		pool.Close()
		<-readersDone
		<-readersDone
	}()
	s := &stratumSwitch{se: se, jobs: make(map[string]issuedJob),
		aliasJobs:     se.commission != nil && se.commission.Enabled(),
		lastMinerAuth: append([]byte(nil), se.initialAuth...),
		toPool: func(line []byte) error {
			pool.SetWriteDeadline(time.Now().Add(writeTimeout))
			return writeLine(pool, line)
		},
		toMiner: func(line []byte) error {
			client.SetWriteDeadline(time.Now().Add(writeTimeout))
			return writeLine(client, line)
		},
	}
	defer s.release()
	observedSide, endReason := "proxy", "connection ended"
	defer func() { s.finish(observedSide, endReason) }()
	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	for {
		var timeout <-chan time.Time
		if s.phase != minerWork {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			delay := time.Until(s.deadline)
			if delay < 0 {
				delay = 0
			}
			timer.Reset(delay)
			timeout = timer.C
		}
		var err error
		select {
		case in := <-minerLines:
			if in.line == nil {
				observedSide, endReason = "miner", readEndReason(in.err)
				logReadErr("miner", client, in.err)
				return
			}
			err = s.miner(in.line)
		case in := <-poolLines:
			if in.line == nil {
				observedSide, endReason = "pool", readEndReason(in.err)
				logReadErr("pool", pool, in.err)
				return
			}
			err = s.pool(in.line)
		case now := <-timeout:
			err = s.tick(now)
		}
		if err != nil {
			endReason = err.Error()
			if err == errCommissionComplete {
				log.Printf("[COMMISSION] batch_complete miner=%s pool=%s action=reconnect", se.source, se.pool)
			} else {
				log.Printf("[CONN] stratum miner=%s pool=%s: %v", se.source, se.pool, err)
			}
			return
		}
	}
}

func readEndReason(err error) string {
	if err == nil {
		return "EOF"
	}
	return err.Error()
}

func (s *stratumSwitch) phaseName() string {
	switch s.phase {
	case feeStarting:
		return "fee_authorize"
	case feeWork:
		return "fee_work"
	case minerStarting:
		return "miner_authorize"
	default:
		return "miner_work"
	}
}

func (s *stratumSwitch) finish(side, reason string) {
	if !s.completed && s.phase != minerWork && s.se.commission != nil {
		s.se.commission.disableSwitch(s.se.pool, s.se.source, "commission_connection_closed")
		s.se.commission.countFailed(s.se.pool)
	}
	log.Printf("[DIAG] connection_end miner=%s pool=%s phase=%s epoch=%d observed_side=%s reason=%q auth_confirmed=%t notify_before_ack=%t",
		s.se.source, s.se.pool, s.phaseName(), s.epoch, side, reason, s.authOK, s.notifyBeforeAck)
}

func (s *stratumSwitch) release() {
	if s.reserved {
		s.se.commission.release(s.reservedAt)
		s.reserved = false
	}
}

func (s *stratumSwitch) pending() int {
	s.se.mu.Lock()
	defer s.se.mu.Unlock()
	return len(s.se.pending)
}

func (s *stratumSwitch) switchAuth(fee bool, now time.Time) error {
	s.epoch++
	s.serial++
	tag := fmt.Sprintf("%s%d", commissionAuthTag, s.serial)
	s.controlID = fmt.Sprintf("%q", tag)
	if s.serviceIDs == nil {
		s.serviceIDs = make(map[string]bool)
	}
	s.serviceIDs[s.controlID] = true
	s.serviceOrder = append(s.serviceOrder, s.controlID)
	if len(s.serviceOrder) > 64 {
		delete(s.serviceIDs, s.serviceOrder[0])
		s.serviceOrder = s.serviceOrder[1:]
	}
	s.authOK = false
	s.notifyBeforeAck = false
	s.pendingNotify = nil
	s.deadline = now.Add(commissionTransitionTimeout)
	s.se.lastSwitch(now)
	worker := s.se.workerName()
	line := miningAuthorizeLine(worker, tag)
	if fee {
		s.phase = feeStarting
		s.stopFee = false
		s.feeWorker = s.se.commission.WindowWorker()
		worker = s.feeWorker
		line = miningAuthorizeLine(worker, tag)
	} else {
		s.phase = minerStarting
		// Preserve the miner's password and optional authorization parameters.
		if len(s.lastMinerAuth) != 0 {
			line = replaceMessageID(s.lastMinerAuth, tag)
		}
	}
	log.Printf("[COMMISSION] switch miner=%s pool=%s worker=%q epoch=%d", s.se.source, s.se.pool, worker, s.epoch)
	return s.toPool(line)
}

func (s *stratumSwitch) tick(now time.Time) error {
	unsafe := s.se.commission != nil && s.se.commission.switchBlocked(s.se.pool, s.se.source)
	if unsafe && s.phase == feeStarting {
		s.release()
		s.se.denyFee()
		return s.switchAuth(false, now)
	}
	if s.phase == feeStarting || s.phase == minerStarting {
		if now.Before(s.deadline) {
			return nil
		}
		if s.phase == minerStarting {
			return fmt.Errorf("miner authorization/job timeout; reconnect required")
		}
		s.se.commission.disableSwitch(s.se.pool, s.se.source, "commission_authorization_job_timeout")
		s.release()
		s.se.denyFee()
		s.se.commission.countFailed(s.se.pool)
		return s.switchAuth(false, now)
	}
	if s.phase == feeWork {
		if unsafe || now.After(s.deadline) || !s.se.commission.Enabled() {
			s.stopFee = true
		}
		if s.stopFee && s.pending() == 0 {
			s.release()
			// Returning authorize can leave the ASIC hashing fee jobs while
			// waiting for a replacement notify. A fresh connection obtains the
			// miner's own subscribe, extranonce and authorize together.
			s.completed = true
			return errCommissionComplete
		}
		if s.stopFee && now.After(s.deadline) {
			return fmt.Errorf("commission submit response timeout; reconnect required")
		}
	}
	return nil
}

func (s *stratumSwitch) maybeStart(now time.Time) error {
	c := s.se.commission
	if c == nil || !s.aliasJobs || s.phase != minerWork || s.se.feeDeniedNow() ||
		s.se.workerName() == "" || len(s.jobs) == 0 || s.pending() != 0 {
		return nil
	}
	// Admission is nonblocking. A busy global authorizer leaves the miner's
	// connection untouched, rather than sleeping in its submit path.
	if !c.tryStartMiner(s.se.pool, s.se.source, now) {
		return nil
	}
	s.reserved = true
	s.reservedAt = now
	return s.switchAuth(true, now)
}

func (s *stratumSwitch) rejectTransition(line []byte) error {
	id, ok := SubmitID(line)
	if !ok {
		return fmt.Errorf("submit without id during authorization switch")
	}
	reason := "stale job after authorization switch"
	job, known := s.jobs[JobIDFromSubmit(line)]
	unsafe := s.epoch > 0 && (s.phase != minerWork || known && job.epoch != s.epoch)
	if !unsafe {
		reason = "unknown job id"
	}
	s.se.submitJob(id, WorkerFromSubmit(line), JobIDFromSubmit(line))
	s.se.resolve(PoolResponse{ID: id, Error: reason})
	// An in-flight old-job share during entry is an honest stale response,
	// not evidence that the pool can never collect commission. Completion
	// now reconnects immediately, so there is no restore interval producing
	// repeated fee-job rejects and permanently disabling the pool.
	response, _ := json.Marshal(struct {
		ID     json.RawMessage `json:"id"`
		Result bool            `json:"result"`
		Error  []interface{}   `json:"error"`
	}{json.RawMessage(id), false, []interface{}{21, reason, nil}})
	if err := s.toMiner(response); err != nil {
		return err
	}
	return s.tick(time.Now())
}

func (s *stratumSwitch) miner(line []byte) error {
	s.se.traceHandshake(line)
	if IsMinerAuthorize(line) {
		// A miner-initiated authorization during a service switch would race
		// with that switch. Reconnect instead of silently binding wrong work.
		if s.phase != minerWork {
			return fmt.Errorf("miner reauthorized during commission switch")
		}
		s.lastMinerAuth = append([]byte(nil), line...)
		s.se.authorize(WorkerFromAuthorize(line))
		s.se.trackControl(line)
		return s.toPool(line)
	}
	if IsMinerSubscribe(line) {
		s.se.trackControl(line)
	}
	if msg, err := Parse(line); err == nil && msg.Method == "mining.extranonce.subscribe" {
		s.se.trackControl(line)
	}
	if !IsMinerSubmit(line) {
		return s.toPool(line)
	}
	if s.phase != minerWork {
		if err := s.tick(time.Now()); err != nil {
			return err
		}
	}
	id, hasID := SubmitID(line)
	originalJob := JobIDFromSubmit(line)
	job, known := s.jobs[originalJob]
	if s.aliasJobs {
		if !known || job.epoch != s.epoch || s.phase == feeStarting || s.phase == minerStarting {
			return s.rejectTransition(line)
		}
		var err error
		line, err = replaceParam(line, 1, job.id)
		if err != nil {
			return err
		}
	}
	if s.phase == feeWork {
		// Once admitted, work belongs to this authorization even if the
		// budget runs out while earlier responses are still in flight.
		// Do not relabel it as ordinary miner work.
		if s.stopFee || !hasID {
			return s.rejectTransition(line)
		}
		var err error
		line, err = rewriteSubmitWorker(line, s.feeWorker)
		if err != nil {
			return err
		}
		s.reserved = false
		diff := s.se.markCommissionJob(id, s.feeWorker, originalJob, job.diff)
		s.se.commission.countSteal(s.se.pool, diff)
		s.se.stats.noteCommissionSteal(s.se.pool, s.feeWorker, diff, s.minerDiff)
		if err := s.toPool(line); err != nil {
			return err
		}
		s.deadline = time.Now().Add(commissionWorkTimeout)
		s.reserved = s.se.commission.reserve(s.se.pool)
		s.reservedAt = time.Now()
		s.stopFee = !s.reserved
		return nil
	}
	s.se.submitJobDifficulty(id, WorkerFromSubmit(line), originalJob, job.diff)
	if err := s.toPool(line); err != nil {
		return err
	}
	return nil
}

func (s *stratumSwitch) pool(line []byte) error {
	if s.phase != minerWork {
		if err := s.tick(time.Now()); err != nil {
			return err
		}
	}
	if resp, ok := ParsePoolResponse(line); ok {
		if s.controlID != "" && resp.ID == s.controlID {
			log.Printf("[DIAG] commission_authorize miner=%s pool=%s phase=%s epoch=%d accepted=%t notify_before_ack=%t error=%q",
				s.se.source, s.se.pool, s.phaseName(), s.epoch, resp.Accepted, s.notifyBeforeAck, resp.Error)
			s.controlID = ""
			if !resp.Accepted {
				if s.phase == minerStarting {
					return fmt.Errorf("miner authorization rejected: %s", resp.Error)
				}
				s.release()
				s.se.denyFee()
				s.se.commission.disableSwitch(s.se.pool, s.se.source, "commission_authorization_rejected")
				s.se.commission.reportDeny(s.se.pool)
				return s.switchAuth(false, time.Now())
			}
			s.authOK = true
			if s.phase == feeStarting {
				s.se.commission.reportAuthOK(s.se.pool)
				now := time.Now()
				if s.se.commission.SuggestDifficulty() && s.minerDiff > 0 &&
					now.Sub(s.suggestAt) >= 90*time.Second && !now.Before(s.suggestUntil) {
					// A suggestion is advisory. Never wait for it, and always
					// publish the actual difficulty with the next job.
					s.suggestAt = now
					if err := s.toPool(miningSuggestDifficultyLine(s.minerDiff, commissionDiffTag)); err != nil {
						return err
					}
				}
			}
			if len(s.pendingNotify) != 0 {
				pending, diff := s.pendingNotify, s.pendingNotifyDiff
				s.pendingNotify = nil
				latestDiff := s.poolDiff
				s.poolDiff = diff
				err := s.pool(pending)
				s.poolDiff = latestDiff
				return err
			}
			return nil
		}
		if resp.ID == commissionDiffID {
			s.se.stats.noteControl(s.se.pool, "mining.suggest_difficulty", resp.Accepted, resp.Error)
			if strings.Contains(resp.Error, "Frequency limit") {
				s.suggestUntil = time.Now().Add(3 * time.Minute)
			}
			return nil
		}
		if s.serviceIDs[resp.ID] {
			return nil
		} // late control reply from a timed out switch
		if method := s.se.resolveControl(resp.ID); method != "" {
			s.se.stats.noteControl(s.se.pool, method, resp.Accepted, resp.Error)
		}
		s.se.resolve(resp)
		if err := s.toMiner(line); err != nil {
			return err
		}
		if err := s.tick(time.Now()); err != nil {
			return err
		}
		return s.maybeStart(time.Now())
	}
	if resp, ok := ParseControlResponse(line); ok {
		if method := s.se.resolveControl(resp.ID); method != "" {
			if method == "mining.subscribe" {
				s.se.traceSubscription(line)
			}
			s.se.stats.noteControl(s.se.pool, method, resp.Accepted, resp.Error)
		}
	}
	if msg, err := Parse(line); err == nil && msg.Method == "mining.set_extranonce" {
		s.se.tracePoolExtranonce(msg.Params)
	}
	if diff, ok := ParseSetDifficulty(line); ok {
		s.poolDiff = diff
		if s.aliasJobs {
			return nil
		} // publish atomically with the next notify
		s.se.setDifficulty(diff)
	}
	if jobID, ok := JobIDFromNotify(line); ok {
		transition := s.phase == feeStarting || s.phase == minerStarting
		if transition && !s.authOK {
			// Only retain a previously unseen upstream job. A notification
			// already queued before authorize must not become fee work merely
			// because it was read while the response was in flight.
			seen := false
			for _, job := range s.jobs {
				if job.id == jobID {
					seen = true
					break
				}
			}
			if !seen {
				s.pendingNotify = append([]byte(nil), line...)
				s.pendingNotifyDiff = s.poolDiff
			}
			if !s.notifyBeforeAck {
				s.notifyBeforeAck = true
				log.Printf("[DIAG] commission_notify miner=%s pool=%s phase=%s epoch=%d before_auth_ack=true job=%q action=buffer_until_ack",
					s.se.source, s.se.pool, s.phaseName(), s.epoch, jobID)
			}
			return nil
		}
		if transition {
			log.Printf("[DIAG] commission_notify miner=%s pool=%s phase=%s epoch=%d before_auth_ack=false job=%q action=activate",
				s.se.source, s.se.pool, s.phaseName(), s.epoch, jobID)
			if s.phase == feeStarting {
				s.phase = feeWork
			} else {
				s.phase = minerWork
			}
			s.deadline = time.Now().Add(commissionWorkTimeout)
		}
		if s.aliasJobs {
			// Aliases prevent a reused upstream job id from turning a delayed
			// old submit into work for a different authorization.
			s.serial++
			alias := fmt.Sprintf("mp-%x-%x", s.epoch, s.serial)
			s.jobs[alias] = issuedJob{jobID, s.epoch, s.poolDiff}
			s.jobOrder = append(s.jobOrder, alias)
			if len(s.jobOrder) > 256 {
				delete(s.jobs, s.jobOrder[0])
				s.jobOrder = s.jobOrder[1:]
			}
			var err error
			line, err = replaceParam(line, 0, alias)
			if err != nil {
				return err
			}
			if transition {
				line, err = replaceParam(line, 8, true)
				if err != nil {
					return err
				}
			}
			if s.poolDiff > 0 {
				diffLine, _ := json.Marshal(map[string]interface{}{"id": nil, "method": "mining.set_difficulty", "params": []float64{s.poolDiff}})
				if err := s.toMiner(diffLine); err != nil {
					return err
				}
				s.se.setDifficulty(s.poolDiff)
				if s.phase == feeWork {
					s.se.setFeeDiff(s.poolDiff)
				} else {
					s.minerDiff = s.poolDiff
				}
			}
			jobID = alias
		}
		s.se.noteNotify(jobID, CleanJobsFromNotify(line))
	}
	return s.toMiner(line)
}

func replaceParam(line []byte, index int, value interface{}) ([]byte, error) {
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(line, &msg); err != nil {
		return nil, err
	}
	var params []json.RawMessage
	if err := json.Unmarshal(msg["params"], &params); err != nil {
		return nil, err
	}
	if index >= len(params) {
		return nil, fmt.Errorf("missing Stratum parameter %d", index)
	}
	params[index], _ = json.Marshal(value)
	msg["params"], _ = json.Marshal(params)
	return json.Marshal(msg)
}

func replaceMessageID(line []byte, id string) []byte {
	var msg map[string]json.RawMessage
	if json.Unmarshal(line, &msg) != nil {
		return line
	}
	msg["id"], _ = json.Marshal(id)
	raw, _ := json.Marshal(msg)
	return raw
}

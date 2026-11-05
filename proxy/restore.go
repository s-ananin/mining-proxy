package proxy

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"
)

const minerRestoreTimeout = 10 * time.Second

type minerRestore struct {
	deadline   time.Time
	authorized bool
	notified   bool
	updates    [][]byte
}

func (s *session) beginMinerRestore(pool net.Conn) {
	s.mu.Lock()
	s.restore = &minerRestore{deadline: time.Now().Add(minerRestoreTimeout)}
	if pool != nil {
		pool.SetReadDeadline(s.restore.deadline)
	}
	s.mu.Unlock()
}

func (s *session) poolReadDeadline(pool net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	deadline := time.Now().Add(idleTimeout)
	if s.restore != nil {
		deadline = s.restore.deadline
	}
	pool.SetReadDeadline(deadline)
}

// Restoration keeps feeActive set until the pool has confirmed authorize
// and supplied a job. Preserve the order of difficulty/extranonce/notify,
// including pools which send their notify before the authorize response.
func (s *session) restorePoolLine(raw []byte) (bool, [][]byte, error) {
	msg, err := Parse(raw)
	if err != nil {
		return false, nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.restore
	if string(msg.ID) == commissionRestoreID {
		if r == nil {
			return true, nil, nil
		}
		resp, ok := ParsePoolResponse(raw)
		if !ok || !resp.Accepted {
			return true, nil, fmt.Errorf("miner restore authorization rejected")
		}
		r.authorized = true
	} else if r != nil && (msg.Method == "mining.set_difficulty" || msg.Method == "mining.set_extranonce" || msg.Method == "mining.notify") {
		if msg.Method == "mining.notify" {
			var params []json.RawMessage
			if json.Unmarshal(msg.Params, &params) != nil || len(params) < 9 {
				return true, nil, fmt.Errorf("invalid miner restore notify")
			}
			params[8] = json.RawMessage("true")
			// Modify only the clean_jobs flag; preserve the original job ID
			// and all other message fields, including extensions.
			var fields map[string]json.RawMessage
			json.Unmarshal(raw, &fields)
			fields["params"], _ = json.Marshal(params)
			raw, _ = json.Marshal(fields)
			r.notified = true
		}
		if len(r.updates) >= 32 {
			return true, nil, fmt.Errorf("too many updates during miner restore")
		}
		r.updates = append(r.updates, append([]byte(nil), raw...))
	} else {
		return false, nil, nil
	}
	if !r.authorized || !r.notified {
		return true, nil, nil
	}
	s.restore = nil
	s.feeActive = false
	return true, r.updates, nil
}

func submitJobID(raw []byte) string {
	msg, err := Parse(raw)
	if err != nil {
		return ""
	}
	var params []json.RawMessage
	if json.Unmarshal(msg.Params, &params) != nil || len(params) < 2 {
		return ""
	}
	var job string
	json.Unmarshal(params[1], &job)
	return job
}

func (s *session) oldCommissionShare(raw []byte) bool {
	job := submitJobID(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.restore != nil || !s.feeActive && s.feeJobs[job]
}

// A queued share of a fee job must not be sent as ordinary miner work.
// Send an honest stale response; never manufacture an accepted result.
func (s *session) rejectCommissionTail(dst net.Conn, raw []byte) error {
	id, ok := SubmitID(raw)
	if !ok {
		return fmt.Errorf("commission tail submit has no id")
	}
	reason := "stale commission job after miner reauthorization"
	s.submit(id, WorkerFromSubmit(raw))
	s.resolve(PoolResponse{ID: id, Error: reason})
	response, _ := json.Marshal(struct {
		ID     json.RawMessage `json:"id"`
		Result bool            `json:"result"`
		Error  []interface{}   `json:"error"`
	}{json.RawMessage(id), false, []interface{}{21, reason, nil}})
	s.minerWriteMu.Lock()
	defer s.minerWriteMu.Unlock()
	dst.SetWriteDeadline(time.Now().Add(writeTimeout))
	return writeLine(dst, response)
}

func (s *session) publishMinerRestore(dst net.Conn, updates [][]byte) error {
	s.minerWriteMu.Lock()
	defer s.minerWriteMu.Unlock()
	for _, line := range updates {
		if diff, ok := ParseSetDifficulty(line); ok {
			s.setDifficulty(diff)
		}
		if job, ok := JobIDFromNotify(line); ok {
			s.setJobID(job)
		}
		dst.SetWriteDeadline(time.Now().Add(writeTimeout))
		if err := writeLine(dst, line); err != nil {
			return err
		}
	}
	log.Printf("[COMMISSION] miner authorization and new job restored miner=%s pool=%s", s.source, s.pool)
	return nil
}

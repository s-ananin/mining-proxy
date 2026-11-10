package proxy

import (
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
	s.restoreDone = make(chan struct{})
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
	s.feeActive = false
	return true, r.updates, nil
}

// A new fee window must not interrupt an in-progress miner restore.
func (s *session) restoringMiner() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.restore != nil
}

func (s *session) publishMinerRestore(dst net.Conn, updates [][]byte) error {
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
	s.mu.Lock()
	s.restore = nil
	if s.restoreDone != nil {
		close(s.restoreDone)
		s.restoreDone = nil
	}
	s.mu.Unlock()
	log.Printf("[COMMISSION] miner authorization and new job restored miner=%s pool=%s", s.source, s.pool)
	return nil
}

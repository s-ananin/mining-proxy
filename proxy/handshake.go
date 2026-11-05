package proxy

import (
	"encoding/json"
	"log"
)

// Handshake diagnostics intentionally log selected metadata only, never raw
// requests, authorize passwords, configure values or extranonce contents.
func (s *session) firstHandshakeEvent(event string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handshakeLogged == nil {
		s.handshakeLogged = make(map[string]bool)
	}
	if s.handshakeLogged[event] {
		return false
	}
	s.handshakeLogged[event] = true
	return true
}

func boundedDiagnostic(value string, max int) string {
	if len(value) > max {
		return value[:max]
	}
	return value
}

func (s *session) traceHandshake(raw []byte) {
	msg, err := Parse(raw)
	if err != nil {
		return
	}
	switch msg.Method {
	case "mining.subscribe":
		if !s.firstHandshakeEvent(msg.Method) {
			return
		}
		var params []json.RawMessage
		var agent string
		if json.Unmarshal(msg.Params, &params) == nil && len(params) > 0 {
			json.Unmarshal(params[0], &agent)
		}
		log.Printf("[DIAG] miner_handshake miner=%s pool=%s method=%s agent=%q", s.source, s.pool, msg.Method, boundedDiagnostic(agent, 128))
	case "mining.extranonce.subscribe":
		if s.firstHandshakeEvent(msg.Method) {
			log.Printf("[DIAG] miner_handshake miner=%s pool=%s method=%s support=requested", s.source, s.pool, msg.Method)
		}
	case "mining.configure":
		if !s.firstHandshakeEvent(msg.Method) {
			return
		}
		var params []json.RawMessage
		var extensions []string
		if json.Unmarshal(msg.Params, &params) == nil && len(params) > 0 {
			json.Unmarshal(params[0], &extensions)
		}
		if len(extensions) > 16 {
			extensions = extensions[:16]
		}
		for i := range extensions {
			extensions[i] = boundedDiagnostic(extensions[i], 64)
		}
		log.Printf("[DIAG] miner_handshake miner=%s pool=%s method=%s extensions=%q", s.source, s.pool, msg.Method, extensions)
	}
}

func (s *session) traceSubscription(raw []byte) {
	msg, err := Parse(raw)
	if err != nil {
		return
	}
	var result []json.RawMessage
	if json.Unmarshal(msg.Result, &result) != nil || len(result) < 3 {
		return
	}
	var nonce string
	var size int
	if json.Unmarshal(result[1], &nonce) != nil || json.Unmarshal(result[2], &size) != nil {
		return
	}
	if s.firstHandshakeEvent("subscription_result") {
		log.Printf("[DIAG] pool_extranonce miner=%s pool=%s method=mining.subscribe extranonce1_hex_chars=%d extranonce2_bytes=%d", s.source, s.pool, len(nonce), size)
	}
}

func (s *session) tracePoolExtranonce(raw json.RawMessage) {
	var params []json.RawMessage
	if json.Unmarshal(raw, &params) != nil || len(params) < 2 {
		return
	}
	var nonce string
	var size int
	if json.Unmarshal(params[0], &nonce) != nil || json.Unmarshal(params[1], &size) != nil {
		return
	}
	if s.firstHandshakeEvent("set_extranonce") {
		log.Printf("[DIAG] pool_extranonce miner=%s pool=%s method=mining.set_extranonce extranonce1_hex_chars=%d extranonce2_bytes=%d", s.source, s.pool, len(nonce), size)
	}
}

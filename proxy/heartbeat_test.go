package proxy

import (
	"testing"
	"time"
)

func TestHeartbeatFresh(t *testing.T) {
	h := NewHeartbeat()
	if !h.IsAlive() {
		t.Fatal("fresh heartbeat must be alive")
	}
}

func TestHeartbeatStaleAndRevive(t *testing.T) {
	old := staleAfterHeartbeat
	staleAfterHeartbeat = 20 * time.Millisecond
	defer func() { staleAfterHeartbeat = old }()

	h := NewHeartbeat()
	time.Sleep(40 * time.Millisecond)
	if h.IsAlive() {
		t.Fatal("stale heartbeat must be dead")
	}

	h.Beat()
	if !h.IsAlive() {
		t.Fatal("heartbeat must be alive right after Beat()")
	}
	if h.Age() > 200*time.Millisecond {
		t.Fatalf("Age() after Beat() = %v, expected ~0", h.Age())
	}
}

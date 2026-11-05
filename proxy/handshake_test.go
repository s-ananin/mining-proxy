package proxy

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestHandshakeDiagnosticsTrackExtranonceWithoutSecrets(t *testing.T) {
	var out bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&out)
	defer log.SetOutput(previous)
	se := newSession(NewStats(), "pool:3333", "10.0.0.1", nil)
	defer se.close()
	se.trackControl([]byte(`{"id":1,"method":"mining.subscribe","params":["ASIC/test"]}`))
	se.traceHandshake([]byte(`{"id":1,"method":"mining.subscribe","params":["ASIC/test"]}`))
	se.traceHandshake([]byte(`{"id":2,"method":"mining.configure","params":[["version-rolling"],{"private":"do-not-log-config"}]}`))
	se.trackControl([]byte(`{"id":3,"method":"mining.authorize","params":["worker","do-not-log-password"]}`))
	se.trackControl([]byte(`{"id":4,"method":"mining.extranonce.subscribe","params":[]}`))
	if method := se.resolveControl("4"); method != "mining.extranonce.subscribe" {
		t.Fatalf("extranonce subscription response not tracked: %s", method)
	}
	se.traceSubscription([]byte(`{"id":1,"result":[[],"deadbeef",4],"error":null}`))
	se.tracePoolExtranonce([]byte(`["cafebabe",8]`))
	got := out.String()
	for _, secret := range []string{"do-not-log-password", "do-not-log-config", "deadbeef", "cafebabe"} {
		if strings.Contains(got, secret) {
			t.Fatalf("handshake logs exposed %q", secret)
		}
	}
	for _, want := range []string{`agent="ASIC/test"`, "version-rolling", "support=requested", "extranonce2_bytes=4", "extranonce2_bytes=8"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing metadata %q: %s", want, got)
		}
	}
	if strings.Count(got, `agent="ASIC/test"`) != 1 {
		t.Fatal("duplicate handshake logs")
	}
}

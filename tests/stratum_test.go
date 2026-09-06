package proxy_test

import (
	"encoding/json"
	"testing"

	"mining-proxy/proxy"
)

func TestIsMinerSubmit(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{
			name: "valid submit",
			raw:  `{"id":1,"method":"mining.submit","params":["worker","job","extra","time","nonce"]}`,
			want: true,
		},
		{
			name: "not submit",
			raw:  `{"id":1,"method":"mining.notify","params":["job",...]}`,
			want: false,
		},
		{
			name: "invalid json",
			raw:  `not json`,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := proxy.IsMinerSubmit([]byte(tt.raw)); got != tt.want {
				t.Errorf("IsMinerSubmit(%s) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestRewriteWorkerSubmit(t *testing.T) {
	raw := `{"id":1,"method":"mining.submit","params":["old.worker","job","extra","time","nonce"]}`
	out, err := proxy.RewriteWorkerSubmit([]byte(raw), "new_worker")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var msg proxy.StratumMessage
	if err := json.Unmarshal(out, &msg); err != nil {
		t.Fatalf("output not valid JSON: %v", err)
	}

	var params []string
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		t.Fatalf("params not array: %v", err)
	}
	if params[0] != "new_worker" {
		t.Errorf("worker not rewritten: got %s, want new_worker", params[0])
	}
	// остальные параметры (job, extra, time, nonce) должны сохраниться
	if len(params) != 5 {
		t.Errorf("expected 5 params, got %d", len(params))
	}
}

func TestExtractWorkerFromAuthorize(t *testing.T) {
	raw := `{"id":1,"method":"mining.authorize","params":["pool.worker","x"]}`
	want := "worker"
	if got := proxy.ExtractWorkerFromAuthorize([]byte(raw)); got != want {
		t.Errorf("ExtractWorkerFromAuthorize = %v, want %v", got, want)
	}
}

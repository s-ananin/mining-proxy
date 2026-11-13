package proxy_test

import (
	"testing"

	"mining-proxy/proxy"
)

func TestIsMinerSubmit(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{"submit", `{"id":1,"method":"mining.submit","params":["w","job","e","t","n"]}`, true},
		{"notify", `{"id":null,"method":"mining.notify","params":[]}`, false},
		{"garbage", `not json`, false},
		{"empty", ``, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := proxy.IsMinerSubmit([]byte(tt.raw)); got != tt.want {
				t.Errorf("IsMinerSubmit(%s) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

// Воркер сохраняется ПОЛНЫМ именем — монитору важна исходная строка
// майнера ("pool.worker"), а не только последняя часть.
func TestWorkerExtraction(t *testing.T) {
	auth := `{"id":1,"method":"mining.authorize","params":["viabtc.вася3344","x"]}`
	if got := proxy.WorkerFromAuthorize([]byte(auth)); got != "viabtc.вася3344" {
		t.Errorf("WorkerFromAuthorize = %q, want viabtc.вася3344", got)
	}
	sub := `{"id":2,"method":"mining.submit","params":["viabtc.вася3344","job","e","t","n"]}`
	if got := proxy.WorkerFromSubmit([]byte(sub)); got != "viabtc.вася3344" {
		t.Errorf("WorkerFromSubmit = %q, want viabtc.вася3344", got)
	}
}

func TestWorkerExtractionWrongMethod(t *testing.T) {
	raw := `{"id":1,"method":"mining.subscribe","params":["viabtc.вася3344","x"]}`
	if got := proxy.WorkerFromAuthorize([]byte(raw)); got != "" {
		t.Errorf("ожидалась пустая строка для не-authorize, получено %q", got)
	}
}

func TestSubmitID(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
		ok   bool
	}{
		{"numeric", `{"id":7,"method":"mining.submit","params":["w"]}`, "7", true},
		{"string", `{"id":"abc","method":"mining.submit","params":["w"]}`, `"abc"`, true},
		{"null id", `{"id":null,"method":"mining.submit","params":["w"]}`, "", false},
		{"not submit", `{"id":7,"method":"mining.authorize","params":["w"]}`, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := proxy.SubmitID([]byte(tt.raw))
			if got != tt.want || ok != tt.ok {
				t.Errorf("SubmitID(%s) = (%q,%v), want (%q,%v)", tt.raw, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestParsePoolResponse(t *testing.T) {
	resp, ok := proxy.ParsePoolResponse([]byte(`{"id":3,"result":true,"error":null}`))
	if !ok || !resp.Accepted || resp.ID != "3" || resp.Error != "" {
		t.Errorf("accept: got %+v ok=%v", resp, ok)
	}

	resp, ok = proxy.ParsePoolResponse([]byte(`{"id":3,"result":false,"error":[21,"low difficulty share",null]}`))
	if !ok || resp.Accepted || resp.Error != "low difficulty share" {
		t.Errorf("reject: got %+v ok=%v", resp, ok)
	}

	// Ответ на subscribe (result — массив) не должен считаться ответом на
	// шару: иначе массив коллизионирует с id submit-а.
	if _, ok = proxy.ParsePoolResponse([]byte(`{"id":1,"result":[["sub1"],"01000000",4],"error":null}`)); ok {
		t.Error("ответ subscribe не должен разбираться как ответ на шару")
	}

	// Запрос (есть method) — не ответ.
	if _, ok = proxy.ParsePoolResponse([]byte(`{"id":1,"method":"mining.notify","params":[]}`)); ok {
		t.Error("запрос пула не должен разбираться как ответ")
	}
}

func TestParseSetDifficulty(t *testing.T) {
	got, ok := proxy.ParseSetDifficulty([]byte(`{"id":null,"method":"mining.set_difficulty","params":[64]}`))
	if !ok || got != 64 {
		t.Errorf("ParseSetDifficulty = (%v,%v), want (64,true)", got, ok)
	}
	if _, ok := proxy.ParseSetDifficulty([]byte(`{"id":null,"method":"mining.notify","params":[]}`)); ok {
		t.Error("notify не должен парситься как set_difficulty")
	}
	if _, ok := proxy.ParseSetDifficulty([]byte(`{"method":"mining.set_difficulty","params":["x"]}`)); ok {
		t.Error("нечисловая сложность не должна парситься")
	}
}

func TestLooksLikeStratum(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{"subscribe", `{"id":1,"method":"mining.subscribe","params":[]}`, true},
		{"notify", `{"id":null,"method":"mining.notify","params":[]}`, true},
		{"tls handshake", "\x16\x03\x01\x02\x00\x01", false},
		{"http", "GET / HTTP/1.1\r\n", false},
		{"binary", "\x00\x01\x02\x03", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := proxy.LooksLikeStratum([]byte(tt.raw)); got != tt.want {
				t.Errorf("LooksLikeStratum(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

package proxy

import (
	"encoding/hex"
	"testing"
	"time"
)

// notifyWithCoinbase собирает mining.notify, в coinbase которого (coinb1)
// зашит текст tag.
func notifyWithCoinbase(tag string) []byte {
	cb1 := "01000000010000ffffffff" + hex.EncodeToString([]byte(tag))
	return []byte(`{"id":null,"method":"mining.notify","params":["j1","00","` + cb1 +
		`","ffffffff01","[]","20000000","17021673","6b041f8f",true]}`)
}

func TestCoinbaseFromNotify(t *testing.T) {
	cb, ok := coinbaseFromNotify(notifyWithCoinbase("/ViaBTC/Mined by acc/"))
	if !ok {
		t.Fatal("coinbaseFromNotify: ok=false на валидном notify")
	}
	if got := coinbaseText(cb); got == "" || !contains(got, "ViaBTC") {
		t.Errorf("coinbaseText = %q, ждали подпись с ViaBTC", got)
	}
	if _, ok := coinbaseFromNotify([]byte(`{"method":"mining.set_difficulty","params":[16384]}`)); ok {
		t.Error("coinbaseFromNotify: ok=true не на notify")
	}
	if _, ok := coinbaseFromNotify([]byte(`{"id":1,"result":true}`)); ok {
		t.Error("coinbaseFromNotify: ok=true на ответе пула")
	}
}

func TestMatchPoolTag(t *testing.T) {
	cb, _ := coinbaseFromNotify(notifyWithCoinbase("/ViaBTC/Mined by mpool/"))
	ant, _ := coinbaseFromNotify(notifyWithCoinbase("Mined by AntPool900"))

	cases := []struct {
		name     string
		coinbase []byte
		tags     []string
		want     string
	}{
		{"viabtc match", cb, []string{"ViaBTC"}, "ViaBTC"},
		{"case-insensitive", cb, []string{"viabtc"}, "viabtc"},
		{"antpool not in list", ant, []string{"ViaBTC"}, ""},
		{"antpool in list", ant, []string{"ViaBTC", "AntPool"}, "AntPool"},
		{"empty list", cb, nil, ""},
		{"empty coinbase", nil, []string{"ViaBTC"}, ""},
		{"no match", ant, []string{"F2Pool", "SecPool"}, ""},
	}
	for _, tc := range cases {
		if got := matchPoolTag(tc.coinbase, tc.tags); got != tc.want {
			t.Errorf("%s: matchPoolTag = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// TestPoolFilterGatesCommission: при включённом фильтре комиссия берётся
// только после notify с подписью из списка, иначе соединение прозрачно.
func TestPoolFilterGatesCommission(t *testing.T) {
	stats := NewStats()
	c := NewCommission("mpool", 1, 0, 5*time.Minute, 0, stats, WithCommissionPools([]string{"ViaBTC"}))

	via := newSession(stats, "via", "10.0.0.1", c)
	foreign := newSession(stats, "foreign", "10.0.0.2", c)

	// До notify подпись неизвестна — комиссия запрещена на обоих.
	if via.poolTagAllowsCommission() {
		t.Error("без notify комиссия не должна быть разрешена")
	}

	via.observeCoinbase(mustCoinbase(t, "/ViaBTC/Mined by mpool/"))
	foreign.observeCoinbase(mustCoinbase(t, "Mined by AntPool"))

	if !via.poolTagAllowsCommission() {
		t.Error("ViaBTC: комиссия должна быть разрешена")
	}
	if foreign.poolTagAllowsCommission() {
		t.Error("AntPool: комиссия должна быть запрещена")
	}

	// Пул сменил подпись на чужую — комиссия снова запрещена.
	via.observeCoinbase(mustCoinbase(t, "Mined by SecPool"))
	if via.poolTagAllowsCommission() {
		t.Error("после смены подписи на чужую комиссия должна прекратиться")
	}
}

// TestPoolFilterOffAllowsAny: без commission_pools фильтр не ограничивает.
func TestPoolFilterOffAllowsAny(t *testing.T) {
	stats := NewStats()
	c := NewCommission("mpool", 1, 0, 5*time.Minute, 0, stats)
	s := newSession(stats, "any", "10.0.0.3", c)
	if !s.poolTagAllowsCommission() {
		t.Error("без фильтра комиссия должна быть разрешена независимо от подписи")
	}
	if c.PoolFilterOn() {
		t.Error("PoolFilterOn должен быть false без commission_pools")
	}
}

func mustCoinbase(t *testing.T, tag string) []byte {
	t.Helper()
	cb, ok := coinbaseFromNotify(notifyWithCoinbase(tag))
	if !ok {
		t.Fatalf("не удалось собрать coinbase для %q", tag)
	}
	return cb
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

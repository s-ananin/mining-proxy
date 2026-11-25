package proxy

import (
	"testing"
	"time"
)

func TestCommissionDomainFilter(t *testing.T) {
	cases := []struct {
		name    string
		allowed []string
		domain  string
		want    bool
	}{
		{"exact", []string{"btc.viabtc.world"}, "btc.viabtc.world", true},
		{"case and trailing dot", []string{"BTC.ViaBTC.World."}, "btc.viabtc.world", true},
		{"different host", []string{"btc.viabtc.world"}, "btc.ru.viabtc.world", false},
		{"parent domain", []string{"viabtc.world"}, "btc.viabtc.world", false},
		{"deceptive suffix", []string{"btc.viabtc.world"}, "btc.viabtc.world.example", false},
		{"unknown", []string{"btc.viabtc.world"}, "", false},
		{"short name", []string{"ViaBTC"}, "btc.viabtc.world", true},
		{"short name with nested subdomain", []string{"viabtc"}, "btc.ru.viabtc.world", true},
		{"short name with different TLD", []string{"viabtc"}, "btc.viabtc.io", true},
		{"short name with multi-label suffix", []string{"viabtc"}, "btc.viabtc.co.uk", true},
		{"brand in subdomain only", []string{"viabtc"}, "viabtc.example.com", false},
		{"brand substring", []string{"viabtc"}, "btc.notviabtc.com", false},
		{"brand under private suffix", []string{"viabtc"}, "viabtc.github.io", false},
		{"public suffix itself", []string{"uk"}, "co.uk", false},
		{"IP literal", []string{"158.160.226.85"}, "158.160.226.85", false},
		{"filter disabled", nil, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			commission := &Commission{poolDomains: tc.allowed}
			if got := commission.allowsPoolDomain(tc.domain); got != tc.want {
				t.Fatalf("allowsPoolDomain(%q) = %v, want %v", tc.domain, got, tc.want)
			}
		})
	}
}

func TestCommissionDomainFilterSharedDestination(t *testing.T) {
	const (
		ip      = "130.193.56.79"
		pool    = ip + ":3333"
		allowed = "gate.emcd.network"
		foreign = "ru.hash.care"
		first   = "192.0.2.10"
		second  = "192.0.2.11"
	)
	tracker := NewPoolDNS()
	now := time.Now()
	tracker.store(poolDNSKey{first, ip}, allowed, now, 60)
	tracker.store(poolDNSKey{second, ip}, foreign, now, 60)
	commission := &Commission{poolDomains: []string{allowed}}
	if !commission.allowsPoolDomain(tracker.Domain(first, pool)) {
		t.Fatal("allowlisted ASIC on shared endpoint denied")
	}
	if commission.allowsPoolDomain(tracker.Domain(second, pool)) {
		t.Fatal("different domain on shared endpoint allowed")
	}
	tracker.store(poolDNSKey{first, ip}, foreign, now, 60)
	if commission.allowsPoolDomain(tracker.Domain(first, pool)) {
		t.Fatal("ambiguous domain allowed")
	}
}

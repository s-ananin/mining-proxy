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
			commission := &Commission{worker: "fee"}
			WithCommissionPools(poolRoutes(tc.allowed, ""))(commission)
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
	commission := &Commission{worker: "fee"}
	WithCommissionPools(poolRoutes([]string{allowed}, ""))(commission)
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

// poolRoutes строит белый список пулов с одним воркером на всех.
func poolRoutes(pools []string, worker string) []CommissionPoolRoute {
	var out []CommissionPoolRoute
	for _, p := range pools {
		out = append(out, CommissionPoolRoute{Pool: p, Worker: worker})
	}
	return out
}

func TestCommissionWorkerPerPool(t *testing.T) {
	c := &Commission{worker: "default.fee"}
	WithCommissionPools([]CommissionPoolRoute{
		{Pool: "ViaBTC", Worker: "anton425"},
		{Pool: "emcd", Worker: "emcd.generated01"},
		{Pool: "antpool"},
		{Pool: "ss.antpool.com", Worker: "ant.exact"},
	})(c)
	for _, tc := range []struct{ domain, want string }{
		{"btc.viabtc.io", "anton425"},
		{"BTC.ViaBTC.World.", "anton425"},
		{"gate.emcd.network", "emcd.generated01"},
		{"ss.antpool.com", "ant.exact"}, // полное имя важнее короткого
		{"stratum.antpool.com", "default.fee"},
		{"ru.hash.care", ""},
		{"", ""},
	} {
		if got := c.WorkerFor(tc.domain); got != tc.want {
			t.Errorf("WorkerFor(%q) = %q, want %q", tc.domain, got, tc.want)
		}
	}
	if !c.enabledLocked() {
		t.Fatal("commission with pool workers disabled")
	}
	if got := c.workers(); len(got) != 4 {
		t.Fatalf("workers = %q", got)
	}
}

func TestCommissionEnabledWithoutDefaultWorker(t *testing.T) {
	c := NewCommission("", 1, 40, 0, 0, NewStats(),
		WithCommissionPools([]CommissionPoolRoute{{Pool: "emcd", Worker: "emcd.gen"}}))
	if !c.Enabled() {
		t.Fatal("pool worker must enable commission")
	}
	if got := c.WorkerFor("gate.emcd.network"); got != "emcd.gen" {
		t.Fatalf("WorkerFor = %q", got)
	}
	rep := c.Snapshot()
	if !rep.Enabled || rep.PoolWorkers["emcd"] != "emcd.gen" {
		t.Fatalf("snapshot = %+v", rep)
	}
	if NewCommission("", 1, 40, 0, 0, NewStats(), WithCommissionPools(poolRoutes([]string{"emcd"}, ""))).Enabled() {
		t.Fatal("commission without any worker enabled")
	}
}

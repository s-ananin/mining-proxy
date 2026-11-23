package proxy

import (
	"bufio"
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

// fakeDNS — подменный резолвер с управляемыми ответами.
type fakeDNS struct {
	mu   sync.Mutex
	ans  map[string][]string
	fail map[string]bool
}

func (f *fakeDNS) set(host string, ips ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ans[host] = ips
	delete(f.fail, host)
}

func (f *fakeDNS) breakHost(host string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail[host] = true
}

func (f *fakeDNS) lookup(_ context.Context, host string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail[host] {
		return nil, errors.New("dns down")
	}
	return f.ans[host], nil
}

func newFakeDNS() *fakeDNS {
	return &fakeDNS{ans: map[string][]string{}, fail: map[string]bool{}}
}

func TestAllowlistMatchesResolvedIPAndPort(t *testing.T) {
	dns := newFakeDNS()
	dns.set("bs.poolbinance.com", "1.1.1.1", "1.1.1.2")
	a := NewPoolAllowlist([]string{"BS.poolbinance.com:3333", "10.0.0.5:443"}, dns.lookup)
	a.refresh()

	cases := []struct {
		dest string
		name string
		ok   bool
	}{
		{"1.1.1.1:3333", "bs.poolbinance.com:3333", true},
		{"1.1.1.2:3333", "bs.poolbinance.com:3333", true},
		{"1.1.1.1:443", "", false},                                   // тот же IP, другой порт
		{"9.9.9.9:3333", "", false},                                  // чужой пул
		{"10.0.0.5:443", "10.0.0.5:443", true},                       // IP в конфиге
		{"bs.poolbinance.com:3333", "bs.poolbinance.com:3333", true}, // прямое подключение
		{"garbage", "", false},
	}
	for _, c := range cases {
		name, ok := a.Match(c.dest)
		if ok != c.ok || name != c.name {
			t.Errorf("Match(%q) = %q,%v; want %q,%v", c.dest, name, ok, c.name, c.ok)
		}
	}
}

func TestAllowlistKeepsAddressesOnDNSFailureAndExpiresStale(t *testing.T) {
	dns := newFakeDNS()
	dns.set("pool.example", "2.2.2.1")
	a := NewPoolAllowlist([]string{"pool.example:3333"}, dns.lookup)
	e := a.entries[0]
	t0 := time.Now()
	a.refreshEntry(e, t0)

	// DNS упал — прежний адрес остаётся.
	dns.breakHost("pool.example")
	a.refreshEntry(e, t0.Add(2*allowlistAddrTTL))
	if _, ok := a.Match("2.2.2.1:3333"); !ok {
		t.Fatal("address dropped on DNS failure")
	}

	// Round-robin: новый IP добавляется, старый держится до TTL.
	dns.set("pool.example", "2.2.2.2")
	a.refreshEntry(e, t0.Add(allowlistAddrTTL/2))
	if _, ok := a.Match("2.2.2.1:3333"); !ok {
		t.Fatal("old round-robin address dropped before TTL")
	}
	if _, ok := a.Match("2.2.2.2:3333"); !ok {
		t.Fatal("new address not added")
	}
	a.refreshEntry(e, t0.Add(allowlistAddrTTL+time.Minute))
	if _, ok := a.Match("2.2.2.1:3333"); ok {
		t.Fatal("stale address kept after TTL")
	}

	want := map[string][]string{"pool.example:3333": {"2.2.2.2:3333"}}
	if got := a.Snapshot(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Snapshot = %v, want %v", got, want)
	}
}

func TestCommissionAllowlistGatesReserveAndCountsInactive(t *testing.T) {
	dns := newFakeDNS()
	dns.set("fee.pool", "3.3.3.3")
	allow := NewPoolAllowlist([]string{"fee.pool:3333"}, dns.lookup)
	allow.refresh()
	c := NewCommission("fee", 1, 0, time.Minute, 0, NewStats(), WithPoolAllowlist(allow))
	defer c.Close()
	c.takeBudget = 100

	if !c.admitPool("3.3.3.3:3333") || !c.reserve("3.3.3.3:3333", 1) {
		t.Fatal("allowed pool rejected")
	}
	if c.admitPool("8.8.8.8:3333") || c.reserve("8.8.8.8:3333", 1) || c.hasBudget("8.8.8.8:3333") {
		t.Fatal("foreign pool admitted")
	}
	c.admitPool("8.8.8.8:3333")

	// Без бюджета комиссия ничего бы не взяла — шара не недобранная.
	c.mu.Lock()
	c.takeBudget = 0
	c.mu.Unlock()
	c.admitPool("8.8.8.8:3333")

	rep := c.Snapshot()
	if got := rep.InactivePools["8.8.8.8:3333"]; got != 2 {
		t.Fatalf("inactive = %v, want 2", rep.InactivePools)
	}
	if _, ok := rep.InactivePools["3.3.3.3:3333"]; ok {
		t.Fatal("allowed pool counted as inactive")
	}
	if !reflect.DeepEqual(rep.UpstreamPools, map[string][]string{"fee.pool:3333": {"3.3.3.3:3333"}}) {
		t.Fatalf("upstream_pools = %v", rep.UpstreamPools)
	}
}

func TestEmptyAllowlistDisablesCommissionEverywhere(t *testing.T) {
	c := NewCommission("fee", 1, 0, time.Minute, 0, NewStats(), WithPoolAllowlist(NewPoolAllowlist(nil, newFakeDNS().lookup)))
	defer c.Close()
	c.takeBudget = 100
	if c.PoolAllowed("1.2.3.4:3333") || c.reserve("1.2.3.4:3333", 1) {
		t.Fatal("empty allowlist allowed commission")
	}
}

func TestForeignPoolWorkExcludedFromBudgetBase(t *testing.T) {
	dns := newFakeDNS()
	dns.set("fee.pool", "3.3.3.3")
	allow := NewPoolAllowlist([]string{"fee.pool:3333"}, dns.lookup)
	allow.refresh()
	stats := NewStats()
	c := NewCommission("fee", 1, 0, time.Minute, 0, stats, WithPoolAllowlist(allow))
	defer c.Close()

	for _, pool := range []string{"3.3.3.3:3333", "8.8.8.8:3333"} {
		se := newSession(stats, pool, "miner", c)
		se.authorize("w")
		se.setDifficulty(100)
		se.submitJob("1", "w", "job")
		se.resolve(PoolResponse{ID: "1", Accepted: true})
		se.close()
	}
	if got := stats.AcceptedWork(); got != 100 {
		t.Fatalf("budget base work = %v, want 100 (foreign pool excluded)", got)
	}
}

// Шара на пул вне списка проходит майнеру без служебного authorize, даже
// если бюджет есть, и попадает в inactive_pools.
func TestForeignPoolShareGoesThroughUntouched(t *testing.T) {
	stats := NewStats()
	allow := NewPoolAllowlist([]string{"fee.pool:3333"}, newFakeDNS().lookup)
	c := NewCommission("fee.worker", 1, 40, 0, 0, stats, WithPoolAllowlist(allow))
	defer c.Close()
	c.takeBudget = 1e9
	se := newSession(stats, "8.8.8.8:3333", "miner", c)
	defer se.close()
	se.authorize("main.worker")
	se.setDifficulty(16)

	client, miner := net.Pipe()
	upstream, pool := net.Pipe()
	done := make(chan struct{})
	go func() { pipeMinerToPool(client, bufio.NewReader(client), upstream, se, c); close(done) }()
	defer func() {
		client.Close()
		miner.Close()
		upstream.Close()
		pool.Close()
		<-done
	}()

	raw := `{"id":1,"method":"mining.submit","params":["main.worker","job","e","t","n"]}`
	miner.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	pool.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if err := writeLine(miner, []byte(raw)); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(pool).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	if line != raw+"\n" {
		t.Fatalf("foreign pool share changed: %s", line)
	}
	if got := c.Snapshot().InactivePools["8.8.8.8:3333"]; got != 1 {
		t.Fatalf("inactive = %d, want 1", got)
	}
}

package proxy

import (
	"testing"
	"time"
)

// Snapshot считает подключённых воркеров/пулы и тех, с кого комиссия
// может браться сейчас: BTC, проверка пройдена, предохранитель закрыт.
func TestSnapshotActivity(t *testing.T) {
	stats := NewStats()
	c := NewCommission("fee.worker", 1, 40, 0, 0, stats, WithBTCOnly(),
		WithPoolProbe(func(string, string) error { return nil }))

	connect := func(pool, coin string, workers ...string) {
		stats.Connect(pool)
		if coin != "" {
			stats.SetPoolCoin(pool, coin)
		}
		for _, w := range workers {
			stats.BindWorker(pool, w, "")
		}
	}
	connect("btc-ok", "btc", "a", "b")
	connect("btc-open", "btc", "c")
	connect("btc-unprobed", "btc", "d")
	connect("bch", "other", "e")
	connect("gone", "btc", "f")
	stats.UnbindWorker("gone", "f")
	stats.Disconnect("gone")

	c.mu.Lock()
	for _, p := range []string{"btc-ok", "btc-open", "bch", "gone"} {
		c.probes[p] = &poolProbe{status: probeOK, until: time.Now().Add(time.Hour)}
	}
	c.breakers["btc-open"] = &poolBreaker{openTill: time.Now().Add(time.Hour)}
	c.mu.Unlock()

	rep := c.Snapshot()
	if rep.PoolsActive != 4 || rep.PoolsWithCommission != 1 {
		t.Errorf("pools active/with_commission = %d/%d, want 4/1", rep.PoolsActive, rep.PoolsWithCommission)
	}
	if rep.WorkersActive != 5 || rep.WorkersWithCommission != 2 {
		t.Errorf("workers active/with_commission = %d/%d, want 5/2", rep.WorkersActive, rep.WorkersWithCommission)
	}
}

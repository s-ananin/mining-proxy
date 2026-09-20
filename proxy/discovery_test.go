package proxy

import (
	"testing"
)

// TestDiscoveryObserve проверяет наполнение реестра «пул+воркер»:
// пул, воркер из authorize/submit, счётчики шар, источник и нормализацию
// воркера формата "pool.worker".
func TestDiscoveryObserve(t *testing.T) {
	d := NewDiscovery()

	d.ObservePool("1.2.3.4:3333")
	d.ObserveWorker("1.2.3.4:3333", ExtractWorkerFromAuthorize(
		[]byte(`{"id":1,"method":"mining.authorize","params":["viabtc.вася3344","x"]}`)),
		"10.0.0.5:5000")
	d.ObserveWorker("1.2.3.4:3333", ExtractWorkerFromAuthorize(
		[]byte(`{"id":2,"method":"mining.authorize","params":["viabtc.петя1","x"]}`)),
		"10.0.0.6:5000")

	for i := 0; i < 3; i++ {
		d.ObserveSubmit("1.2.3.4:3333", ExtractWorkerFromSubmit(
			[]byte(`{"id":3,"method":"mining.submit","params":["viabtc.вася3344","job","e","t","n"]}`)),
			"10.0.0.5:5000")
	}

	snaps := d.Snapshot()
	if len(snaps) != 1 {
		t.Fatalf("pools = %d, want 1", len(snaps))
	}
	p := snaps[0]
	if p.Pool != "1.2.3.4:3333" {
		t.Errorf("pool = %q, want 1.2.3.4:3333", p.Pool)
	}
	if p.Submits != 3 {
		t.Errorf("pool submits = %d, want 3", p.Submits)
	}
	if len(p.Workers) != 2 {
		t.Fatalf("workers = %d, want 2", len(p.Workers))
	}

	var found bool
	for _, w := range p.Workers {
		if w.Worker == "вася3344" {
			found = true
			if w.Submits != 3 {
				t.Errorf("worker submits = %d, want 3", w.Submits)
			}
			if w.LastSource != "10.0.0.5" {
				t.Errorf("worker source = %q, want 10.0.0.5", w.LastSource)
			}
		}
	}
	if !found {
		t.Errorf("worker вася3344 not found in %+v", p.Workers)
	}
}

// TestDiscoveryMultiplePools проверяет, что несколько пулов на разных
// IP-адресах (один и тот же порт) — это РАЗНЫЕ записи реестра: у каждого свои
// воркеры, счётчики и источник. Одинаковое имя воркера на разных пулах не
// смешивается (ключ — пара «пул + воркер»).
func TestDiscoveryMultiplePools(t *testing.T) {
	d := NewDiscovery()

	pools := []struct {
		pool   string
		worker string
		source string
		n      int
	}{
		{"10.0.0.1:3333", "вася3344", "192.168.1.10", 2},
		{"10.0.0.2:3333", "вася3344", "192.168.1.11", 3},
		{"10.0.0.3:3333", "петя", "192.168.1.12", 4},
	}
	for _, p := range pools {
		d.ObserveWorker(p.pool, p.worker, p.source)
		for i := 0; i < p.n; i++ {
			d.ObserveSubmit(p.pool, p.worker, p.source)
		}
	}

	snaps := d.Snapshot()
	if len(snaps) != 3 {
		t.Fatalf("pools = %d, want 3", len(snaps))
	}

	for _, want := range pools {
		var found bool
		for _, p := range snaps {
			if p.Pool != want.pool {
				continue
			}
			found = true
			if p.Submits != int64(want.n) {
				t.Errorf("pool %s submits = %d, want %d", want.pool, p.Submits, want.n)
			}
			if len(p.Workers) != 1 {
				t.Fatalf("pool %s workers = %d, want 1", want.pool, len(p.Workers))
			}
			w := p.Workers[0]
			if w.Worker != want.worker {
				t.Errorf("pool %s worker = %q, want %q", want.pool, w.Worker, want.worker)
			}
			if w.Submits != int64(want.n) {
				t.Errorf("pool %s worker submits = %d, want %d", want.pool, w.Submits, want.n)
			}
			if w.LastSource != want.source {
				t.Errorf("pool %s source = %q, want %q", want.pool, w.LastSource, want.source)
			}
		}
		if !found {
			t.Errorf("pool %s not found in %+v", want.pool, snaps)
		}
	}
}

// TestDiscoveryNilSafe проверяет, что вызовы на nil-реестре не паникуют:
// это позволяет передавать nil в тестах и необязательных местах.
func TestDiscoveryNilSafe(t *testing.T) {
	var d *Discovery
	d.ObservePool("1.2.3.4:3333")
	d.ObserveWorker("1.2.3.4:3333", "w", "10.0.0.1")
	d.ObserveSubmit("1.2.3.4:3333", "w", "10.0.0.1")
	if got := d.Snapshot(); got != nil {
		t.Errorf("nil discovery snapshot = %v, want nil", got)
	}
	if got := d.DiscoverySnapshot(); got != nil {
		t.Errorf("nil discovery DiscoverySnapshot = %v, want nil", got)
	}
}

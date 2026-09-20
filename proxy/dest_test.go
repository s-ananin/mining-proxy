package proxy

import (
	"net"
	"testing"
)

// TestGetOriginalDst проверяет, что getsockopt(SO_ORIGINAL_DST) работает и
// для прямого соединения (без iptables DNAT) возвращает адрес нашего listener.
func TestGetOriginalDst(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type result struct {
		addr net.Addr
		ok   bool
	}
	res := make(chan result, 1)

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		addr, ok := getOriginalDst(c.(*net.TCPConn))
		res <- result{addr, ok}
	}()

	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()

	r := <-res
	if !r.ok || r.addr == nil {
		// ОС без netfilter/не Linux — пропускаем (SO_ORIGINAL_DST недоступен).
		t.Skipf("SO_ORIGINAL_DST unavailable: addr=%v ok=%v", r.addr, r.ok)
	}

	// Без DNAT ядро вернёт тот же 127.0.0.1:port, куда мы сами сконнектились.
	if r.addr.String() != ln.Addr().String() {
		t.Errorf("original dst = %v, want %v", r.addr, ln.Addr())
	}
}

// TestResolveDestinationFallback проверяет: прямой коннект на наш listener
// (loopback) в прозрачном режиме считается «прямым» и уходит на fallback.
func TestResolveDestinationFallback(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type result struct {
		addr string
		ssl  bool
	}
	res := make(chan result, 1)

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		addr, ssl := resolveDestination(c, ProxyPass{
			ListenAddr:  ln.Addr().String(),
			Fallback:    "1.2.3.4:3333",
			FallbackSSL: true,
			Transparent: true,
		})
		res <- result{addr, ssl}
	}()

	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer cc.Close()

	r := <-res
	// Прямой коннект => fallback с его ssl-флагом.
	if r.addr != "1.2.3.4:3333" || !r.ssl {
		t.Errorf("resolve = %q ssl=%v, want fallback 1.2.3.4:3333 ssl=true", r.addr, r.ssl)
	}
}

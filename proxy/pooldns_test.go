package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestPoolDNSDomain(t *testing.T) {
	tracker := &PoolDNS{names: make(map[poolDNSKey]map[string]time.Time)}
	const source = "192.0.2.10"
	const dest = "192.0.2.42:7016"
	const domain = "ltc-ru.kryptex.network"
	reply := &dns.Msg{}
	for _, line := range []string{
		"ltc-ru.kryptex.network. 60 IN CNAME edge.example.",
		"edge.example. 300 IN A 192.0.2.42",
		"unrelated.example. 300 IN A 192.0.2.43",
	} {
		record, err := dns.NewRR(line)
		if err != nil {
			t.Fatal(err)
		}
		reply.Answer = append(reply.Answer, record)
	}
	question := dns.Question{Name: "LTC-RU.Kryptex.Network.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	now := time.Now()
	tracker.remember(source, question, reply, now.Add(-2*time.Minute))
	if got := tracker.Domain(source, dest); got != "" {
		t.Fatalf("expired CNAME: got %q", got)
	}
	tracker.remember(source, question, reply, now)
	if got := tracker.Domain(source, dest); got != domain {
		t.Fatalf("got %q, want %q", got, domain)
	}
	if got := tracker.Domain("192.0.2.11", dest); got != "" {
		t.Fatalf("different ASIC: got %q", got)
	}
	if got := tracker.Domain(source, "192.0.2.43:7016"); got != "" {
		t.Fatalf("unrelated answer: got %q", got)
	}
	tracker.store(poolDNSKey{source, "192.0.2.42"}, "other.example", now, 60)
	if got := tracker.Domain(source, dest); got != "" {
		t.Fatalf("shared destination: got %q", got)
	}
}

func TestPoolDNSForwardUDPAndTCP(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		reply := new(dns.Msg).SetReply(q)
		reply.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.42"),
		}}
		w.WriteMsg(reply)
	})
	for _, server := range []*dns.Server{{Listener: tcp}, {PacketConn: udp}} {
		ready := make(chan struct{})
		server.Handler = handler
		server.NotifyStartedFunc = func() { close(ready) }
		go server.ActivateAndServe()
		<-ready
		defer server.Shutdown()
	}
	tracker, err := StartPoolDNS("127.0.0.1:0", tcp.Addr().String(), []string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	defer tracker.Close()

	for _, transport := range []string{"udp", "tcp"} {
		q := new(dns.Msg).SetQuestion("pool.example.", dns.TypeA)
		client := dns.Client{Net: transport, Timeout: time.Second}
		reply, _, err := client.Exchange(q, tracker.servers[0].Listener.Addr().String())
		if err != nil {
			t.Fatalf("%s: %v", transport, err)
		}
		if len(reply.Answer) != 1 {
			t.Fatalf("%s: unexpected answer %v", transport, reply.Answer)
		}
	}
	if got := tracker.Domain("127.0.0.1", "192.0.2.42:7016"); got != "pool.example" {
		t.Fatalf("got domain %q", got)
	}
}

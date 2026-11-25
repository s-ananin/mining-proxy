package proxy

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestPoolDNSCaptureAndReport(t *testing.T) {
	query := new(dns.Msg).SetQuestion("ss.antpool.com.", dns.TypeA)
	reply := new(dns.Msg).SetReply(query)
	for _, line := range []string{
		"ss.antpool.com. 60 IN CNAME edge.example.",
		"edge.example. 60 IN A 8.209.6.11",
		"edge.example. 60 IN A 8.209.6.47",
	} {
		answer, err := dns.NewRR(line)
		if err != nil {
			t.Fatal(err)
		}
		reply.Answer = append(reply.Answer, answer)
	}
	payload, err := reply.Pack()
	if err != nil {
		t.Fatal(err)
	}

	frame := make([]byte, 16+20+8+len(payload))
	binary.BigEndian.PutUint16(frame[14:], 0x0800)
	ip := frame[16:]
	ip[0], ip[9] = 0x45, 17
	binary.BigEndian.PutUint16(ip[2:], uint16(len(ip)))
	copy(ip[16:20], net.ParseIP("10.122.1.3").To4())
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp, 53)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)

	var capture bytes.Buffer
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header, 0xa1b2c3d4)
	binary.LittleEndian.PutUint32(header[20:], 113)
	capture.Write(header)
	record := make([]byte, 16)
	binary.LittleEndian.PutUint32(record[8:], uint32(len(frame)))
	capture.Write(record)
	capture.Write(frame)

	tracker := NewPoolDNS()
	if err := readPoolDNSCapture(&capture, tracker); err != io.EOF {
		t.Fatal(err)
	}
	stats := NewStats()
	for _, pool := range []string{"8.209.6.11:3333", "8.209.6.47:3333"} {
		domain := tracker.Domain("10.122.1.3", pool)
		if domain != "ss.antpool.com" {
			t.Fatalf("%s: unexpected domain %q", pool, domain)
		}
		stats.Connect(pool)
		stop := stats.TrackPoolDomain(pool, domain)
		snapshot := stats.Report()
		if len(snapshot.Pools) != 1 || snapshot.Pools[0].PoolDomain != domain {
			t.Fatalf("unexpected pool report: %+v", snapshot.Pools)
		}
		stopOther := stats.TrackPoolDomain(pool, "other.example")
		shared := stats.Report().Pools[0]
		if shared.PoolDomain != "" || len(shared.PoolDomains) != 2 ||
			shared.PoolDomains[0] != "other.example" || shared.PoolDomains[1] != domain {
			t.Fatalf("unexpected report for shared endpoint: %+v", shared)
		}
		stopOther()
		stop()
		closed := stats.Report().Pools[0]
		if closed.PoolDomain != "" || len(closed.PoolDomains) != 0 {
			t.Fatalf("closed connection domain still reported: %+v", closed)
		}
		stats.Disconnect(pool)
	}
}

package proxy

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type poolDNSKey struct {
	source string
	ip     string
}

// PoolDNS forwards DNS for ASICs and correlates their answers with TCP destinations.
type PoolDNS struct {
	servers  []*dns.Server
	subnets  []*net.IPNet
	upstream string

	mu          sync.Mutex
	names       map[poolDNSKey]map[string]time.Time
	nextCleanup time.Time
}

// NewPoolDNS creates a DNS correlation table shared by capture and forwarding.
func NewPoolDNS() *PoolDNS {
	return &PoolDNS{names: make(map[poolDNSKey]map[string]time.Time)}
}

func StartPoolDNS(listen, upstream string, subnets []string) (*PoolDNS, error) {
	d := NewPoolDNS()
	d.upstream = upstream
	for _, subnet := range subnets {
		_, network, err := net.ParseCIDR(subnet)
		if err != nil {
			return nil, err
		}
		d.subnets = append(d.subnets, network)
	}
	tcp, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, err
	}
	udp, err := net.ListenPacket("udp", tcp.Addr().String())
	if err != nil {
		tcp.Close()
		return nil, err
	}
	handler := dns.HandlerFunc(d.serveDNS)
	d.servers = []*dns.Server{{Listener: tcp, Handler: handler}, {PacketConn: udp, Handler: handler}}
	for _, server := range d.servers {
		ready := make(chan struct{})
		stopped := make(chan error, 1)
		server.NotifyStartedFunc = func() { close(ready) }
		go func(server *dns.Server) { stopped <- server.ActivateAndServe() }(server)
		select {
		case <-ready:
		case err := <-stopped:
			tcp.Close()
			udp.Close()
			return nil, fmt.Errorf("start DNS: %v", err)
		}
	}
	return d, nil
}

func (d *PoolDNS) Close() {
	for _, server := range d.servers {
		server.Shutdown()
	}
}

func (d *PoolDNS) serveDNS(w dns.ResponseWriter, request *dns.Msg) {
	source := sourceHost(w.RemoteAddr())
	ip := net.ParseIP(source)
	allowed := false
	for _, subnet := range d.subnets {
		if subnet.Contains(ip) {
			allowed = true
			break
		}
	}
	reply := new(dns.Msg)
	if !allowed || request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 {
		w.WriteMsg(reply.SetRcode(request, dns.RcodeRefused))
		return
	}
	network := w.RemoteAddr().Network()
	client := dns.Client{Net: network, Timeout: 3 * time.Second}
	reply, _, err := client.Exchange(request, d.upstream)
	if err != nil {
		w.WriteMsg(new(dns.Msg).SetRcode(request, dns.RcodeServerFailure))
		return
	}
	d.remember(source, request.Question[0], reply, time.Now())
	w.WriteMsg(reply)
}

func (d *PoolDNS) remember(source string, question dns.Question, reply *dns.Msg, now time.Time) {
	if reply.Truncated || reply.Rcode != dns.RcodeSuccess || question.Qclass != dns.ClassINET ||
		(question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA) {
		return
	}
	name := strings.TrimSuffix(strings.ToLower(question.Name), ".")
	owner := name
	ttl := ^uint32(0)
	// Follow the answer's CNAME chain and use the shortest TTL along the path.
	for hops := 0; hops <= len(reply.Answer); hops++ {
		var alias *dns.CNAME
		for _, record := range reply.Answer {
			header := record.Header()
			if header.Class != dns.ClassINET || strings.TrimSuffix(strings.ToLower(header.Name), ".") != owner {
				continue
			}
			if cname, ok := record.(*dns.CNAME); ok {
				alias = cname
				continue
			}
			if header.Rrtype != question.Qtype {
				continue
			}
			var ip net.IP
			switch address := record.(type) {
			case *dns.A:
				ip = address.A
			case *dns.AAAA:
				ip = address.AAAA
			default:
				continue
			}
			lifetime := ttl
			if header.Ttl < lifetime {
				lifetime = header.Ttl
			}
			d.store(poolDNSKey{source, ip.String()}, name, now, lifetime)
		}
		if alias == nil {
			break
		}
		if alias.Hdr.Ttl < ttl {
			ttl = alias.Hdr.Ttl
		}
		owner = strings.TrimSuffix(strings.ToLower(alias.Target), ".")
	}
}

func (d *PoolDNS) store(key poolDNSKey, name string, now time.Time, ttl uint32) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !now.Before(d.nextCleanup) {
		for key, names := range d.names {
			for name, expiry := range names {
				if now.After(expiry) {
					delete(names, name)
				}
			}
			if len(names) == 0 {
				delete(d.names, key)
			}
		}
		d.nextCleanup = now.Add(time.Minute)
	}
	names := d.names[key]
	if names == nil {
		names = make(map[string]time.Time)
		d.names[key] = names
	}
	// A TTL of zero still permits the connection that triggered the query.
	expiry := now.Add(time.Duration(ttl) * time.Second)
	if ttl == 0 {
		expiry = now.Add(time.Second)
	}
	if expiry.After(names[name]) {
		names[name] = expiry
	}
}

func (d *PoolDNS) Domain(source, destination string) string {
	host, _, err := net.SplitHostPort(destination)
	if err != nil {
		return ""
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	var domain string
	for name, expiry := range d.names[poolDNSKey{source, ip.String()}] {
		if !now.Before(expiry) {
			continue
		}
		if domain != "" {
			return ""
		}
		domain = name
	}
	return domain
}

package iptables

import (
	"strings"
	"testing"
)

// Строки в обоих форматах: procfs ("ipv4 2 tcp ...") и conntrack -L.
const ctSample = `ipv4     2 tcp      6 431999 ESTABLISHED src=10.4.6.30 dst=158.160.226.85 sport=40000 dport=3333 src=127.0.0.1 dst=10.4.6.30 sport=8443 dport=40000 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 431999 ESTABLISHED src=10.4.6.31 dst=158.160.226.85 sport=40001 dport=3333 src=127.0.0.1 dst=10.4.6.31 sport=8443 dport=40001 [ASSURED] mark=0 zone=0 use=2
tcp      6 431999 ESTABLISHED src=10.4.6.32 dst=1.2.3.4 sport=40002 dport=14444 src=1.2.3.4 dst=10.4.6.32 sport=14444 dport=40002 [ASSURED] mark=0 use=1
tcp      6 118 SYN_SENT src=10.4.6.33 dst=1.2.3.4 sport=40003 dport=14444 [UNREPLIED] src=1.2.3.4 dst=10.4.6.33 sport=14444 dport=40003 mark=0 use=1
ipv4     2 tcp      6 431999 ESTABLISHED src=10.4.6.34 dst=5.6.7.8 sport=40004 dport=3333 src=5.6.7.8 dst=10.4.6.34 sport=3333 dport=40004 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 431999 ESTABLISHED src=192.168.0.10 dst=1.2.3.4 sport=50000 dport=14444 src=1.2.3.4 dst=192.168.0.10 sport=14444 dport=50000 [ASSURED] mark=0 zone=0 use=2
ipv4     2 tcp      6 431999 ESTABLISHED src=10.4.6.30 dst=10.4.6.1 sport=50001 dport=22 src=10.4.6.1 dst=10.4.6.30 sport=22 dport=50001 [ASSURED] mark=0 zone=0 use=2
ipv4     2 udp      17 29 src=10.4.6.30 dst=10.4.6.1 sport=34326 dport=53 src=10.4.6.1 dst=10.4.6.30 sport=53 dport=34326 mark=0 zone=0 use=2
`

func TestParseConntrack(t *testing.T) {
	entries, err := parseConntrack(strings.NewReader(ctSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 7 { // udp отброшен
		t.Fatalf("entries = %d, want 7", len(entries))
	}
	e := entries[0]
	if e.state != "ESTABLISHED" || e.origSrc != "10.4.6.30" || e.origDst != "158.160.226.85" ||
		e.origDport != 3333 || e.replySrc != "127.0.0.1" || e.replySport != 8443 {
		t.Errorf("entry[0] = %+v", e)
	}
	if entries[3].state != "SYN_SENT" || entries[3].replySrc != "1.2.3.4" {
		t.Errorf("entry[3] = %+v", entries[3])
	}
}

func TestBuildPortInfo(t *testing.T) {
	entries, _ := parseConntrack(strings.NewReader(ctSample))
	info := PortInfo{
		ListenPort:     "8443",
		CaptureFilters: []string{"25:9999"},
		RulePorts:      []string{"25:9999"},
	}
	buildPortInfo(&info, entries, parseSubnets([]string{"10.4.6.0/24"}),
		map[string]bool{"10.4.6.1": true})

	if len(info.Captured) != 1 || info.Captured[0].Dest != "158.160.226.85:3333" ||
		info.Captured[0].Connections != 2 || info.Captured[0].SourcesTotal != 2 {
		t.Errorf("captured = %+v", info.Captured)
	}
	// 1.2.3.4:14444 вне фильтра (2 соединения, одно висит в SYN_SENT),
	// 5.6.7.8:3333 в фильтре, но мимо прокси. 192.168.0.10 и ssh к шлюзу — не в счёт.
	if len(info.Bypassed) != 2 {
		t.Fatalf("bypassed = %+v", info.Bypassed)
	}
	b := info.Bypassed[0]
	if b.Dest != "1.2.3.4:14444" || b.InFilter || b.Connections != 2 || b.States["SYN_SENT"] != 1 {
		t.Errorf("bypassed[0] = %+v", b)
	}
	if !info.Bypassed[1].InFilter {
		t.Errorf("bypassed[1] = %+v, want in_filter", info.Bypassed[1])
	}

	// Порты: сначала с обходом (3333 смешанный, 14444), отсортированы.
	if len(info.Ports) != 2 || info.Ports[0].Port != 3333 || info.Ports[0].CapturedConns != 2 ||
		info.Ports[0].BypassedConns != 1 || info.Ports[1].Port != 14444 || info.Ports[1].BypassedConns != 2 {
		t.Errorf("ports = %+v", info.Ports)
	}
	joined := strings.Join(info.Problems, "\n")
	if !strings.Contains(joined, "порт 14444") || !strings.Contains(joined, "capture_ports") {
		t.Errorf("problems = %q", info.Problems)
	}
}

func TestRulePortsAndFilters(t *testing.T) {
	rules := []string{
		"-A MINING_PROXY -s 10.4.6.0/24 -i eth0 -p tcp -m tcp --dport 25:9999 -j DNAT --to-destination 127.0.0.1:8443",
		"-A MINING_PROXY -s 10.4.6.0/24 -i eth0 -p tcp -m tcp --dport 14444 -j DNAT --to-destination 127.0.0.1:8443",
		"-A MINING_PROXY -s 10.4.7.0/24 -i eth1 -p tcp -m tcp --dport 14444 -j DNAT --to-destination 127.0.0.1:8443",
	}
	got := rulePorts(rules)
	if !sameStrings(got, []string{"25:9999", "14444"}) {
		t.Errorf("rulePorts = %v", got)
	}
	if !portInFilters(3333, got) || !portInFilters(14444, got) || portInFilters(25000, got) {
		t.Error("portInFilters mismatch")
	}
	if !portInFilters(25000, []string{"all"}) {
		t.Error("all must match any port")
	}
	if rp := rulePorts([]string{"-A MINING_PROXY -s 10.0.0.0/8 -p tcp -j DNAT --to-destination 127.0.0.1:8443"}); !sameStrings(rp, []string{"all"}) {
		t.Errorf("rulePorts without dport = %v", rp)
	}
}

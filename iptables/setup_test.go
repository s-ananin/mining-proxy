package iptables

import (
	"reflect"
	"strings"
	"testing"
)

// listenPortOf: порт нужен, чтобы построить --to-destination.
func TestListenPortOf(t *testing.T) {
	cases := []struct {
		addr string
		want string
		err  bool
	}{
		{"0.0.0.0:3333", "3333", false},
		{"127.0.0.1:9090", "9090", false},
		{"[::]:3333", "3333", false},
		{"0.0.0.0", "", true},
		{"", "", true},
	}
	for _, c := range cases {
		got, err := listenPortOf(c.addr)
		if c.err {
			if err == nil {
				t.Errorf("listenPortOf(%q) ожидалась ошибка, получено %q", c.addr, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("listenPortOf(%q): неожиданная ошибка %v", c.addr, err)
			continue
		}
		if got != c.want {
			t.Errorf("listenPortOf(%q) = %q, хотели %q", c.addr, got, c.want)
		}
	}
}

// Setup обязан отказываться работать, когда перехватывать нечего.
// Именно этот случай раньше проходил тихо: создавалась пустая цепочка,
// лог писал «setup complete», а трафик ASIC уходил мимо прокси.
func TestSetupFailsWithoutSubnets(t *testing.T) {
	err := Setup(Options{
		ListenAddr: "0.0.0.0:3333",
		Subnets:    nil,
	})
	if err == nil {
		t.Fatal("Setup с пустым allowed_subnets должен вернуть ошибку, а не «успех»")
	}
	if !strings.Contains(err.Error(), "allowed_subnets") {
		t.Errorf("в ошибке ожидалось упоминание allowed_subnets, получено: %v", err)
	}
}

func TestSetupRejectsBadCIDR(t *testing.T) {
	err := Setup(Options{
		ListenAddr: "0.0.0.0:3333",
		Subnets:    []string{"не-подсеть"},
	})
	if err == nil {
		t.Fatal("Setup с некорректной подсетью должен вернуть ошибку")
	}
}

func TestSetupRejectsBadListenAddr(t *testing.T) {
	err := Setup(Options{
		ListenAddr: "0.0.0.0",
		Subnets:    []string{"10.4.6.0/24"},
	})
	if err == nil {
		t.Fatal("Setup без порта в listen_addr должен вернуть ошибку")
	}
}

// Явно заданные nat_ingress_ifaces используются как есть: автоопределение
// по маршруту в тестах недопустимо (зависит от машины).
func TestIngressIfacesForSubnetUsesExplicitConfig(t *testing.T) {
	opts := Options{
		Subnets:       []string{"10.4.6.0/24", "192.168.1.0/24"},
		IngressIfaces: []string{"eth0", "eth0", "eth1"},
	}
	got := ingressIfacesForSubnet("10.4.6.0/24", opts)
	want := []string{"eth0", "eth1"} // дедуплицировано
	if len(got) != len(want) {
		t.Fatalf("ingressIfacesForSubnet = %v, хотели %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ingressIfacesForSubnet[%d] = %q, хотели %q", i, got[i], want[i])
		}
	}
}

// resolveIngressIfaces при явном конфиге не должен ходить в систему.
func TestResolveIngressIfacesExplicit(t *testing.T) {
	got := resolveIngressIfaces(Options{
		Subnets:       []string{"10.4.6.0/24"},
		IngressIfaces: []string{"eth1"},
	})
	if len(got) != 1 || got[0] != "eth1" {
		t.Errorf("resolveIngressIfaces = %v, хотели [eth1]", got)
	}
}

// ifaceSysctlLines не должен дублировать общий параметр: он уже добавлен
// вызывающей стороной, и в persist-файле две одинаковые строки бессмысленны.
func TestIfaceSysctlLinesSkipsAll(t *testing.T) {
	got := ifaceSysctlLines([]string{
		"net.ipv4.conf.all.route_localnet",
		"net.ipv4.conf.eth0.route_localnet",
	})
	if strings.Contains(got, "conf.all.") {
		t.Errorf("в persist-файле не должно быть net.ipv4.conf.all, получено:\n%s", got)
	}
	if !strings.Contains(got, "net.ipv4.conf.eth0.route_localnet = 1") {
		t.Errorf("в persist-файле нет per-device параметра, получено:\n%s", got)
	}
}

// uniqStrings дедуплицирует, триммит и ВЫБРАСЫВАЕТ пустые строки: пустой
// интерфейс не должен превращаться в вариант "-i ''" в правиле iptables.
func TestUniqStrings(t *testing.T) {
	got := uniqStrings([]string{"eth0", " eth1 ", "eth0", "", "eth1", "  "})
	want := []string{"eth0", "eth1"}
	if len(got) != len(want) {
		t.Fatalf("uniqStrings = %v, хотели %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("uniqStrings[%d] = %q, хотели %q", i, got[i], want[i])
		}
	}
}

// Статус без правил и без sysctl обязан честно перечислить проблемы:
// это то, что оператор читает в /status, когда трафик не доходит.
func TestStatusWithoutSubnetsReportsProblem(t *testing.T) {
	st := Status(Options{
		ListenAddr: "0.0.0.0:3333",
		Subnets:    nil,
	})
	if st.Active {
		t.Error("Active должен быть false, когда правил нет")
	}
	joined := strings.Join(st.Problems, "; ")
	if !strings.Contains(joined, "allowed_subnets") {
		t.Errorf("в проблемах ожидалось упоминание allowed_subnets, получено: %s", joined)
	}
}

func TestDportFilters(t *testing.T) {
	cases := []struct {
		opts Options
		want []string
	}{
		{Options{CaptureAllTCP: true, CapturePorts: []string{"25:9999"}, UpstreamPort: "3333"}, []string{"25:9999"}},
		{Options{CaptureAllTCP: true, CapturePorts: []string{"25:9999", "25000", "14444"}}, []string{"25:9999", "25000", "14444"}},
		{Options{CaptureAllTCP: true}, nil},
		{Options{CaptureAllTCP: false, CapturePorts: []string{"3333", "25000"}, UpstreamPort: "3333"}, []string{"3333", "25000"}},
		{Options{CaptureAllTCP: false, UpstreamPort: "3333"}, []string{"3333"}},
	}
	for _, c := range cases {
		if got := dportFilters(c.opts); !reflect.DeepEqual(got, c.want) {
			t.Errorf("dportFilters(%+v) = %q, want %q", c.opts, got, c.want)
		}
	}
}

func TestParseRouteDev(t *testing.T) {
	cases := map[string]string{
		"default via 10.110.255.254 dev eth0 proto dhcp src 10.110.255.1 metric 100\n": "eth0",
		"default via 1.2.3.4 dev ens18\ndefault via 5.6.7.8 dev ens19\n":               "ens18",
		"":                    "",
		"default via 1.2.3.4": "",
	}
	for in, want := range cases {
		if got := parseRouteDev(in); got != want {
			t.Errorf("parseRouteDev(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMissingIfaces(t *testing.T) {
	got := missingIfaces([]string{"eth1", "eth0", "eth1"}, []string{"eth0"})
	if !reflect.DeepEqual(got, []string{"eth1"}) {
		t.Errorf("missingIfaces = %v, want [eth1]", got)
	}
	if got := missingIfaces(nil, []string{"eth0"}); got != nil {
		t.Errorf("missingIfaces(nil) = %v, want nil", got)
	}
}

// MASQUERADE не должен трогать собственные соединения прокси (адрес сервера
// может входить в allowed_subnets) и при известном выходе — ограничиваться им.
func TestMasqueradeArgs(t *testing.T) {
	got := masqueradeArgs("10.0.0.0/9", "eth0")
	want := []string{"-t", "nat", "-A", postChainName, "-s", "10.0.0.0/9", "-o", "eth0",
		"-m", "addrtype", "!", "--src-type", "LOCAL", "-j", "MASQUERADE"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("masqueradeArgs = %q, want %q", got, want)
	}
	if got := masqueradeArgs("10.0.0.0/9", ""); strings.Contains(strings.Join(got, " "), "-o") {
		t.Errorf("без интерфейса не должно быть -o: %q", got)
	}
}

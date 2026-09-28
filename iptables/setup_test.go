package iptables

import (
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

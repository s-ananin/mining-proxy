package config

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeTmp создаёт временный YAML-файл и возвращает путь к нему.
func writeTmp(t *testing.T, content string) string {
	t.Helper()
	dir, err := ioutil.TempDir("", "mpcfg")
	if err != nil {
		t.Fatalf("tempdir: %v", err)
	}
	// Очистка в конце теста (t.Cleanup недоступен в Go 1.13).
	t.Logf("tmp dir: %s", dir)
	path := filepath.Join(dir, "config.yaml")
	if err := ioutil.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestLoadDefaults(t *testing.T) {
	path := writeTmp(t, "upstream_pool: \"bs.poolbinance.com:3333\"\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != "0.0.0.0:8443" {
		t.Errorf("ListenAddr = %q, want 0.0.0.0:8443", cfg.ListenAddr)
	}
	if cfg.MonitorAddr != "127.0.0.1:9090" {
		t.Errorf("MonitorAddr = %q, want 127.0.0.1:9090", cfg.MonitorAddr)
	}
	if cfg.UpstreamPort != "3333" {
		t.Errorf("UpstreamPort = %q, want 3333", cfg.UpstreamPort)
	}
}

func TestLoadSetupWithoutSubnetsFails(t *testing.T) {
	path := writeTmp(t, "setup_iptables: true\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("setup_iptables без allowed_subnets должен падать на старте")
	}
	if !strings.Contains(err.Error(), "allowed_subnets") {
		t.Errorf("в ошибке ожидалось allowed_subnets, получено: %v", err)
	}
}

func TestLoadBadCIDRFails(t *testing.T) {
	path := writeTmp(t, "allowed_subnets: [\"не-подсеть\"]\n")
	if _, err := Load(path); err == nil {
		t.Fatal("некорректный CIDR должен давать ошибку")
	}
}

func TestLoadBadListenFails(t *testing.T) {
	path := writeTmp(t, "listen_addr: \"0.0.0.0\"\n")
	if _, err := Load(path); err == nil {
		t.Fatal("listen_addr без порта должен давать ошибку")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(os.TempDir(), "no-such-mp-config.yaml")); err == nil {
		t.Fatal("отсутствующий файл должен давать ошибку")
	}
}

func TestLoadCommissionInterval(t *testing.T) {
	path := writeTmp(t, "commission_worker: \"me\"\ncommission_interval: \"10m\"\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CommissionEvery != 10*time.Minute {
		t.Errorf("CommissionEvery = %v, want 10m", cfg.CommissionEvery)
	}
}

func TestLoadBadCommissionIntervalFails(t *testing.T) {
	path := writeTmp(t, "commission_worker: \"me\"\ncommission_interval: \"not-a-duration\"\n")
	if _, err := Load(path); err == nil {
		t.Fatal("некорректный commission_interval должен давать ошибку")
	}
}

func TestLoadCommissionIntervalIgnoredWithoutWorker(t *testing.T) {
	path := writeTmp(t, "commission_interval: \"10m\"\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CommissionEvery != 0 {
		t.Errorf("без commission_worker интервал не должен применяться: %v", cfg.CommissionEvery)
	}
}

func TestLoadCommissionSession(t *testing.T) {
	path := writeTmp(t, "commission_worker: \"me\"\ncommission_interval: \"30m\"\ncommission_session: \"20m\"\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CommissionSessionEvery != 20*time.Minute {
		t.Errorf("CommissionSessionEvery = %v, want 20m", cfg.CommissionSessionEvery)
	}
}

func TestLoadCommissionSessionBadDurationFails(t *testing.T) {
	path := writeTmp(t, "commission_worker: \"me\"\ncommission_interval: \"30m\"\ncommission_session: \"nope\"\n")
	if _, err := Load(path); err == nil {
		t.Fatal("некорректный commission_session должен давать ошибку")
	}
}

func TestLoadCommissionSessionWithoutIntervalFails(t *testing.T) {
	path := writeTmp(t, "commission_worker: \"me\"\ncommission_session: \"20m\"\n")
	if _, err := Load(path); err == nil {
		t.Fatal("commission_session без commission_interval должен давать ошибку")
	}
}

func TestLoadCommissionSessionGreaterThanIntervalFails(t *testing.T) {
	path := writeTmp(t, "commission_worker: \"me\"\ncommission_interval: \"10m\"\ncommission_session: \"20m\"\n")
	if _, err := Load(path); err == nil {
		t.Fatal("commission_session больше commission_interval должен давать ошибку")
	}
}

func TestLoadCommissionSessionIgnoredWithoutWorker(t *testing.T) {
	path := writeTmp(t, "commission_session: \"20m\"\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CommissionSessionEvery != 0 {
		t.Errorf("без commission_worker session не должен применяться: %v", cfg.CommissionSessionEvery)
	}
}

func TestLoadFull(t *testing.T) {
	path := writeTmp(t, `
listen_addr: "0.0.0.0:8443"
upstream_pool: "bs.poolbinance.com:3333"
allowed_subnets:
  - "10.4.6.0/24"
setup_iptables: true
capture_all_tcp: false
monitor_addr: "127.0.0.1:9091"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.SetupIPTables || cfg.CaptureAllTCP {
		t.Errorf("flags: setup=%v capture=%v, want true/false", cfg.SetupIPTables, cfg.CaptureAllTCP)
	}
	if cfg.MonitorAddr != "127.0.0.1:9091" {
		t.Errorf("MonitorAddr = %q", cfg.MonitorAddr)
	}
	if cfg.UpstreamPort != "3333" {
		t.Errorf("UpstreamPort = %q, want 3333", cfg.UpstreamPort)
	}
}

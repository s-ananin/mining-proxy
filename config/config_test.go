package config

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
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
	path := writeTmp(t, "listen_addr: \"\"\n")
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

func TestLoadCommissionPools(t *testing.T) {
	cfg, err := Load(writeTmp(t, `
commission_worker: "me"
commission_pools:
  - " btc.viabtc.world "
  - "BTC.VIABTC.WORLD."
  - ""
  - "AntPool"
  - "stratum+tcp://ss.antpool.com:3333"
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"btc.viabtc.world", "AntPool", "stratum+tcp://ss.antpool.com:3333"} // пробелы убраны, дубль по регистру и пустой отброшены
	if got := cfg.CommissionPoolNames(); !reflect.DeepEqual(got, want) {
		t.Errorf("CommissionPools = %q, want %q", got, want)
	}
	for _, p := range cfg.CommissionPools {
		if p.Worker != "me" {
			t.Errorf("pool %q worker = %q, want commission_worker", p.Pool, p.Worker)
		}
	}
	if len(cfg.Deprecated) != 1 || !strings.Contains(cfg.Deprecated[0], "stratum+tcp://") {
		t.Errorf("expected warning for URL, got %q", cfg.Deprecated)
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
allowed_subnets:
  - "10.4.6.0/24"
setup_iptables: true
capture_all_tcp: false
capture_ports: [3333]
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
	if got := cfg.CapturePorts(); !reflect.DeepEqual(got, []string{"3333"}) {
		t.Errorf("CapturePorts = %q, want [3333]", got)
	}
}

// Убранные из конфига ключи не ломают старт, а попадают в предупреждения.
func TestLoadDeprecatedKeys(t *testing.T) {
	cfg, err := Load(writeTmp(t, `
upstream_pool: ["btc.viabtc.io:3333"]
upstream_ssl: true
nat_masquerade: false
commission_worker_rotate: true
commission_suggest_difficulty: false
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Deprecated) != 5 {
		t.Fatalf("Deprecated = %q, want 5 entries", cfg.Deprecated)
	}
	cfg, err = Load(writeTmp(t, "listen_addr: \"0.0.0.0:8443\"\n"))
	if err != nil || len(cfg.Deprecated) != 0 {
		t.Fatalf("clean config: %v %q", err, cfg.Deprecated)
	}
}

func TestLoadCommissionBTCOnly(t *testing.T) {
	cfg, err := Load(writeTmp(t, "commission_worker: fee\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.BTCOnly() {
		t.Fatal("commission_btc_only по умолчанию должен быть true")
	}
	cfg, err = Load(writeTmp(t, "commission_worker: fee\ncommission_btc_only: false\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BTCOnly() {
		t.Fatal("commission_btc_only: false должен выключать фильтр")
	}
}

func TestLoadCapturePortsDefaults(t *testing.T) {
	cfg, err := Load(writeTmp(t, "listen_addr: \"0.0.0.0:8443\"\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.CaptureAllTCP {
		t.Errorf("capture_all_tcp по умолчанию должен быть true")
	}
	if got := cfg.CapturePorts(); !reflect.DeepEqual(got, []string{"25:9999"}) {
		t.Errorf("CapturePorts = %q, want [25:9999]", got)
	}
	if cfg.StdoutTruncateEvery != 48*time.Hour {
		t.Errorf("StdoutTruncateEvery = %v, want 48h", cfg.StdoutTruncateEvery)
	}
}

func TestLoadCapturePortsSingle(t *testing.T) {
	cfg, err := Load(writeTmp(t, "capture_port_from: 9999\ncapture_port_to: 9999\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.CapturePorts(); !reflect.DeepEqual(got, []string{"9999"}) {
		t.Errorf("CapturePorts = %q, want [9999]", got)
	}
}

func TestLoadCapturePortsInvalid(t *testing.T) {
	cases := []string{
		"capture_port_from: 5000\ncapture_port_to: 100\n",
		"capture_port_from: 25\ncapture_port_to: 70000\n",
		"capture_port_from: -1\n",
		"capture_ports: [0]\n",
		"capture_ports: [70000]\n",
		"stdout_truncate_interval: abc\n",
		"stdout_truncate_interval: 10s\n",
	}
	for _, c := range cases {
		if _, err := Load(writeTmp(t, c)); err == nil {
			t.Errorf("ожидалась ошибка для %q", c)
		}
	}
}

func TestLoadCapturePortsExtra(t *testing.T) {
	// 3333 внутри диапазона — пропускается; 25000 повторён — один раз.
	cfg, err := Load(writeTmp(t, "capture_ports: [25000, 3333, 14444, 25000]\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"25:9999", "25000", "14444"}
	if got := cfg.CapturePorts(); !reflect.DeepEqual(got, want) {
		t.Errorf("CapturePorts = %q, want %q", got, want)
	}

	// capture_all_tcp: false — только capture_ports, без диапазона.
	cfg, err = Load(writeTmp(t, "capture_all_tcp: false\ncapture_ports: [3333, 25000]\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want = []string{"3333", "25000"}
	if got := cfg.CapturePorts(); !reflect.DeepEqual(got, want) {
		t.Errorf("CapturePorts = %q, want %q", got, want)
	}
}

func TestLoadStdoutTruncateInterval(t *testing.T) {
	cfg, err := Load(writeTmp(t, "stdout_truncate_interval: \"0\"\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.StdoutTruncateEvery != 0 {
		t.Errorf("StdoutTruncateEvery = %v, want 0", cfg.StdoutTruncateEvery)
	}
	cfg, err = Load(writeTmp(t, "stdout_truncate_interval: 24h\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.StdoutTruncateEvery != 24*time.Hour {
		t.Errorf("StdoutTruncateEvery = %v, want 24h", cfg.StdoutTruncateEvery)
	}
}

// capture_all_tcp: false без capture_ports перехватывал бы весь TCP подсетей.
func TestLoadCaptureAllFalseRequiresPorts(t *testing.T) {
	_, err := Load(writeTmp(t, "setup_iptables: true\nallowed_subnets: [\"10.0.0.0/9\"]\ncapture_all_tcp: false\n"))
	if err == nil {
		t.Fatal("capture_all_tcp: false без capture_ports должен падать")
	}
}

func TestLoadCommissionPoolWorkers(t *testing.T) {
	cfg, err := Load(writeTmp(t, `
commission_pools:
  - pool: "viabtc"
    worker: "anton425"
  - pool: "emcd"
    worker: " emcd.generated01 "
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.CommissionEnabled() || cfg.CommissionPercent != 2 {
		t.Fatalf("commission not enabled with defaults: %+v", cfg)
	}
	want := []CommissionPool{{"viabtc", "anton425"}, {"emcd", "emcd.generated01"}}
	if !reflect.DeepEqual(cfg.CommissionPools, want) {
		t.Errorf("CommissionPools = %+v, want %+v", cfg.CommissionPools, want)
	}
}

func TestLoadCommissionPoolWorkersMixed(t *testing.T) {
	cfg, err := Load(writeTmp(t, `
commission_worker: "default"
commission_pools:
  - "viabtc"
  - pool: "emcd"
    worker: "emcd.gen"
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []CommissionPool{{"viabtc", "default"}, {"emcd", "emcd.gen"}}
	if !reflect.DeepEqual(cfg.CommissionPools, want) {
		t.Errorf("CommissionPools = %+v, want %+v", cfg.CommissionPools, want)
	}
}

func TestLoadCommissionPoolWithoutWorkerFails(t *testing.T) {
	_, err := Load(writeTmp(t, `
commission_pools:
  - "viabtc"
  - pool: "emcd"
    worker: "emcd.gen"
`))
	if err == nil || !strings.Contains(err.Error(), "viabtc") {
		t.Fatalf("expected error for pool without worker, got %v", err)
	}
}

func TestLoadCommissionDisabledWithoutWorkers(t *testing.T) {
	cfg, err := Load(writeTmp(t, "commission_pools: [\"viabtc\"]\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CommissionEnabled() {
		t.Fatal("commission enabled without any worker")
	}
}

func TestLoadCommissionPoolWorkerWithSpaceFails(t *testing.T) {
	_, err := Load(writeTmp(t, "commission_pools:\n  - pool: emcd\n    worker: \"a b\"\n"))
	if err == nil {
		t.Fatal("worker with space accepted")
	}
}

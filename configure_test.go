package main

import (
	"bufio"
	"io/ioutil"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"mining-proxy/config"
)

// Мастер спрашивает воркера для каждого пула из белого списка; результат
// проходит config.Load и сохраняет привязку пул → воркер.
func TestConfigureCommissionWorkerPerPool(t *testing.T) {
	in := strings.Join([]string{
		"viabtc, emcd", // пулы
		"",             // viabtc — оставить прежнего воркера
		"emcd.gen01",   // emcd — новый воркер
	}, "\n") + "\n"
	p := &prompter{in: bufio.NewReader(strings.NewReader(in)), out: ioutil.Discard}
	c := config.Config{
		ListenAddr:       "0.0.0.0:8443",
		MonitorAddr:      "127.0.0.1:9090",
		CapturePortFrom:  25,
		CapturePortTo:    9999,
		CommissionWorker: "anton425",
		CommissionPools:  []config.CommissionPool{{Pool: "ViaBTC"}},
	}
	c, err := askCommissionWorkers(p, c)
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	path := filepath.Join(tempDir(t), "config.yaml") // tempDir: logtrunc_test.go
	if err := writeConfig(path, c); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := []config.CommissionPool{{Pool: "viabtc", Worker: "anton425"}, {Pool: "emcd", Worker: "emcd.gen01"}}
	if !reflect.DeepEqual(cfg.CommissionPools, want) || !cfg.CommissionEnabled() {
		t.Fatalf("pools = %+v enabled=%v", cfg.CommissionPools, cfg.CommissionEnabled())
	}
}

// Пустой список пулов — один воркер на любой пул.
func TestConfigureCommissionAnyPool(t *testing.T) {
	p := &prompter{in: bufio.NewReader(strings.NewReader("-\nfee.w\n")), out: ioutil.Discard}
	c := config.Config{
		ListenAddr:      "0.0.0.0:8443",
		MonitorAddr:     "127.0.0.1:9090",
		CapturePortFrom: 25,
		CapturePortTo:   9999,
		CommissionPools: []config.CommissionPool{{Pool: "viabtc", Worker: "x"}},
	}
	c, err := askCommissionWorkers(p, c)
	if err != nil {
		t.Fatalf("ask: %v", err)
	}
	path := filepath.Join(tempDir(t), "config.yaml") // tempDir: logtrunc_test.go
	if err := writeConfig(path, c); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.CommissionWorker != "fee.w" || len(cfg.CommissionPools) != 0 {
		t.Fatalf("worker=%q pools=%+v", cfg.CommissionWorker, cfg.CommissionPools)
	}
}

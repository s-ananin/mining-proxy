package config

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeConfig создаёт временный YAML-файл с переданным содержимым и
// возвращает путь и функцию очистки (в Go 1.13 ещё нет t.Cleanup).
func writeConfig(t *testing.T, content string) (string, func()) {
	t.Helper()
	dir, err := ioutil.TempDir("", "mp-config")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	cleanup := func() { os.RemoveAll(dir) }
	path := filepath.Join(dir, "config.yaml")
	if err := ioutil.WriteFile(path, []byte(content), 0644); err != nil {
		cleanup()
		t.Fatalf("write config: %v", err)
	}
	return path, cleanup
}

const baseConfig = `
upstream_pool: "127.0.0.1:3333"
steal_to:
  pool: "127.0.0.1:3334"
  worker: "my_worker"
`

// TestLoadStealRules проверяет разбор секции steal_rules: необязательный
// worker (пусто = весь пул) и сохранение порядка правил.
func TestLoadStealRules(t *testing.T) {
	path, cleanup := writeConfig(t, baseConfig+`
steal_rules:
  - pool: "1.2.3.4:3333"
  - pool: "5.6.7.8:3333"
    worker: "вася3344"
`)
	defer cleanup()
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.StealRules) != 2 {
		t.Fatalf("StealRules len = %d, want 2", len(cfg.StealRules))
	}
	if cfg.StealRules[0].Pool != "1.2.3.4:3333" || cfg.StealRules[0].Worker != "" {
		t.Errorf("rule[0] = %+v, want pool-only", cfg.StealRules[0])
	}
	if cfg.StealRules[1].Pool != "5.6.7.8:3333" || cfg.StealRules[1].Worker != "вася3344" {
		t.Errorf("rule[1] = %+v, want pool+worker", cfg.StealRules[1])
	}
}

// TestLoadNoStealRules проверяет обратную совместимость: без секции правил
// конфиг грузится, а срез правил пуст (режим «кусать у всех»).
func TestLoadNoStealRules(t *testing.T) {
	path, cleanup := writeConfig(t, baseConfig)
	defer cleanup()
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.StealRules) != 0 {
		t.Fatalf("StealRules len = %d, want 0", len(cfg.StealRules))
	}
}

// TestLoadPassThrough проверяет режим простого пропуска: upstream_pool пуст —
// конфиг грузится БЕЗ обязательных steal_to, кража выключена (pass-through).
func TestLoadPassThrough(t *testing.T) {
	path, cleanup := writeConfig(t, `
listen_addr: "0.0.0.0:8443"
upstream_pool: ""
allowed_subnets:
  - "192.168.1.0/24"
`)
	defer cleanup()
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.PassThrough() {
		t.Errorf("expected pass-through mode, got %+v", cfg)
	}
	if cfg.UpstreamPort != "" {
		t.Errorf("UpstreamPort = %q, want empty in pass-through", cfg.UpstreamPort)
	}
}

// TestLoadPassThroughEmptyStealTo проверяет: upstream_pool задан, а steal_to
// пуст — конфиг грузится БЕЗ ошибки и кража выключена (pass-through).
func TestLoadPassThroughEmptyStealTo(t *testing.T) {
	path, cleanup := writeConfig(t, `
listen_addr: "0.0.0.0:8443"
upstream_pool: "127.0.0.1:3333"
`)
	defer cleanup()
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.PassThrough() {
		t.Errorf("expected pass-through (empty steal_to), got %+v", cfg)
	}
}

// TestLoadStealRulesInvalid проверяет валидацию правил: пустой pool и
// некорректный host:port должны приводить к ошибке.
func TestLoadStealRulesInvalid(t *testing.T) {
	cases := []struct {
		name    string
		section string
		wantErr string
	}{
		{
			name:    "empty pool",
			section: "steal_rules:\n  - worker: \"вася3344\"\n",
			wantErr: "steal_rules[0].pool is required",
		},
		{
			name:    "bad host:port",
			section: "steal_rules:\n  - pool: \"no-port\"\n",
			wantErr: "steal_rules[0].pool",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path, cleanup := writeConfig(t, baseConfig+tc.section)
			defer cleanup()
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %q, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// TestLoadSetupIPTablesWithoutSubnets — главный защитный тест этой правки.
//
// Такая конфигурация (NAT включён, но перехватывать нечего) раньше
// проходила загрузку, процесс стартовал, в лог уходило «setup complete»
// при нуле правил DNAT, а трафик ASIC уходил мимо прокси прямо в пул.
// Теперь это ошибка с внятным текстом.
func TestLoadSetupIPTablesWithoutSubnets(t *testing.T) {
	path, cleanup := writeConfig(t, baseConfig+`
setup_iptables: true
allowed_subnets: []
`)
	defer cleanup()

	_, err := Load(path)
	if err == nil {
		t.Fatal("ожидалась ошибка: setup_iptables=true при пустом allowed_subnets")
	}
	if !strings.Contains(err.Error(), "allowed_subnets") {
		t.Errorf("в ошибке ожидалось упоминание allowed_subnets, получено: %v", err)
	}
}

// Обратный случай: NAT выключен, подсети пусты — конфиг валиден (локальная
// разработка и тесты без root). Ошибка тут была бы ложной.
func TestLoadNoIPTablesWithoutSubnetsOK(t *testing.T) {
	path, cleanup := writeConfig(t, baseConfig+`
setup_iptables: false
allowed_subnets: []
`)
	defer cleanup()

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("конфиг без NAT и без подсетей должен грузиться, получено: %v", err)
	}
	if cfg.SetupIPTables {
		t.Error("SetupIPTables должен быть false")
	}
}

func TestLoadNATIngressIfaces(t *testing.T) {
	path, cleanup := writeConfig(t, baseConfig+`
setup_iptables: true
allowed_subnets: ["10.4.6.0/24"]
nat_ingress_ifaces: ["eth0", "eth1"]
`)
	defer cleanup()

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.NATIngressIfaces) != 2 ||
		cfg.NATIngressIfaces[0] != "eth0" || cfg.NATIngressIfaces[1] != "eth1" {
		t.Errorf("NATIngressIfaces = %v, хотели [eth0 eth1]", cfg.NATIngressIfaces)
	}
}

// TestExampleConfigLoads защищает эталон config.example.yaml от типичных
// правок, которые ломают его незаметно для человека:
//
//   - дублирующийся YAML-ключ (yaml.v3 отвергает такой файл целиком);
//   - потерянное или переименованное поле;
//   - значение, не проходящее валидацию Config.Load.
//
// Раньше эталон правился руками и его никто не проверял: сломанный файл
// обнаруживался только при копировании в /etc на целевой машине.
func TestExampleConfigLoads(t *testing.T) {
	path := filepath.Join("..", "config.example.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Skipf("config.example.yaml недоступен: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("эталон config.example.yaml не грузится: %v", err)
	}
	if len(cfg.AllowedSubnets) == 0 {
		t.Error("в эталоне должен быть непустой allowed_subnets, иначе NAT не работает")
	}
	if cfg.ListenAddr == "" {
		t.Error("в эталоне должен быть listen_addr")
	}
	if cfg.MonitorAddr == "" {
		t.Error("Load() подставляет дефолт мониторинга — эталон его не переопределяет пустым")
	}
}

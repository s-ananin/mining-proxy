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

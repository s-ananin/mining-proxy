// Пакет config — чтение и валидация YAML-конфигурации mining-proxy.
//
// Прокси мониторинга шар не меняет трафик: он перехватывает TCP майнеров
// (iptables DNAT), прозрачно проксирует в реальный пул и считает шары
// (mining.submit → accepted/rejected). Конфиг описывает только то, что нужно
// для этой работы: адреса, подсети для перехвата и адрес HTTP-мониторинга.
package config

import (
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config — параметры приложения, читаются из YAML-файла.
type Config struct {
	// ListenAddr адрес и порт прокси, сюда приходит трафик после DNAT.
	// Дефолт "0.0.0.0:8443".
	ListenAddr string `yaml:"listen_addr"`

	// UpstreamPool реальный пул (host:port), если SO_ORIGINAL_DST недоступен:
	// прямое подключение к прокси мимо iptables (локальный тест) или
	// fallback. Пусто = работаем только в прозрачном режиме.
	UpstreamPool string `yaml:"upstream_pool"`

	// UpstreamSSL TLS при подключении к UpstreamPool (fallback-соединение).
	// В прозрачном режиме TLS не терминируется никогда: клиент сам держит
	// TLS-сессию с пулом сквозь байтовую трубу.
	UpstreamSSL bool `yaml:"upstream_ssl"`

	// AllowedSubnets подсети майнеров (CIDR), трафик которых перехватывается.
	// Обязательно, если setup_iptables: true.
	AllowedSubnets []string `yaml:"allowed_subnets"`

	// SetupIPTables автоматически настроить DNAT при старте (нужен root).
	SetupIPTables bool `yaml:"setup_iptables"`

	// NATIngressIfaces входящие интерфейсы вручную; пусто = автоопределение
	// по маршруту к allowed_subnets.
	NATIngressIfaces []string `yaml:"nat_ingress_ifaces"`

	// CaptureAllTCP перехватывать весь TCP подсетей (воронка), а не только
	// порт UpstreamPool. Нужно, если майнеры ходят на разные порты пулов.
	CaptureAllTCP bool `yaml:"capture_all_tcp"`

	// MonitorAddr адрес HTTP-мониторинга (/status, /health).
	// Дефолт "127.0.0.1:9090"; наружу не выставляйте без firewall.
	MonitorAddr string `yaml:"monitor_addr"`

	// CommissionWorker воркер, на который уходит комиссия. Пусто = комиссия
	// выключена. Шары комиссии НЕ идут в реальный пул майнера: они забираются
	// в выделенное соединение под этим воркером (см. proxy/commission.go).
	CommissionWorker string `yaml:"commission_worker"`

	// CommissionPercent процент принятых за сутки шар, изымаемый в комиссию.
	// Дефолт 2. Применяется только если CommissionWorker задан.
	CommissionPercent float64 `yaml:"commission_percent"`

	// CommissionIteration сколько итераций изъятия за сутки (на случайные
	// моменты). Дефолт 40. Применяется только если CommissionWorker задан и
	// CommissionInterval пуст.
	CommissionIteration int `yaml:"commission_iteration"`

	// CommissionInterval фиксированный интервал изъятия (Go-длительность,
	// например "10m"): изъятие идёт ровными порциями каждые N, пропорционально
	// принятым за интервал шарам, суммарно не более CommissionPercent% в сутки.
	// Пусто — случайные итерации CommissionIteration раз в сутки.
	CommissionInterval string `yaml:"commission_interval"`

	// CommissionEvery распарсенный CommissionInterval — производное поле
	// (не читается из файла).
	CommissionEvery time.Duration `yaml:"-"`

	// UpstreamPort порт UpstreamPool — производное поле для DNAT-фильтра
	// (--dport). Тег yaml:"-" — не читается из файла.
	UpstreamPort string `yaml:"-"`
}

// Load читает YAML-файл, применяет дефолты и валидирует поля.
func Load(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0:8443"
	}
	if cfg.MonitorAddr == "" {
		cfg.MonitorAddr = "127.0.0.1:9090"
	}

	if err := validHostPort(cfg.ListenAddr, "listen_addr"); err != nil {
		return nil, err
	}
	if err := validHostPort(cfg.MonitorAddr, "monitor_addr"); err != nil {
		return nil, err
	}

	for _, sn := range cfg.AllowedSubnets {
		if _, _, err := net.ParseCIDR(sn); err != nil {
			return nil, fmt.Errorf("invalid CIDR in allowed_subnets %q: %w", sn, err)
		}
	}

	// Пустые подсети при включённом setup_iptables — гарантированный провал:
	// старая логика молча создавала пустую цепочку, оператор видел «NAT
	// настроен», а трафик шёл мимо прокси. Отказываемся на старте.
	if cfg.SetupIPTables && len(cfg.AllowedSubnets) == 0 {
		return nil, fmt.Errorf("setup_iptables: true, но allowed_subnets пуст — перенаправлять нечего; " +
			"укажите подсети майнеров (например [\"10.4.6.0/24\"]) или отключите setup_iptables")
	}

	for _, ifc := range cfg.NATIngressIfaces {
		if strings.TrimSpace(ifc) == "" {
			return nil, fmt.Errorf("invalid nat_ingress_ifaces: пустое имя интерфейса")
		}
	}

	if cfg.UpstreamPool != "" {
		if err := validHostPort(cfg.UpstreamPool, "upstream_pool"); err != nil {
			return nil, err
		}
		_, port, err := net.SplitHostPort(cfg.UpstreamPool)
		if err != nil {
			return nil, fmt.Errorf("upstream_pool: %w", err)
		}
		cfg.UpstreamPort = port
	}

	// Комиссия: дефолты и валидация только когда воркер задан. Пусто —
	// комиссия полностью выключена, остальные поля не читаются.
	if cfg.CommissionWorker != "" {
		if cfg.CommissionPercent == 0 {
			cfg.CommissionPercent = 2 // дефолт по ТЗ
		}
		if cfg.CommissionPercent < 0 || cfg.CommissionPercent > 100 {
			return nil, fmt.Errorf("commission_percent %v вне диапазона (0..100)", cfg.CommissionPercent)
		}
		if cfg.CommissionIteration <= 0 {
			cfg.CommissionIteration = 40 // дефолт по ТЗ
		}
		// Фиксированный интервал (если задан) имеет приоритет над
		// commission_iteration: число изъятий выводится из интервала.
		if cfg.CommissionInterval != "" {
			d, err := time.ParseDuration(cfg.CommissionInterval)
			if err != nil {
				return nil, fmt.Errorf("invalid commission_interval %q: %w", cfg.CommissionInterval, err)
			}
			if d <= 0 || d > 24*time.Hour {
				return nil, fmt.Errorf("commission_interval %v вне диапазона (0..24h)", d)
			}
			cfg.CommissionEvery = d
		}
	}

	return &cfg, nil
}

// validHostPort проверяет формат host:port и диапазон порта 1–65535.
func validHostPort(addr, field string) error {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid %s %q: %w", field, addr, err)
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid port in %s %q: %w", field, addr, err)
	}
	if p < 1 || p > 65535 {
		return fmt.Errorf("port out of range in %s %q: %d", field, addr, p)
	}
	return nil
}

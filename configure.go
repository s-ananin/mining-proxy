// configure.go — интерактивный мастер конфигурации: `mining-proxy configure`.
//
// Спрашивает основные параметры (адреса, подсети, перехват, комиссию),
// подставляя в качестве ответов по умолчанию значения из существующего
// конфига (или дефолты config.example.yaml, если файла нет). Результат
// проверяется тем же config.Load, что и при старте прокси, и только после
// этого атомарно записывается на место; прежний файл сохраняется в *.bak.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"

	"mining-proxy/config"
)

// errAborted — ввод закончился (Ctrl+D) до завершения мастера.
var errAborted = errors.New("ввод прерван, конфиг не изменён")

// clearToken — ввод, очищающий необязательное значение.
const clearToken = "-"

// runConfigure — точка входа подкоманды configure. Возвращает код выхода.
func runConfigure(args []string) int {
	fs := flag.NewFlagSet("configure", flag.ContinueOnError)
	path := fs.String("config", "/etc/mining-proxy/config.yaml", "куда записать конфиг")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	p := &prompter{in: bufio.NewReader(os.Stdin), out: os.Stdout}
	for {
		cfg, err := askConfig(p, *path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "configure: %v\n", err)
			return 1
		}
		err = writeConfig(*path, cfg)
		if err == nil {
			fmt.Fprintf(os.Stdout, "\nКонфиг записан: %s\n", *path)
			return 0
		}
		fmt.Fprintf(os.Stderr, "\nКонфиг не прошёл проверку: %v\n", err)
		again, aerr := p.askBool("Заполнить заново?", true)
		if aerr != nil || !again {
			return 1
		}
	}
}

// loadDefaults читает существующий конфиг без валидации (чтобы мастер
// открывался и для битого файла) и дополняет пустые поля дефолтами.
func loadDefaults(path string) (config.Config, bool) {
	var c config.Config
	exists := false
	if data, err := ioutil.ReadFile(path); err == nil {
		exists = true
		if err := yaml.Unmarshal(data, &c); err != nil {
			fmt.Fprintf(os.Stderr, "предупреждение: %s не разобран (%v), берутся дефолты\n", path, err)
			c = config.Config{}
		}
	}
	if c.ListenAddr == "" {
		c.ListenAddr = "0.0.0.0:8443"
	}
	if c.MonitorAddr == "" {
		c.MonitorAddr = "127.0.0.1:9090"
	}
	if !exists {
		c.SetupIPTables = true
		c.AllowedSubnets = []string{"10.4.6.0/24"}
	}
	if c.CapturePortFrom == 0 {
		c.CapturePortFrom = 25
	}
	if c.CapturePortTo == 0 {
		c.CapturePortTo = 9999
	}
	if c.CommissionPercent == 0 {
		c.CommissionPercent = 2
	}
	if c.CommissionIteration <= 0 {
		c.CommissionIteration = 40
	}
	return c, exists
}

// askConfig проводит пользователя по всем вопросам.
func askConfig(p *prompter, path string) (config.Config, error) {
	c, exists := loadDefaults(path)
	if exists {
		fmt.Fprintf(p.out, "Редактирование %s. Enter — оставить значение в [скобках], %q — очистить.\n\n", path, clearToken)
	} else {
		fmt.Fprintf(p.out, "Первичная настройка %s. Enter — значение в [скобках], %q — очистить.\n\n", path, clearToken)
	}

	var err error
	fmt.Fprintln(p.out, "--- Сеть ---")
	if c.ListenAddr, err = p.askString("Адрес прокси (listen_addr)", c.ListenAddr, true, checkHostPort); err != nil {
		return c, err
	}
	if c.UpstreamPool, err = p.askString("Fallback-пул host:port (upstream_pool, можно пусто)", c.UpstreamPool, false, checkHostPort); err != nil {
		return c, err
	}
	if c.MonitorAddr, err = p.askString("Адрес мониторинга /status (monitor_addr)", c.MonitorAddr, true, checkHostPort); err != nil {
		return c, err
	}

	fmt.Fprintln(p.out, "\n--- Перехват (iptables) ---")
	if c.SetupIPTables, err = p.askBool("Настраивать iptables DNAT автоматически (setup_iptables)?", c.SetupIPTables); err != nil {
		return c, err
	}
	if c.AllowedSubnets, err = p.askList("Подсети майнеров через запятую (allowed_subnets)", c.AllowedSubnets, c.SetupIPTables, checkCIDR); err != nil {
		return c, err
	}
	if c.SetupIPTables {
		if c.NATIngressIfaces, err = p.askList("Входящие интерфейсы через запятую (пусто — автоопределение)", c.NATIngressIfaces, false, nil); err != nil {
			return c, err
		}
		captureAll := c.CaptureAllTCPRaw == nil || *c.CaptureAllTCPRaw
		if captureAll, err = p.askBool("Перехватывать диапазон портов, а не только порт upstream_pool (capture_all_tcp)?", captureAll); err != nil {
			return c, err
		}
		c.CaptureAllTCPRaw = &captureAll
		if captureAll {
			for {
				if c.CapturePortFrom, err = p.askInt("Начало диапазона портов (capture_port_from)", c.CapturePortFrom, 1, 65535); err != nil {
					return c, err
				}
				if c.CapturePortTo, err = p.askInt("Конец диапазона портов (capture_port_to)", c.CapturePortTo, 1, 65535); err != nil {
					return c, err
				}
				if c.CapturePortFrom <= c.CapturePortTo {
					break
				}
				fmt.Fprintln(p.out, "  ! начало диапазона больше конца")
			}
		}
		if c.CapturePortsExtra, err = p.askPorts("Доп. порты через запятую (capture_ports, можно пусто)", c.CapturePortsExtra); err != nil {
			return c, err
		}
	}

	fmt.Fprintln(p.out, "\n--- Комиссия ---")
	if c.CommissionWorker, err = p.askString("Воркер комиссии (commission_worker, пусто — выключена)", c.CommissionWorker, false, checkNoSpace); err != nil {
		return c, err
	}
	if c.CommissionWorker == "" {
		c.CommissionWorkerRotate = false
		c.CommissionSuggestDifficulty = false
		return c, nil
	}
	if c.CommissionPercent, err = p.askFloat("Процент комиссии (commission_percent)", c.CommissionPercent, 0, 100); err != nil {
		return c, err
	}
	if c.CommissionInterval, err = p.askString("Интервал изъятия, напр. 5m (commission_interval, пусто — случайные итерации)", c.CommissionInterval, false, checkDuration); err != nil {
		return c, err
	}
	if c.CommissionInterval == "" {
		c.CommissionSession = ""
		if c.CommissionIteration, err = p.askInt("Итераций изъятия в сутки (commission_iteration)", c.CommissionIteration, 1, 100000); err != nil {
			return c, err
		}
	} else {
		every, _ := time.ParseDuration(c.CommissionInterval)
		checkSession := func(s string) error {
			if err := checkDuration(s); err != nil {
				return err
			}
			if d, _ := time.ParseDuration(s); d > every {
				return fmt.Errorf("окно больше интервала %s", c.CommissionInterval)
			}
			return nil
		}
		if c.CommissionSession, err = p.askString("Окно изъятия внутри интервала (commission_session, можно пусто)", c.CommissionSession, false, checkSession); err != nil {
			return c, err
		}
	}
	btcOnly := c.CommissionBTCOnly == nil || *c.CommissionBTCOnly
	if btcOnly, err = p.askBool("Комиссия только с BTC (commission_btc_only)?", btcOnly); err != nil {
		return c, err
	}
	c.CommissionBTCOnly = &btcOnly
	if c.CommissionSuggestDifficulty, err = p.askBool("Просить у пула сложность (commission_suggest_difficulty)?", c.CommissionSuggestDifficulty); err != nil {
		return c, err
	}
	if c.CommissionWorkerRotate, err = p.askBool("Ротация имени воркера комиссии (commission_worker_rotate)?", c.CommissionWorkerRotate); err != nil {
		return c, err
	}
	return c, nil
}

// writeConfig рендерит конфиг, проверяет его config.Load и атомарно
// заменяет файл. Прежняя версия сохраняется в path+".bak".
func writeConfig(path string, c config.Config) error {
	var buf bytes.Buffer
	if err := configTemplate.Execute(&buf, c); err != nil {
		return fmt.Errorf("render: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := ioutil.TempFile(dir, ".config-*.yaml")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op после успешного Rename
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0640); err != nil {
		return err
	}
	if _, err := config.Load(tmpName); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		if err := copyFile(path, path+".bak"); err != nil {
			return fmt.Errorf("backup: %w", err)
		}
	}
	return os.Rename(tmpName, path)
}

func copyFile(src, dst string) error {
	data, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(dst, data, 0640)
}

// --- Проверки ввода ---

func checkHostPort(s string) error {
	_, port, err := net.SplitHostPort(s)
	if err != nil {
		return err
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("порт %q вне 1..65535", port)
	}
	return nil
}

func checkCIDR(s string) error {
	_, _, err := net.ParseCIDR(s)
	return err
}

func checkDuration(s string) error {
	d, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	if d <= 0 || d > 24*time.Hour {
		return fmt.Errorf("нужно от 1s до 24h")
	}
	return nil
}

func checkNoSpace(s string) error {
	if strings.ContainsAny(s, " \t\"'") {
		return fmt.Errorf("без пробелов и кавычек")
	}
	return nil
}

// --- Ввод ---

type prompter struct {
	in  *bufio.Reader
	out io.Writer
}

// line печатает вопрос и читает строку без пробелов по краям.
func (p *prompter) line(question, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(p.out, "%s [%s]: ", question, def)
	} else {
		fmt.Fprintf(p.out, "%s: ", question)
	}
	s, err := p.in.ReadString('\n')
	if err != nil && (err != io.EOF || s == "") {
		fmt.Fprintln(p.out)
		return "", errAborted
	}
	return strings.TrimSpace(s), nil
}

func (p *prompter) askString(q, def string, required bool, check func(string) error) (string, error) {
	for {
		s, err := p.line(q, def)
		if err != nil {
			return "", err
		}
		switch {
		case s == "":
			s = def
		case s == clearToken:
			s = ""
		}
		if s == "" {
			if required {
				fmt.Fprintln(p.out, "  ! значение обязательно")
				continue
			}
			return "", nil
		}
		if check != nil {
			if err := check(s); err != nil {
				fmt.Fprintf(p.out, "  ! %v\n", err)
				continue
			}
		}
		return s, nil
	}
}

func (p *prompter) askList(q string, def []string, required bool, check func(string) error) ([]string, error) {
	for {
		s, err := p.line(q, strings.Join(def, ", "))
		if err != nil {
			return nil, err
		}
		var items []string
		switch s {
		case "":
			items = def
		case clearToken:
		default:
			for _, f := range strings.Split(s, ",") {
				if f = strings.TrimSpace(f); f != "" {
					items = append(items, f)
				}
			}
		}
		if required && len(items) == 0 {
			fmt.Fprintln(p.out, "  ! нужен хотя бы один элемент")
			continue
		}
		bad := false
		for _, it := range items {
			if check != nil {
				if err := check(it); err != nil {
					fmt.Fprintf(p.out, "  ! %q: %v\n", it, err)
					bad = true
				}
			}
		}
		if !bad {
			return items, nil
		}
	}
}

func (p *prompter) askPorts(q string, def []int) ([]int, error) {
	defStr := make([]string, len(def))
	for i, v := range def {
		defStr[i] = strconv.Itoa(v)
	}
	checkPort := func(s string) error {
		v, err := strconv.Atoi(s)
		if err != nil || v < 1 || v > 65535 {
			return fmt.Errorf("порт вне 1..65535")
		}
		return nil
	}
	items, err := p.askList(q, defStr, false, checkPort)
	if err != nil {
		return nil, err
	}
	out := make([]int, 0, len(items))
	for _, it := range items {
		v, _ := strconv.Atoi(it)
		out = append(out, v)
	}
	return out, nil
}

func (p *prompter) askBool(q string, def bool) (bool, error) {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	for {
		s, err := p.line(q+" ("+hint+")", "")
		if err != nil {
			return false, err
		}
		switch strings.ToLower(s) {
		case "":
			return def, nil
		case "y", "yes", "д", "да":
			return true, nil
		case "n", "no", "н", "нет":
			return false, nil
		}
		fmt.Fprintln(p.out, "  ! ответьте y или n")
	}
}

func (p *prompter) askInt(q string, def, min, max int) (int, error) {
	for {
		s, err := p.line(q, strconv.Itoa(def))
		if err != nil {
			return 0, err
		}
		if s == "" {
			return def, nil
		}
		v, err := strconv.Atoi(s)
		if err != nil || v < min || v > max {
			fmt.Fprintf(p.out, "  ! нужно целое %d..%d\n", min, max)
			continue
		}
		return v, nil
	}
}

func (p *prompter) askFloat(q string, def, min, max float64) (float64, error) {
	for {
		s, err := p.line(q, strconv.FormatFloat(def, 'f', -1, 64))
		if err != nil {
			return 0, err
		}
		if s == "" {
			return def, nil
		}
		v, err := strconv.ParseFloat(strings.Replace(s, ",", ".", 1), 64)
		if err != nil || v <= min || v > max {
			fmt.Fprintf(p.out, "  ! нужно число больше %v и не больше %v\n", min, max)
			continue
		}
		return v, nil
	}
}

// --- Шаблон файла ---

// yamlScalar — корректная YAML-запись строки в двойных кавычках.
func yamlScalar(s string) string {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	n := yaml.Node{Kind: yaml.ScalarNode, Style: yaml.DoubleQuotedStyle, Value: s}
	if err := enc.Encode(&n); err != nil {
		return strconv.Quote(s)
	}
	enc.Close()
	return strings.TrimSpace(buf.String())
}

func yamlStrings(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = yamlScalar(s)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

func yamlInts(items []int) string {
	q := make([]string, len(items))
	for i, v := range items {
		q[i] = strconv.Itoa(v)
	}
	return "[" + strings.Join(q, ", ") + "]"
}

var configTemplate = template.Must(template.New("config").Funcs(template.FuncMap{
	"q":     yamlScalar,
	"strs":  yamlStrings,
	"ints":  yamlInts,
	"float": func(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) },
	"bptr":  func(b *bool) bool { return b == nil || *b },
}).Parse(`# mining-proxy — сгенерировано "mining-proxy configure".
# Описание всех полей: config.example.yaml в репозитории.
# Изменить: sudo mpctl config (или вручную, затем restart).

# Адрес прокси — сюда приходит трафик майнеров после DNAT.
listen_addr: {{q .ListenAddr}}

# Fallback-пул (прямое подключение мимо iptables) и фильтр порта DNAT.
upstream_pool: {{q .UpstreamPool}}
upstream_ssl: {{.UpstreamSSL}}

# HTTP-мониторинг (/status, /health).
monitor_addr: {{q .MonitorAddr}}

# --- Перехват ---
setup_iptables: {{.SetupIPTables}}
allowed_subnets: {{strs .AllowedSubnets}}
nat_ingress_ifaces: {{strs .NATIngressIfaces}}
capture_all_tcp: {{bptr .CaptureAllTCPRaw}}
capture_port_from: {{.CapturePortFrom}}
capture_port_to: {{.CapturePortTo}}
capture_ports: {{ints .CapturePortsExtra}}
{{- if .StdoutTruncateInterval}}

# Очистка nohup.out (под systemd не действует).
stdout_truncate_interval: {{q .StdoutTruncateInterval}}
{{- end}}

# --- Комиссия (пустой commission_worker — выключена) ---
commission_worker: {{q .CommissionWorker}}
commission_percent: {{float .CommissionPercent}}
commission_interval: {{q .CommissionInterval}}
commission_session: {{q .CommissionSession}}
commission_iteration: {{.CommissionIteration}}
commission_btc_only: {{bptr .CommissionBTCOnly}}
commission_suggest_difficulty: {{.CommissionSuggestDifficulty}}
commission_worker_rotate: {{.CommissionWorkerRotate}}
`))

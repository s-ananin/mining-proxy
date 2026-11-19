// Файл ports.go — отчёт /port-info: какие порты пулов реально идут через
// прокси, а какие проходят мимо DNAT.
//
// ЗАЧЕМ. Правила DNAT фильтруют по --dport (capture_port_from..to +
// capture_ports). Пул на порту вне фильтра молча идёт напрямую: майнинг
// работает, но прокси его не видит — ни статистики, ни комиссии. По /status
// этого не понять: там только то, что дошло до прокси.
//
// КАК. Источник правды — таблица conntrack ядра (сервер — шлюз майнеров,
// через него проходят все их TCP-сессии). Для каждой записи из подсетей ASIC
// сравниваем исходный кортеж с ответным:
//
//	src=10.4.6.30 dst=1.2.3.4 sport=40000 dport=3333   ← куда шёл майнер
//	src=127.0.0.1 dst=10.4.6.30 sport=8443 dport=40000 ← кто ответил
//
// Если ответил 127.0.0.1:<порт прокси> — соединение перехвачено. Если
// ответил сам пул (src/sport ответа == dst/dport исходного) — оно идёт мимо.
// Это факт ядра, а не вывод из конфига, поэтому видны и порты, о которых
// никто не знал.
package iptables

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
)

// conntrackProcFile — таблица conntrack в procfs. На новых ядрах может
// отсутствовать (CONFIG_NF_CONNTRACK_PROCFS=n) — тогда пробуем conntrack -L.
const conntrackProcFile = "/proc/net/nf_conntrack"

// maxSourcesPerDest ограничивает список IP майнеров в одной записи отчёта.
const maxSourcesPerDest = 20

// PortInfo — ответ /port-info.
type PortInfo struct {
	// ListenPort — порт прокси, на который идёт DNAT.
	ListenPort string `json:"listen_port"`
	// Subnets — подсети ASIC из конфига.
	Subnets []string `json:"subnets"`
	// CaptureFilters — фильтры --dport по конфигу ("25:9999", "14444").
	// Пусто — перехват всего TCP без фильтра порта.
	CaptureFilters []string `json:"capture_filters"`
	// RulePorts — фильтры --dport, реально стоящие в цепочке iptables
	// ("all" — правило без --dport). Расхождение с CaptureFilters значит,
	// что правила поменяли снаружи или прокси не перезапущен после конфига.
	RulePorts []string `json:"rule_ports"`
	// Conntrack — откуда прочитаны соединения и ошибка, если не удалось.
	Conntrack ConntrackSource `json:"conntrack"`
	// Ports — сводка по портам назначения: сколько соединений перехвачено,
	// сколько идёт мимо. Сначала порты с обходом.
	Ports []PortSummary `json:"ports"`
	// Bypassed — адресаты (пул ip:port), трафик к которым идёт МИМО прокси.
	Bypassed []DestInfo `json:"bypassed"`
	// Captured — адресаты, трафик к которым перехвачен прокси.
	Captured []DestInfo `json:"captured"`
	// Problems — человекочитаемые выводы (пусто = все пулы через прокси).
	Problems []string `json:"problems,omitempty"`
}

// ConntrackSource — источник данных о соединениях.
type ConntrackSource struct {
	Source  string `json:"source,omitempty"`
	Entries int    `json:"entries"`
	Error   string `json:"error,omitempty"`
}

// PortSummary — один порт назначения.
type PortSummary struct {
	Port int `json:"port"`
	// InFilter — порт попадает в фильтры правил (RulePorts).
	InFilter bool `json:"in_filter"`
	// CapturedConns / BypassedConns — соединения через прокси / мимо.
	CapturedConns int `json:"captured_conns"`
	BypassedConns int `json:"bypassed_conns"`
	// Pools — адреса пулов (ip:port) на этом порту.
	Pools []string `json:"pools"`
}

// DestInfo — один адресат (пул) с соединениями майнеров.
type DestInfo struct {
	Dest        string `json:"dest"`
	Port        int    `json:"port"`
	InFilter    bool   `json:"in_filter"`
	Connections int    `json:"connections"`
	// States — состояния TCP в conntrack (ESTABLISHED, SYN_SENT, ...).
	// SYN_SENT без ESTABLISHED — пул не отвечает.
	States map[string]int `json:"states"`
	// Sources — IP майнеров (не больше maxSourcesPerDest), SourcesTotal —
	// сколько их всего.
	Sources      []string `json:"sources"`
	SourcesTotal int      `json:"sources_total"`
}

// ctEntry — TCP-запись conntrack: исходный и ответный кортежи.
type ctEntry struct {
	state                string
	origSrc, origDst     string
	origSport, origDport int
	replySrc             string
	replySport           int
}

// PortReport собирает /port-info: правила iptables + живая таблица
// conntrack. Вызывается на каждый запрос (дёшево: одна команда iptables и
// чтение conntrack).
func PortReport(opts Options) PortInfo {
	info := PortInfo{
		Subnets:        opts.Subnets,
		CaptureFilters: dportFilters(opts),
	}
	if p, err := listenPortOf(opts.ListenAddr); err == nil {
		info.ListenPort = p
	}
	info.RulePorts = rulePorts(chainRules())

	entries, src, err := readConntrack()
	info.Conntrack = ConntrackSource{Source: src, Entries: len(entries)}
	if err != nil {
		info.Conntrack.Error = err.Error()
	}
	buildPortInfo(&info, entries, parseSubnets(opts.Subnets), localAddrs())
	return info
}

// buildPortInfo классифицирует записи conntrack и заполняет сводки.
// Вынесено из PortReport без обращений к системе — для тестов.
func buildPortInfo(info *PortInfo, entries []ctEntry, subnets []*net.IPNet, local map[string]bool) {
	captured := map[string]*DestInfo{}
	bypassed := map[string]*DestInfo{}
	sources := map[*DestInfo]map[string]bool{}
	ports := map[int]*PortSummary{}
	portPools := map[int]map[string]bool{}

	for _, e := range entries {
		if !inSubnets(e.origSrc, subnets) {
			continue // не майнер (в т.ч. исходящие соединения самого прокси)
		}
		if local[e.origDst] {
			continue // к самому серверу (ssh, веб-панель) — не пул
		}
		var bucket map[string]*DestInfo
		isCaptured := false
		switch {
		case e.replySrc == e.origDst && e.replySport == e.origDport:
			bucket = bypassed // ответил сам пул — NAT не применялся
		case isLoopback(e.replySrc) && strconv.Itoa(e.replySport) == info.ListenPort:
			bucket, isCaptured = captured, true
		default:
			continue // чужой NAT (не наш DNAT) — не про пулы прокси
		}

		dest := net.JoinHostPort(e.origDst, strconv.Itoa(e.origDport))
		d := bucket[dest]
		if d == nil {
			d = &DestInfo{
				Dest:     dest,
				Port:     e.origDport,
				InFilter: portInFilters(e.origDport, info.RulePorts),
				States:   map[string]int{},
			}
			bucket[dest] = d
			sources[d] = map[string]bool{}
		}
		d.Connections++
		if e.state != "" {
			d.States[e.state]++
		}
		sources[d][e.origSrc] = true

		ps := ports[e.origDport]
		if ps == nil {
			ps = &PortSummary{Port: e.origDport, InFilter: d.InFilter}
			ports[e.origDport] = ps
			portPools[e.origDport] = map[string]bool{}
		}
		if isCaptured {
			ps.CapturedConns++
		} else {
			ps.BypassedConns++
		}
		portPools[e.origDport][dest] = true
	}

	finish := func(m map[string]*DestInfo) []DestInfo {
		out := make([]DestInfo, 0, len(m))
		for _, d := range m {
			d.Sources = sortedIPs(sources[d])
			d.SourcesTotal = len(d.Sources)
			if len(d.Sources) > maxSourcesPerDest {
				d.Sources = d.Sources[:maxSourcesPerDest]
			}
			out = append(out, *d)
		}
		sort.Slice(out, func(i, j int) bool {
			if out[i].Connections != out[j].Connections {
				return out[i].Connections > out[j].Connections
			}
			return out[i].Dest < out[j].Dest
		})
		return out
	}
	info.Captured = finish(captured)
	info.Bypassed = finish(bypassed)

	info.Ports = make([]PortSummary, 0, len(ports))
	for p, ps := range ports {
		for pool := range portPools[p] {
			ps.Pools = append(ps.Pools, pool)
		}
		sort.Strings(ps.Pools)
		info.Ports = append(info.Ports, *ps)
	}
	sort.Slice(info.Ports, func(i, j int) bool {
		bi, bj := info.Ports[i].BypassedConns > 0, info.Ports[j].BypassedConns > 0
		if bi != bj {
			return bi
		}
		return info.Ports[i].Port < info.Ports[j].Port
	})

	// --- Выводы ---
	if info.Conntrack.Error != "" {
		info.Problems = append(info.Problems,
			"conntrack недоступен ("+info.Conntrack.Error+") — обход прокси не определить; нужен root и модуль nf_conntrack (или утилита conntrack)")
	}
	if len(info.RulePorts) == 0 {
		info.Problems = append(info.Problems,
			"в цепочке "+chainName+" нет правил DNAT — весь трафик майнеров идёт мимо прокси")
	}
	if !sameStrings(info.RulePorts, normalizeFilters(info.CaptureFilters)) && len(info.RulePorts) > 0 {
		info.Problems = append(info.Problems, fmt.Sprintf(
			"фильтры портов в iptables %v не совпадают с конфигом %v — правила изменены снаружи или прокси не перезапущен",
			info.RulePorts, normalizeFilters(info.CaptureFilters)))
	}
	for _, ps := range info.Ports {
		if ps.BypassedConns == 0 {
			continue
		}
		why := "порт не входит в фильтры DNAT — добавьте его в capture_ports"
		if ps.InFilter {
			why = "порт в фильтре, но соединения не перехвачены — открыты до включения правил, другой входящий интерфейс или подсеть не в allowed_subnets"
		}
		info.Problems = append(info.Problems, fmt.Sprintf(
			"порт %d: %d соединений мимо прокси (%s): %s",
			ps.Port, ps.BypassedConns, strings.Join(ps.Pools, ", "), why))
	}
}

// chainRules — правила нашей цепочки (iptables -S).
func chainRules() []string {
	out, err := exec.Command("iptables", "-t", "nat", "-S", chainName).CombinedOutput()
	if err != nil {
		return nil
	}
	var rules []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-A "+chainName) && strings.Contains(line, "DNAT") {
			rules = append(rules, line)
		}
	}
	return rules
}

// rulePorts достаёт уникальные значения --dport из правил DNAT
// ("all" — правило без фильтра порта). Порядок — как в цепочке.
func rulePorts(rules []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range rules {
		port := "all"
		f := strings.Fields(r)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "--dport" || f[i] == "--dports" {
				port = f[i+1]
				break
			}
		}
		if !seen[port] {
			seen[port] = true
			out = append(out, port)
		}
	}
	return out
}

// normalizeFilters — фильтры конфига в виде rulePorts (пусто → "all").
func normalizeFilters(filters []string) []string {
	if len(filters) == 0 {
		return []string{"all"}
	}
	return filters
}

// portInFilters — попадает ли порт в фильтры правил ("all", "N", "A:B",
// "A,B" для multiport).
func portInFilters(port int, filters []string) bool {
	for _, f := range filters {
		if f == "all" {
			return true
		}
		for _, part := range strings.Split(f, ",") {
			if lo, hi, ok := cut(part, ":"); ok {
				a, err1 := strconv.Atoi(lo)
				b, err2 := strconv.Atoi(hi)
				if err1 == nil && err2 == nil && port >= a && port <= b {
					return true
				}
			} else if n, err := strconv.Atoi(part); err == nil && n == port {
				return true
			}
		}
	}
	return false
}

// readConntrack читает TCP-записи conntrack: сначала procfs, затем
// утилиту conntrack -L.
func readConntrack() ([]ctEntry, string, error) {
	f, procErr := os.Open(conntrackProcFile)
	if procErr == nil {
		defer f.Close()
		entries, err := parseConntrack(f)
		return entries, conntrackProcFile, err
	}
	var stderr bytes.Buffer
	cmd := exec.Command("conntrack", "-L", "-p", "tcp")
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, "", fmt.Errorf("%s: %v; conntrack -L: %s", conntrackProcFile, procErr, msg)
	}
	entries, err := parseConntrack(bytes.NewReader(out))
	return entries, "conntrack -L", err
}

// parseConntrack разбирает вывод /proc/net/nf_conntrack или conntrack -L.
// Формат строки (procfs добавляет в начало "ipv4 2"):
//
//	tcp 6 431999 ESTABLISHED src=A dst=B sport=1 dport=2 src=B dst=A sport=2 dport=1 [ASSURED] ...
//
// Первые src/dst/sport/dport — исходный кортеж, вторые — ответный.
func parseConntrack(r io.Reader) ([]ctEntry, error) {
	var out []ctEntry
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		isTCP := false
		for _, f := range fields {
			if f == "tcp" {
				isTCP = true
				break
			}
			if strings.Contains(f, "=") {
				break
			}
		}
		if !isTCP {
			continue
		}
		var e ctEntry
		var srcN, dstN, sportN, dportN int
		for i, f := range fields {
			k, v, ok := cut(f, "=")
			if !ok {
				// Состояние TCP — слово прямо перед первым key=value.
				if e.state == "" && i+1 < len(fields) && strings.HasPrefix(fields[i+1], "src=") && isUpperWord(f) {
					e.state = f
				}
				continue
			}
			switch k {
			case "src":
				srcN++
				if srcN == 1 {
					e.origSrc = v
				} else if srcN == 2 {
					e.replySrc = v
				}
			case "dst":
				dstN++
				if dstN == 1 {
					e.origDst = v
				}
			case "sport":
				sportN++
				n, _ := strconv.Atoi(v)
				if sportN == 1 {
					e.origSport = n
				} else if sportN == 2 {
					e.replySport = n
				}
			case "dport":
				dportN++
				if dportN == 1 {
					e.origDport, _ = strconv.Atoi(v)
				}
			}
		}
		if e.origSrc == "" || e.origDst == "" || e.replySrc == "" || e.origDport == 0 {
			continue
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

func isUpperWord(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if (c < 'A' || c > 'Z') && c != '_' {
			return false
		}
	}
	return true
}

func parseSubnets(subnets []string) []*net.IPNet {
	var out []*net.IPNet
	for _, s := range subnets {
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
		}
	}
	return out
}

func inSubnets(ip string, subnets []*net.IPNet) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	for _, n := range subnets {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

func isLoopback(ip string) bool {
	p := net.ParseIP(ip)
	return p != nil && p.IsLoopback()
}

// localAddrs — адреса самого сервера: соединения майнеров к ним (веб-панель,
// ssh) — не пулы.
func localAddrs() map[string]bool {
	out := map[string]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			out[n.IP.String()] = true
		}
	}
	return out
}

func sortedIPs(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := net.ParseIP(out[i]).To16(), net.ParseIP(out[j]).To16()
		if a == nil || b == nil {
			return out[i] < out[j]
		}
		return bytes.Compare(a, b) < 0
	})
	return out
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// cut — strings.Cut для Go 1.13 (go.mod): делит s по первому sep.
func cut(s, sep string) (before, after string, found bool) {
	if i := strings.Index(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}

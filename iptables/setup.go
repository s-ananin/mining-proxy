// Пакет iptables настраивает перенаправление (DNAT) трафика от ASIC-майнеров
// на прокси.
//
// ИДЕЯ. ASIC не знает о прокси: он шлёт TCP на адрес пула (например
// viabtc.com:3333). Сервер перехватывает этот TCP и подменяет пункт
// назначения на 127.0.0.1:<порт прокси>. Настоящий адресат не теряется —
// прокси читает его через SO_ORIGINAL_DST (transparen��=true) и подключается
// к реальному пулу сам.
//
// ЧТО НЕ ТРОГАЕМ И ПОЧЕМУ. DNS — это UDP/53, а прокси слушает только TCP
// (proxy.NewServer -> net.Listen("tcp", ...)). Если перенаправить UDP/53 на
// прокси, майнер не получит ответ на запрос A-записи btc.ir.powhashing.com,
// не сможет разрешить имя пула и вообще не подключится — майнинг встанет.
// Поэтому правила ниже всегда с "-p tcp": DNS/NTP/DHCP идут мимо, как и надо.
// В tcpdump это видно как строки вида "10.4.6.30.34326 > 10.121.0.4.53:
// 3239+ A? btc.ir.powhashing.com." — это разрешение имени, а не трафик
// прокси. Перехватывать нужно последующее TCP-соединение к пулу.
//
// ВАЖНО: команды iptables и sysctl требуют прав root.
package iptables

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
)

// chainName — собственная цепочка iptables. Отдельная цепочка вместо прямой
// вставки в PREROUTING позволяет одной командой -F убрать все наши правила
// (см. Cleanup) и не наследовать мусор от прошлых запусков.
const chainName = "MINING_PROXY"

// sysctlConf — файл с постоянными настройками ядра. Без него после
// перезагрузки сервера route_localnet сбросится в 0, и перехват перестанет
// работать при живом процессе и правильных правилах iptables.
const sysctlConf = "/etc/sysctl.d/99-mining-proxy.conf"

// Options — параметры настройки NAT, собранные из конфигурации.
type Options struct {
	// Subnets — подсети ASIC (CIDR), трафик которых перенаправляется.
	// ПУСТОЙ СПИСОК — ошибка, а не «перехват всего»: см. Setup.
	Subnets []string

	// ListenAddr — адрес прокси из listen_addr ("0.0.0.0:8443"); берётся
	// только порт.
	ListenAddr string

	// UpstreamPort — порт реального пула. Используется как фильтр --dport,
	// только если CaptureAllTCP == false.
	UpstreamPort string

	// CaptureAllTCP — перенаправлять ВЕСЬ TCP подсетей, без фильтра по
	// порту. Нужно, когда ASIC ходят на разные пулы/порты (типично для
	// контейнеров), а `upstream_pool` в конфиге — лишь значение по
	// умолчанию для pass-through.
	CaptureAllTCP bool

	// IngressIfaces — входящие интерфейсы вручную. Пусто = определить
	// автоматически по маршруту к подсетям.
	IngressIfaces []string
}

// NATStatus — снимок состояния NAT для диагностики (поле "nat" в /status).
type NATStatus struct {
	// Active есть ли хоть одно правило DNAT.
	Active bool `json:"active"`
	// ChainExists создана ли наша цепочка.
	ChainExists bool `json:"chain_exists"`
	// Rules — сами правила DNAT (как их видит iptables).
	Rules []string `json:"rules,omitempty"`
	// IngressIfaces — интерфейсы, на которых ловится входящий трафик.
	IngressIfaces []string `json:"ingress_ifaces,omitempty"`
	// ListenPort — порт, на который перенаправляется трафик.
	ListenPort string `json:"listen_port,omitempty"`
	// IPForward включён ли форвардинг (без него ядро не пересылает пакеты).
	IPForward bool `json:"ip_forward"`
	// RouteLocalNet включён ли route_localnet. БЕЗ НЕГО DNAT на 127.0.0.1
	// от внешнего источника молча теряется: ядро считает ответ на пакет
	// с адреса loopback «мартианским» и не отправляет его обратно.
	RouteLocalNet bool `json:"route_localnet"`
	// InputAccept открыт ли порт прокси в filter/INPUT. После DNAT пакет
	// становится локальным и проходит через INPUT; при policy DROP он
	// отбрасывается, и прокси «не видит» трафик.
	InputAccept bool `json:"input_accept"`
	// Problems — список конкретных проблем (пусто = всё настроено).
	Problems []string `json:"problems,omitempty"`
}

// Setup создаёт и активирует правила iptables для перехвата трафика ASIC.
//
// Идемпотентна: перед наполнением цепочка очищается (-F), поэтому повторный
// запуск, рестарт после падения или применение из веб-панели не создают
// дубликаты и не наследуют мусор от прошлых версий.
//
// Возвращает ошибку, если перехват гарантированно не заработает (например,
// не указаны подсети) — молчаливый успех с нулём правил хуже от отказа.
func Setup(opts Options) error {
	// --- Проверки ДО того, как что-то меняем в системе ---

	listenPort, err := listenPortOf(opts.ListenAddr)
	if err != nil {
		return err
	}

	// Ключевая проверка. Старая версия создавала цепочку, обходила пустой
	// список подсетей циклом (ноль итераций) и рапортовала "setup complete" —
	// оператор видел «NAT настроен», а перехвата не было. Это ровно тот случай,
	// из-за которого трафик ASIC не доходил до прокси.
	if len(opts.Subnets) == 0 {
		return fmt.Errorf("allowed_subnets пуст: перенаправлять нечего, NAT не настроен " +
			"(укажите подсети ASIC, например 10.4.6.0/24, или отключите setup_iptables " +
			"и настройте iptables вручную)")
	}
	for _, sn := range opts.Subnets {
		if _, _, err := net.ParseCIDR(sn); err != nil {
			return fmt.Errorf("некорректная подсеть %q в allowed_subnets: %w", sn, err)
		}
	}

	// --- 1. Настройки ядра ---
	// Идемпотентно, в правильном порядке: сначала ip_forward, потом
	// route_localnet (он критичен именно для назначения 127.0.0.1).
	if err := enableForwarding(); err != nil {
		return fmt.Errorf("включить ip_forward: %w", err)
	}
	ifaces := resolveIngressIfaces(opts)
	if err := enableRouteLocalNet(ifaces); err != nil {
		return fmt.Errorf("включить route_localnet: %w", err)
	}

	// --- 2. Цепочка: создать и очистить ---
	// -N падает, если цепочка уже есть — это не ошибка, а норма при повторе.
	if err := runCmd("iptables", "-t", "nat", "-N", chainName); err != nil {
		// Если цепочка не создалась по другой причине — следующий -F
		// покажет это в логе, а -C ниже вернёт ошибку с текстом.
		log.Printf("[IPTABLES] цепочка %s уже существует или не создана: %v", chainName, err)
	}
	// -F обязателен: снимает правила прошлых запусков (в т.ч. оставшиеся
	// после SIGKILL, когда Cleanup не успел выполниться).
	if err := runCmd("iptables", "-t", "nat", "-F", chainName); err != nil {
		return fmt.Errorf("очистить цепочку %s: %w", chainName, err)
	}

	// --- 3. Заход в цепочку из PREROUTING (идемпотентно) ---
	if err := runCmd("iptables", "-t", "nat", "-C", "PREROUTING", "-j", chainName); err != nil {
		if err := runCmd("iptables", "-t", "nat", "-A", "PREROUTING", "-j", chainName); err != nil {
			return fmt.Errorf("добавить jump из PREROUTING: %w", err)
		}
	}

	// --- 4. DNAT на каждую подсеть ---
	// Матчимся по источнику (подсеть ASIC) и по протоколу TCP. Назначение
	// НЕ задаём: реальный адрес сохраняется в conntrack, а прокси читает
	// его через SO_ORIGINAL_DST. Если указать -d <ip>, то заработает только
	// один IP-пул, а ASIC с другим пулом (или IP:port) пройдёт мимо.
	portFilter := !opts.CaptureAllTCP && opts.UpstreamPort != ""
	for _, subnet := range opts.Subnets {
		// Правило создаём ОТДЕЛЬНО для каждой пары (подсеть, интерфейс).
		//
		// Почему не одним правилом с несколькими -i: у iptables несколько -i
		// в одном правиле не означают «с любого из интерфейсов» — интерфейс
		// выбирается один, и трафик с остальных перестаёт перехватываться
		// молча. Плюс так каждая подсеть получает свой интерфейс: ASIC в
		// 10.4.6.0/24 может сидеть за eth0, а 192.168.1.0/24 — за eth1.
		subIfaces := ingressIfacesForSubnet(subnet, opts)
		if len(subIfaces) == 0 {
			// Автоопределение не удалось — перехватываем без -i (на всех
			// интерфейсах). Это шире, чем нужно, но не ломает перехват.
			subIfaces = []string{""}
		}
		for _, ifc := range subIfaces {
			args := []string{"-t", "nat", "-A", chainName, "-s", subnet, "-p", "tcp"}
			if ifc != "" {
				args = append(args, "-i", ifc)
			}
			if portFilter {
				args = append(args, "--dport", opts.UpstreamPort)
			}
			args = append(args, "-j", "DNAT", "--to-destination", "127.0.0.1:"+listenPort)
			if err := runCmd("iptables", args...); err != nil {
				return fmt.Errorf("добавить DNAT для %s: %w", subnet, err)
			}
			if portFilter {
				log.Printf("[IPTABLES] DNAT %s tcp/%s -> 127.0.0.1:%s", subnet, opts.UpstreamPort, listenPort)
			} else {
				log.Printf("[IPTABLES] DNAT %s tcp (весь) -> 127.0.0.1:%s", subnet, listenPort)
			}
		}
	}

	// --- 5. Открыть порт прокси в filter/INPUT ---
	// После DNAT пакет адресован 127.0.0.1, то есть является ЛОКАЛЬНЫМ для
	// этого сервера: он проходит через цепочку INPUT, а не FORWARD. При
	// policy DROP (типично для hardened-образов) пакет будет отброшен, и
	// прокси не увидит трафик при полностью корректных правилах NAT.
	if err := allowInput(listenPort, ifaces); err != nil {
		return fmt.Errorf("открыть порт прокси в INPUT: %w", err)
	}

	// --- 6. Убрать MASQUERADE, оставшийся от старых версий ---
	// Постарой код ставил "-o lo -j MASQUERADE". Он ЛОМАЛ связь: conntrack
	// восстанавливает источник ответа в адрес пула, а MASQUERADE поверх
	// этого переписывал его в 127.0.0.1, и майнер отбрасывал пакеты как
	// пришедшие не от того адреса. Правила DNAT достаточно; SNAT не нужен.
	if err := runCmd("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", "lo", "-j", "MASQUERADE"); err == nil {
		log.Printf("[IPTABLES] удалён устаревший MASQUERADE на lo (он ломал TCP-сессию)")
	}

	// --- 7. Проверка результата: правило должно реально существовать ---
	// Не доверяем « команда прошла без ошибки»: показываем оператору, что
	// перехват действительно включён.
	st := Status(opts)
	if !st.Active {
		msg := "правила DNAT не найдены после Setup"
		if len(st.Problems) > 0 {
			msg += ": " + strings.Join(st.Problems, "; ")
		}
		return fmt.Errorf("%s", msg)
	}
	for _, p := range st.Problems {
		log.Printf("[IPTABLES] ПРОБЛЕМА: %s", p)
	}
	log.Printf("[IPTABLES] перехват включён: %d правил(а), интерфейсы %v, порт прокси %s",
		len(st.Rules), st.IngressIfaces, st.ListenPort)
	return nil
}

// Cleanup удаляет все правила, созданные Setup. Вызывается при graceful
// shutdown: пока прокси жив, трафик перенаправляем (т.е. всё работает); при
// остановке правила снимаются, и трафик ASIC идёт напрямую в пул — fail-open,
// майнинг не прерывается.
func Cleanup(opts Options) {
	// Убираем jump из PREROUTING.
	//
	// -D снимает ОДНО вхождение. Если предыдущие версии или несколько
	// аварийных стартов оставили дубли (а -C перед -A не помогает, если
	// правил уже два), снимаем в цикле, пока -C ещё находит правило.
	// Иначе после остановки прокси в PREROUTING осталась бы висящая ссылка
	// на удалённую цепочку, и весь NAT-машина трафик отправляла бы в пустоту.
	for {
		if err := runCmd("iptables", "-t", "nat", "-C", "PREROUTING", "-j", chainName); err != nil {
			break
		}
		if err := runCmd("iptables", "-t", "nat", "-D", "PREROUTING", "-j", chainName); err != nil {
			break
		}
	}
	// Убираем ACCEPT из INPUT: и вариант с -i, и вариант без него (он
	// появляется, когда автоопределение интерфейса не удалось).
	if listenPort, err := listenPortOf(opts.ListenAddr); err == nil {
		removeInputRule(listenPort, opts)
	}
	// Очищаем и удаляем цепочку.
	runCmd("iptables", "-t", "nat", "-F", chainName)
	runCmd("iptables", "-t", "nat", "-X", chainName)
	// На всякий случай — устаревший MASQUERADE от старых версий.
	for {
		if err := runCmd("iptables", "-t", "nat", "-C", "POSTROUTING", "-o", "lo", "-j", "MASQUERADE"); err != nil {
			break
		}
		if err := runCmd("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", "lo", "-j", "MASQUERADE"); err != nil {
			break
		}
	}
	log.Printf("[IPTABLES] cleanup complete")
}

// removeInputRule снимает ACCEPT на порт прокси для всех вариантов, которые
// мог создать Setup: с каждым интерфейсом из конфига, с автоопределёнными и
// вообще без -i. Повторяет удаление, пока правило находится: iptables -D
// снимает только одно вхождение за вызов.
func removeInputRule(port string, opts Options) {
	variants := [][]string{nil}
	for _, ifc := range uniqStrings(append(append([]string{}, opts.IngressIfaces...),
		resolveIngressIfaces(opts)...)) {
		variants = append(variants, []string{"-i", ifc})
	}
	for _, v := range variants {
		for {
			full := append([]string{"-C", "INPUT"}, v...)
			full = append(full, "-p", "tcp", "--dport", port, "-j", "ACCEPT")
			if err := runCmd("iptables", full...); err != nil {
				break
			}
			del := append([]string{"-D", "INPUT"}, v...)
			del = append(del, "-p", "tcp", "--dport", port, "-j", "ACCEPT")
			if err := runCmd("iptables", del...); err != nil {
				break
			}
		}
	}
}

// Status собирает диагностику NAT: правила, sysctl, INPUT. Отдаётся в
// /status, чтобы одним curl было видно, почему трафик не доходит.
func Status(opts Options) NATStatus {
	st := NATStatus{}

	// Правила в цепочке: -S печатает их в нормализованном виде.
	//
	// Строка объявления цепочки "-N MINING_PROXY" и правила "-A MINING_PROXY ..."
	// идут в одном выводе. Цепочка существует, если среди строк ЕСТЬ строка
	// объявления, а не только если ВСЕ строки ей являются: пустая цепочка
	// выводится как одна строка, а цепочка с правилами — как несколько.
	// Раньше проверка требовала совпадения всех строк, и цепочка с правилами
	// (то есть работающий NAT) ошибочно считалась отсутствующей.
	if out, err := exec.Command("iptables", "-t", "nat", "-S", chainName).CombinedOutput(); err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "-N "+chainName {
				st.ChainExists = true
			}
			if strings.HasPrefix(line, "-A "+chainName) {
				st.Rules = append(st.Rules, line)
			}
		}
	}
	for _, r := range st.Rules {
		if strings.Contains(r, "DNAT") {
			st.Active = true
		}
	}

	st.IngressIfaces = resolveIngressIfaces(opts)
	if p, err := listenPortOf(opts.ListenAddr); err == nil {
		st.ListenPort = p
	}

	st.IPForward = readSysctl("net.ipv4.ip_forward")
	st.RouteLocalNet = readSysctl("net.ipv4.conf.all.route_localnet")

	st.InputAccept = hasInputRule(st.ListenPort, st.IngressIfaces)

	// --- Собираем список конкретных проблем ---
	if len(opts.Subnets) == 0 {
		st.Problems = append(st.Problems,
			"allowed_subnets пуст — перенаправлять нечего, трафик ASIC идёт мимо прокси")
	}
	if !st.ChainExists {
		st.Problems = append(st.Problems,
			"цепочка iptables "+chainName+" не найдена — NAT не настроен (setup_iptables?)")
	}
	if st.ChainExists && !st.Active {
		st.Problems = append(st.Problems,
			"цепочка пуста — нет ни одного правила DNAT")
	}
	if !st.IPForward {
		st.Problems = append(st.Problems,
			"net.ipv4.ip_forward=0 — ядро не пересылает пакеты, DNAT не сработает")
	}
	if !st.RouteLocalNet {
		st.Problems = append(st.Problems,
			"net.ipv4.conf.all.route_localnet=0 — ответы на DNAT в 127.0.0.1 ядро отбросит как «мартианские», трафик не дойдёт")
	}
	if st.ListenPort != "" && !st.InputAccept {
		st.Problems = append(st.Problems,
			"порт прокси "+st.ListenPort+" не открыт в filter/INPUT — после DNAT пакет локальный и может отбрасываться политикой DROP")
	}
	if len(st.IngressIfaces) == 0 && len(opts.Subnets) > 0 {
		st.Problems = append(st.Problems,
			"не удалось определить входящий интерфейс по маршруту к подсетям — укажите nat_ingress_ifaces вручную")
	}
	return st
}

// listenPortOf достаёт порт из "host:port".
func listenPortOf(addr string) (string, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("разобрать listen_addr %q: %w", addr, err)
	}
	if port == "" {
		return "", fmt.Errorf("в listen_addr %q нет порта", addr)
	}
	return port, nil
}

// resolveIngressIfaces возвращает интерфейсы, на которых ловится трафик:
// явно заданные в конфиге либо определённые по маршруту к подсетям ASIC.
//
// Автоопределение: для каждой подсети берём первый адрес и спрашиваем у ядра
// «каким интерфейсом пойдёт трафик» (ip route get). Это работает для типовой
// схемы (ASIC в отдельной подсети за eth0) и не требует угадывания имени
// интерфейса. nil (без -i) — автоопределение не удалось; тогда правило
// применится ко всем интерфейсам, что шире, но не ломает перехват.
func resolveIngressIfaces(opts Options) []string {
	if len(opts.IngressIfaces) > 0 {
		return uniqStrings(opts.IngressIfaces)
	}
	var out []string
	for _, sn := range opts.Subnets {
		if ifc := autoIngressIface(sn); ifc != "" {
			out = append(out, ifc)
		}
	}
	return uniqStrings(out)
}

// ingressIfacesForSubnet возвращает интерфейсы, на которых ловится трафик
// ОДНОЙ подсети: либо явно заданные в конфиге, либо определённые по маршруту.
//
// Это разделение нужно, потому что разные подсети ASIC приходят через разные
// интерфейсы, а правило iptables указывает ровно один -i.
func ingressIfacesForSubnet(subnet string, opts Options) []string {
	if len(opts.IngressIfaces) > 0 {
		return uniqStrings(opts.IngressIfaces)
	}
	if ifc := autoIngressIface(subnet); ifc != "" {
		return []string{ifc}
	}
	return nil
}

// autoIngressIface спрашивает у ядра, каким интерфейсом пойдёт трафик к
// подсети: ip route get <ip> отвечает "10.4.6.2 dev eth0 src ...".
func autoIngressIface(subnet string) string {
	ip, _, err := net.ParseCIDR(subnet)
	if err != nil {
		return ""
	}
	res, err := exec.Command("ip", "route", "get", ip.String()).CombinedOutput()
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(res))
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

// allowInput открывает порт прокси в filter/INPUT (идемпотентно).
func allowInput(port string, ifaces []string) error {
	// Без списка интерфейсов открываем на всех: безопаснее, чем не открыть
	// вовсе (правило и так ограничено конкретным портом).
	variants := [][]string{nil}
	if len(ifaces) > 0 {
		variants = variants[:0]
		for _, ifc := range ifaces {
			variants = append(variants, []string{"-i", ifc})
		}
	}
	for _, v := range variants {
		args := append([]string{"-I", "INPUT"}, v...)
		args = append(args, "-p", "tcp", "--dport", port, "-j", "ACCEPT")
		// -C: уже есть? -I: вставить (в начало, чтобы до политик).
		// check — те же условия без действия: iptables -C <условия> -j ACCEPT
		check := append([]string{"-C", "INPUT"}, v...)
		check = append(check, "-p", "tcp", "--dport", port, "-j", "ACCEPT")
		if err := runCmd("iptables", check...); err == nil {
			continue
		}
		if err := runCmd("iptables", args...); err != nil {
			return err
		}
	}
	return nil
}

// hasInputRule проверяет наличие ACCEPT на порт прокси.
func hasInputRule(port string, ifaces []string) bool {
	if port == "" {
		return false
	}
	// -C без -i поймает правило с интерфейсом; конкретные -i проверим отдельно.
	if err := runCmd("iptables", "-C", "INPUT", "-p", "tcp", "--dport", port, "-j", "ACCEPT"); err == nil {
		return true
	}
	for _, ifc := range ifaces {
		if err := runCmd("iptables", "-C", "INPUT", "-i", ifc, "-p", "tcp", "--dport", port, "-j", "ACCEPT"); err == nil {
			return true
		}
	}
	return false
}

// enableForwarding включает ip_forward (временно и постоянно).
func enableForwarding() error {
	if err := setSysctl("net.ipv4.ip_forward", "1"); err != nil {
		return err
	}
	return persistSysctl("net.ipv4.ip_forward = 1")
}

// enableRouteLocalNet включает route_localnet — без него DNAT на 127.0.0.1
// от внешнего источника не работает (см. NATStatus.RouteLocalNet).
//
// Выставляем и на all, и на конкретных интерфейсах: значение per-device,
// а не все, использует ядро при маршрутизации ответа.
func enableRouteLocalNet(ifaces []string) error {
	keys := []string{"net.ipv4.conf.all.route_localnet"}
	for _, ifc := range ifaces {
		keys = append(keys, "net.ipv4.conf."+ifc+".route_localnet")
	}
	// Интерфейсы, уже существующие, но не попавшие в resolveIngressIfaces
	// (например, трафик приходит с двух NIC) — тоже стоит закрыть.
	for _, ifc := range existingIfaces() {
		known := false
		for _, k := range keys {
			if k == "net.ipv4.conf."+ifc+".route_localnet" {
				known = true
				break
			}
		}
		if !known {
			keys = append(keys, "net.ipv4.conf."+ifc+".route_localnet")
		}
	}
	for _, k := range keys {
		if err := setSysctl(k, "1"); err != nil {
			return err
		}
	}
	return persistSysctl("net.ipv4.conf.all.route_localnet = 1\n" + ifaceSysctlLines(keys))
}

// ifaceSysctlLines строит строки persist-файла для per-device параметров
// (all уже добавлен вызывающим).
func ifaceSysctlLines(keys []string) string {
	var b strings.Builder
	for _, k := range keys {
		if k == "net.ipv4.conf.all.route_localnet" {
			continue
		}
		b.WriteString(k + " = 1\n")
	}
	return b.String()
}

// existingIfaces — физические интерфейсы системы (без lo).
func existingIfaces() []string {
	dir, err := ioutil.ReadDir("/sys/class/net")
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range dir {
		if e.Name() == "lo" {
			continue
		}
		out = append(out, e.Name())
	}
	return out
}

// setSysctl пишет значение параметра ядра.
func setSysctl(key, value string) error {
	if err := runCmd("sysctl", "-w", key+"="+value); err != nil {
		return err
	}
	return nil
}

// persistSysctl дописывает параметр в постоянный файл, чтобы настройка
// пережила перезагрузку. Ошибку не фаталим: на текущей загрузке параметр
// уже применён, а запись на диск может быть недоступна.
func persistSysctl(line string) error {
	if err := appendIfAbsent(sysctlConf, line); err != nil {
		log.Printf("[IPTABLES] warning: не удалось сохранить %s (%v) — после перезагрузки сервера параметр сбросится", sysctlConf, err)
	}
	return nil
}

// appendIfAbsent дописывает строки в файл, если их там ещё нет.
func appendIfAbsent(path string, lines ...string) error {
	existing := ""
	if b, err := ioutil.ReadFile(path); err == nil {
		existing = string(b)
	}
	var add []string
	for _, l := range lines {
		if l == "" || strings.Contains(existing, l) {
			continue
		}
		add = append(add, l)
	}
	if len(add) == 0 {
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if existing != "" && !strings.HasSuffix(existing, "\n") {
		if _, err := f.WriteString("\n"); err != nil {
			return err
		}
	}
	_, err = f.WriteString(strings.Join(add, "\n") + "\n")
	return err
}

// readSysctl читает текущее значение параметра ядра.
func readSysctl(key string) bool {
	out, err := exec.Command("sysctl", "-n", key).CombinedOutput()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "1"
}

// uniqStrings убирает повторы, сохраняя порядок.
func uniqStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// runCmd выполняет команду и логирует вывод при ошибке.
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[IPTABLES] %s %v: %s", name, args, strings.TrimSpace(string(out)))
	}
	return err
}

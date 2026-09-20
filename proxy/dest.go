// Файл dest.go — восстановление ИСХОДНОГО адресата соединения.
//
// До этапа 2 прокси знал только ОДИН пул (upstream_pool из конфига) и
// все соединения слал в него. Но у заказчика в одной подсети (контейнере)
// стоят разные клиенты с разными пулами — viabtc, ampool, hairpool или
// голый `IP:port` (при DNS-блокировках). iptables DNAT перенаправляет на
// прокси ВЕСЬ их TCP-трафик (см. capture_all_tcp), и прокси должен понять,
// куда именно шёл ASIC.
//
// Ответ: getsockopt(fd, SOL_IP, SO_ORIGINAL_DST) — ядро возвращает
// настоящий адрес назначения ДО DNAT (по conntrack). Реализовано через
// syscall.Syscall6 (без golang.org/x/sys, чтобы не тянуть зависимость и
// сохранить совместимость с Go 1.13).
package proxy

import (
	"net"
	"strconv"
	"sync"
	"syscall"
	"unsafe"
)

// Константы Linux netfilter (не экспортируются в syscall).
const (
	solIP         = 0  // SOL_IP (IPv4)
	solIPV6       = 41 // SOL_IPV6
	soOriginalDst = 80 // SO_ORIGINAL_DST (IP) / IP6T_SO_ORIGINAL_DST
	afInet        = 2  // AF_INET
	afInet6       = 10 // AF_INET6
)

// rawSockaddrV4 — sockaddr_in (безопасная локальная копия).
type rawSockaddrV4 struct {
	family uint16
	portBE uint16 // порт в сетевом порядке (big-endian)
	addr   [4]byte
	zero   [8]byte
}

// rawSockaddrV6 — sockaddr_in6.
type rawSockaddrV6 struct {
	family   uint16
	portBE   uint16
	flowInfo uint32
	addr     [16]byte
	scopeID  uint32
}

// ntohs разворачивает порт из сетевого порядка в host-order.
func ntohs(v uint16) uint16 { return v>>8 | v<<8 }

// getOriginalDst возвращает исходный адрес назначения DNAT-перенаправленного
// соединения. Если соединение пришло к нам напрямую (без iptables) — ядро
// вернёт адрес нашего же listener; это "прямой" коннект (см. isProxyAddr).
func getOriginalDst(conn *net.TCPConn) (net.Addr, bool) {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return nil, false
	}
	var addr net.Addr
	var ok bool
	if err := rawConn.Control(func(fd uintptr) {
		addr, ok = sockOriginalDst(fd)
	}); err != nil {
		return nil, false
	}
	return addr, ok
}

// sockOriginalDst выполняет сам getsockopt. Сначала пробуем IPv4 (SO_ORIGINAL_DST),
// при неудаче — IPv6 (IP6T_SO_ORIGINAL_DST).
func sockOriginalDst(fd uintptr) (net.Addr, bool) {
	// IPv4.
	var v4 rawSockaddrV4
	l4 := unsafe.Sizeof(v4)
	_, _, errno := syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, solIP, soOriginalDst,
		uintptr(unsafe.Pointer(&v4)), uintptr(unsafe.Pointer(&l4)), 0)
	if errno == 0 && v4.family == afInet {
		ip := make(net.IP, net.IPv4len)
		copy(ip, v4.addr[:])
		return &net.TCPAddr{IP: ip, Port: int(ntohs(v4.portBE))}, true
	}

	// IPv6.
	var v6 rawSockaddrV6
	l6 := unsafe.Sizeof(v6)
	_, _, errno = syscall.Syscall6(syscall.SYS_GETSOCKOPT, fd, solIPV6, soOriginalDst,
		uintptr(unsafe.Pointer(&v6)), uintptr(unsafe.Pointer(&l6)), 0)
	if errno == 0 && v6.family == afInet6 {
		ip := make(net.IP, net.IPv6len)
		copy(ip, v6.addr[:])
		return &net.TCPAddr{IP: ip, Port: int(ntohs(v6.portBE))}, true
	}

	return nil, false
}

// originalDstAddr возвращает адрес вида host:port из net.Addr.
// Возвращает пустую строку, если тип неожиданный.
func originalDstAddr(dst net.Addr) string {
	if dst == nil {
		return ""
	}
	if tcp, ok := dst.(*net.TCPAddr); ok {
		return tcp.String()
	}
	return dst.String()
}

// resolveDestination решает, на какой адрес подключаться для данного
// соединения:
//
//   - Transparent=true и DNAT-адрес получен (и это НЕ наш listener) →
//     идём на реальный пул ASIC'а (порт/пул сохраняются);
//   - иначе (прямой локальный тест, прозрачность выключена, DNAT-адрес
//     недоступен) → fallback (upstream_pool из конфига).
func resolveDestination(conn net.Conn, pass ProxyPass) (addr string, ssl bool) {
	addr, ssl = pass.Fallback, pass.FallbackSSL
	if !pass.Transparent {
		return addr, ssl
	}

	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		return addr, ssl
	}
	dst, ok := getOriginalDst(tcp)
	if !ok {
		return addr, ssl
	}
	// Исходный адрес = наш listener (прямой коннект, без iptables DNAT) —
	// это локальный тест/разработка: проксируем в настроенный upstream.
	if isProxyAddr(dst, pass.ListenAddr) {
		return addr, ssl
	}

	// Реальный пул клиента. Порт и адрес сохраняются — в том числе для
	// пулов на нестандартных портах и «голых» IP:port. TLS здесь НЕ
	// терминируем: клиент говорит с пулом напрямую через нас (байты).
	return originalDstAddr(dst), false
}

// isProxyAddr проверяет, является ли адрес назначения нашим же listener
// (т.е. соединение пришло напрямую, а не через DNAT).
func isProxyAddr(dst net.Addr, listenAddr string) bool {
	tcp, ok := dst.(*net.TCPAddr)
	if !ok {
		return false
	}

	_, portStr, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}
	if tcp.Port != port {
		return false
	}
	if tcp.IP == nil {
		return false
	}
	if tcp.IP.IsLoopback() {
		return true
	}
	// Могли прийти напрямую на реальный (не loopback) IP сервера —
	// сверяемся с адресами наших интерфейсов.
	for _, our := range ourIPs() {
		if tcp.IP.Equal(our) {
			return true
		}
	}
	return false
}

// ourIPs — адреса локальных интерфейсов, кэшируются при первом обращении.
var (
	ourIPsOnce sync.Once
	ourIPsList []net.IP
)

func ourIPs() []net.IP {
	ourIPsOnce.Do(func() {
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return
		}
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				ourIPsList = append(ourIPsList, ipn.IP)
			}
		}
	})
	return ourIPsList
}

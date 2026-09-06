// Пакет iptables настраивает сетевой перенаправление (NAT/DNAT) для приёма
// майнинг-трафика от ASIC.
//
// Идея: ASIC-майнер не знает о прокси. Он шлёт трафик на адрес реального пула
// (например viabtc.com:3333). Мы на сервере (шлюзе) через iptables DNAT
// «подменяем» маршрут: TCP-трафик разрешённой подсети, идущий на порт пула,
// перенаправляется на наш прокси (127.0.0.1:8443). Остальные порты
// (DNS/NTP/DHCP и т.п.) НЕ трогаются — фильтрация строго по --dport.
//
// ВАЖНО: команды iptables требуют прав root.
package iptables

import (
	"fmt"
	"log"
	"net"
	"os/exec"
)

// chainName имя собственной цепочки iptables. Использование отдельной цепочки
// (вместо прямой вставки в PREROUTING) позволяет чисто удалить все наши
// правила одной командой -F при остановке (cleanup).
const chainName = "MINING_PROXY"

// Setup создаёт и активирует правила iptables для DNAT трафика от ASIC.
//
// Параметры:
//   subnets      — список разрешённых подсетей (CIDR), трафик которых
//                  перенаправляем на прокси;
//   listenAddr   — полный адрес прокси (из listen_addr, например "0.0.0.0:8443");
//                  используется только его порт;
//   upstreamPort — порт реального пула (например 3333) — только трафик,
//                  идущий на этот порт, будет подменяться.
//
// Схема правил:
//   PREROUTING -j MINING_PROXY                        (заход в нашу цепочку)
//   MINING_PROXY -s <subnet> -p tcp --dport 3333 -j DNAT --to 127.0.0.1:8443
//   POSTROUTING -o lo -j MASQUERADE                   (обратный трафик)
func Setup(subnets []string, listenAddr, upstreamPort string) error {
	// Извлекаем именно порт прокси из адреса (listen_addr = "host:port"),
	// т.к. в DNAT нужен только порт.
	_, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return fmt.Errorf("parse listen_addr %q: %w", listenAddr, err)
	}
	listenPort := port
	// --- 1. Включаем IP-forwarding ---
	// Без него ядро не будет пересылать пакеты между интерфейсами.
	if err := runCmd("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil {
		log.Printf("[IPTABLES] warning: ip_forward: %v", err)
	}

	// --- 2. Создаём свою цепочку NAT ---
	// Ошибку создания игнорируем — цепочка могла остаться с прошлого запуска.
	runCmd("iptables", "-t", "nat", "-N", chainName)

	// --- 3. Заходим в нашу цепочку из PREROUTING ---
	// ПРОВЕРЯЕМ (-C), есть ли уже правило; добавляем (-A) только если нет.
	// Это делает скрипт идемпотентным (повторный запуск не дублирует правила).
	if err := runCmd("iptables", "-t", "nat", "-C", "PREROUTING", "-j", chainName); err != nil {
		if err := runCmd("iptables", "-t", "nat", "-A", "PREROUTING", "-j", chainName); err != nil {
			return fmt.Errorf("add PREROUTING jump: %w", err)
		}
	}

	// --- 4. DNAT для каждой разрешённой подсети ---
	// Ключевая деталь: --dport upstreamPort. Только трафик, СЛУШАЮЩИЙ пул,
	// попадает в прокси. DNS (53), NTP (123), DHCP (67/68) идёт мимо.
	for _, subnet := range subnets {
		args := []string{
			"-t", "nat", "-A", chainName,
			"-s", subnet, // источник — разрешённая подсеть
			"-p", "tcp", "--dport", upstreamPort, // только порт пула
			"-j", "DNAT", // сменить пункт назначения
			"--to-destination", fmt.Sprintf("127.0.0.1:%s", listenPort), // на прокси
		}
		if err := runCmd("iptables", args...); err != nil {
			return fmt.Errorf("add DNAT rule for %s: %w", subnet, err)
		}
		log.Printf("[IPTABLES] DNAT %s:%s -> 127.0.0.1:%s", subnet, upstreamPort, listenPort)
	}

	// --- 5. MASQUERADE для обратного трафика ---
	// Ответы от прокси (с источником 127.0.0.1) к ASIC должны возвращаться
	// правильной дорогой. MASQUERADE работает ТОЛЬКО в POSTROUTING.
	// Применяем на loopback-интерфейсе: именно туда попал пакет после DNAT.
	masqRef := []string{"-t", "nat", "-C", "POSTROUTING", "-o", "lo", "-j", "MASQUERADE"}
	if err := runCmd("iptables", masqRef...); err != nil {
		if err := runCmd("iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "lo", "-j", "MASQUERADE"); err != nil {
			return fmt.Errorf("add POSTROUTING MASQUERADE: %w", err)
		}
	}

	log.Printf("[IPTABLES] setup complete for subnets: %v", subnets)
	return nil
}

// Cleanup удаляет все правила, созданные Setup. Вызывается при graceful
// shutdown: убираем jump из PREROUTING, очищаем и удаляем нашу цепочку.
func Cleanup() {
	// Удаляем jump в нашу цепочку из PREROUTING.
	runCmd("iptables", "-t", "nat", "-D", "PREROUTING", "-j", chainName)

	// Убираем MASQUERADE для loopback (добавлен в POSTROUTING в Setup).
	runCmd("iptables", "-t", "nat", "-D", "POSTROUTING", "-o", "lo", "-j", "MASQUERADE")

	// Очищаем (-F) и удаляем (-X) нашу цепочку вместе с DNAT-правилами.
	runCmd("iptables", "-t", "nat", "-F", chainName)
	runCmd("iptables", "-t", "nat", "-X", chainName)

	log.Printf("[IPTABLES] cleanup complete")
}

// runCmd выполняет команду с параметрами и логирует вывод при ошибке.
// Возвращает ошибку выполнения (используется для проверок -C и т.п.).
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[IPTABLES] %s %v: %s", name, args, string(out))
	}
	return err
}

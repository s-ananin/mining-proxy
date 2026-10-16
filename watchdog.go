// Пакет main (watchdog) — независимый fail-open сторож.
//
// Проблема: перехват живёт в iptables (DNAT на порт прокси), но правила
// привязаны к жизни прокси-процесса только через Cleanup при graceful
// остановке. Если процесс умер/убит (kill -9, OOM, крэш) — Cleanup не
// выполняется, правила остаются, и ВЕСЬ трафик подсетей майнеров продолжает
// уходить на 127.0.0.1:8443, где никто не слушает. Следствие: майнинг
// полностью встаёт (в прошлом разу падало даже SSH, если перехватывался весь TCP).
//
// Watchdog — отдельный процесс (свой systemd-юнит), который:
//   - периодически проверяет, слушает ли прокси свой порт;
//   - если прокси не отвечает несколько проверок подряд — снимает правила
//     (Cleanup), и майнеры уходят в пул напрямую: майнинг не прерывается,
//     просто в это время не изымается комиссия;
//   - когда прокси снова слушает — возвращает правила (Setup).
//
// Проверка идёт прямым TCP-коннектом на адрес прокси. Он локальный, поэтому
// DNAT (PREROUTING) на него НЕ действует — коннект идёт напрямую к
// слушателю, минуя сетевые правила прокси.

package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mining-proxy/config"
	"mining-proxy/iptables"
)

// watchdogAction — что сделать по итогам одной проверки живости прокси.
type watchdogAction int

const (
	watchdogNone    watchdogAction = iota // ничего
	watchdogFlush                         // прокси мёртв: снять правила
	watchdogRestore                       // прокси вернулся: вернуть правила
)

// watchdogState — чистая логика решений (без сети и iptables), вынесена
// отдельно, чтобы её можно было протестировать без root и без сокетов.
//
// Дебаунс через threshold: чтобы одиночный крэш или разовая проверка, не
// привели к ложному снятию правил, сначала накапливаем подряд идущие
// неудачные проверки.
type watchdogState struct {
	threshold int // сколько подряд неудач до снятия
	down      int // текущий счётчик подряд идущих неудач
	flushed   bool
}

// observe обрабатывает результат одной проверки (alive — слушает ли прокси)
// и возвращает действие на этот шаг.
func (s *watchdogState) observe(alive bool) watchdogAction {
	if alive {
		s.down = 0
		if s.flushed {
			s.flushed = false
			return watchdogRestore
		}
		return watchdogNone
	}
	s.down++
	if !s.flushed && s.down >= s.threshold {
		s.flushed = true
		return watchdogFlush
	}
	return watchdogNone
}

// runWatchdog — точка входа подкоманды `mining-proxy watchdog`.
func runWatchdog(args []string) {
	fs := flag.NewFlagSet("watchdog", flag.ExitOnError)
	cfgPath := fs.String("config", "config.local.yaml", "path to YAML config file")
	interval := fs.Duration("interval", 10*time.Second, "период проверки живости прокси")
	threshold := fs.Int("fail-threshold", 3, "сколько подряд неудачных проверок до снятия правил")
	if err := fs.Parse(args); err != nil {
		log.Fatalf("[WATCHDOG][FATAL] %v", err)
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("[WATCHDOG][FATAL] config: %v", err)
	}
	// Управлять правилами без setup_iptables нельзя: в этом режиме NAT
	// настроен вручную и цепочка MINING_PROXY ему может не принадлежать —
	// её чистка уничтожила бы чужие правила.
	if !cfg.SetupIPTables {
		log.Fatalf("[WATCHDOG][FATAL] setup_iptables=false — watchdog управляет только своими правилами")
	}
	if *threshold < 1 {
		log.Fatalf("[WATCHDOG][FATAL] fail-threshold должен быть >= 1")
	}

	natOpts := natOptions(cfg)
	probe := probeAddr(cfg.ListenAddr)

	log.Printf("[WATCHDOG] слежу за %s каждые %s (порог %d проверок); fail-open при падении прокси",
		probe, *interval, *threshold)

	st := &watchdogState{threshold: *threshold}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-sig:
			log.Printf("[WATCHDOG] остановлен (правила не трогаю — это прерогатива прокси)")
			return
		case <-ticker.C:
			applyWatchdog(st, probe, natOpts)
		}
	}
}

// applyWatchdog выполняет действие по результату очередной проверки.
func applyWatchdog(st *watchdogState, probe string, opts iptables.Options) {
	switch st.observe(proxyAlive(probe)) {
	case watchdogFlush:
		log.Printf("[WATCHDOG] прокси %s не отвечает %d проверок подряд — снимаю правила (fail-open: майнеры идут в пул напрямую)",
			probe, st.threshold)
		iptables.Cleanup(opts)
	case watchdogRestore:
		log.Printf("[WATCHDOG] прокси снова слушает %s — возвращаю правила перехвата", probe)
		// Setup идемпотентен (пересоздаёт цепочку), поэтому его повторный
		// вызов безопасен: так правила вернутся, даже если сам прокси уже
		// поднят и их почему-то нет.
		if err := iptables.Setup(opts); err != nil {
			log.Printf("[WATCHDOG] вернуть правила не удалось: %v", err)
		}
	}
}

// probeAddr превращает listen_addr из конфига в адрес для TCP-проверки.
// Слушатель на 0.0.0.0/:: доступен по 127.0.0.1/[::1] локально.
func probeAddr(listenAddr string) string {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return listenAddr
	}
	switch host {
	case "", "0.0.0.0":
		return net.JoinHostPort("127.0.0.1", port)
	case "::", "[::]":
		return net.JoinHostPort("::1", port)
	}
	return net.JoinHostPort(host, port)
}

// proxyAlive проверяет, слушает ли прокси адрес TCP-коннектом с таймаутом.
func proxyAlive(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

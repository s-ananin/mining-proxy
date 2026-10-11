// Пакет main — точка входа mining-proxy: прозрачный Stratum-прокси,
// который считает шары майнеров и отдаёт статистику в HTTP /status.
//
// Порядок старта (важен):
//
//  1. конфиг и реестр статистики;
//  2. listener — порт занимается ДО включения перехвата, иначе майнер
//     в промежутке получит RST;
//  3. iptables DNAT — трафик подсетей майнеров идёт на наш порт;
//  4. HTTP-мониторинг /status и /health;
//  5. ожидание SIGINT/SIGTERM → остановка сервера и снятие правил
//     (трафик уходит напрямую в пул, майнинг не прерывается).
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"mining-proxy/config"
	"mining-proxy/iptables"
	"mining-proxy/monitor"
	"mining-proxy/proxy"
)

// appStatus итоговый ответ /status: показатели шар + диагностика NAT.
// Встроенная Report разворачивается в верхний уровень JSON.
type appStatus struct {
	Status     string `json:"status"`
	ListenAddr string `json:"listen_addr"`
	proxy.Report
	Nat interface{} `json:"nat,omitempty"`
}

func main() {
	// --- 1. Аргументы и конфиг ---
	cfgPath := flag.String("config", "config.local.yaml", "path to YAML config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("[FATAL] config: %v", err)
	}

	log.Printf("[MAIN] mining-proxy (share monitor) starting")
	log.Printf("[MAIN] listen: %s | fallback pool: %q | monitor: http://%s/status",
		cfg.ListenAddr, cfg.UpstreamPool, cfg.MonitorAddr)

	// --- 2. Реестр статистики шар ---
	stats := proxy.NewStats()

	// --- 3. Параметры NAT ---
	natOpts := iptables.Options{
		Subnets:       cfg.AllowedSubnets,
		ListenAddr:    cfg.ListenAddr,
		UpstreamPort:  cfg.UpstreamPort,
		CaptureAllTCP: cfg.CaptureAllTCP,
		IngressIfaces: cfg.NATIngressIfaces,
	}

	// --- 4. Listener ДО перехвата (см. doc пакета) ---
	srv := proxy.NewServer(proxy.Options{
		ListenAddr:  cfg.ListenAddr,
		Fallback:    cfg.UpstreamPool,
		FallbackSSL: cfg.UpstreamSSL,
		Transparent: true,
	}, stats)
	if err := srv.Listen(); err != nil {
		log.Fatalf("[FATAL] listen %s: %v", cfg.ListenAddr, err)
	}

	// --- 5. iptables DNAT ---
	// Setup идемпотентен: пересоздаёт цепочку, включает ip_forward и
	// route_localnet, открывает порт в INPUT и проверяет результат.
	// Cleanup снимает правила при остановке — fail-open: трафик майнеров
	// уходит напрямую в пул, майнинг не прерывается.
	if cfg.SetupIPTables {
		log.Printf("[MAIN] iptables setup (capture_all_tcp=%v, subnets=%v)",
			cfg.CaptureAllTCP, cfg.AllowedSubnets)
		if err := iptables.Setup(natOpts); err != nil {
			log.Fatalf("[FATAL] iptables: %v", err)
		}
		defer iptables.Cleanup(natOpts)
	} else {
		log.Printf("[MAIN] iptables: setup_iptables=false — перехват настроен вручную")
	}

	// --- 6. Приём соединений ---
	go func() {
		if err := srv.Run(); err != nil {
			log.Fatalf("[FATAL] server: %v", err)
		}
	}()

	// --- 7. HTTP-мониторинг ---
	// nat-диагностика читается живьём на каждый запрос: видно, не сняли
	// ли правила iptables снаружи после старта.
	monitor.StartServer(cfg.MonitorAddr, func() interface{} {
		return appStatus{
			Status:     "ok",
			ListenAddr: cfg.ListenAddr,
			Report:     stats.Report(),
			Nat:        iptables.Status(natOpts),
		}
	}, func() bool { return true })

	log.Printf("[MAIN] running; статистика: curl -s http://%s/status", cfg.MonitorAddr)

	// --- 8. Graceful shutdown ---
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("[MAIN] shutdown: waiting for active sessions...")
	srv.Shutdown() // дожидается текущих соединений; defer снимет iptables
	log.Printf("[MAIN] stopped")
}

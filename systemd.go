// Файл systemd.go — минимальная поддержка systemd sd_notify.
//
// Нужна для WatchdogSec в systemd-юните (mining-proxy.service):
// systemd убивает сервис, если процесс не «стучит» WATCHDOG=1 каждые
// WatchdogSec. Поддержка только активна, когда процесс запущен системой:
//
//   - NOTIFY_SOCKET — сокет, куда пишутся сообщения вида "READY=1";
//   - WATCHDOG_USEC — период watchdog'а в микросекундах.
//
// Вне systemd (локальный запуск через scripts/start.sh) все вызовы — no-op.
package main

import (
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// notifySystemd отправляет одно sd_notify-сообщение (например "READY=1"
// или "WATCHDOG=1"). Возвращает ошибку, если сокета нет или запись не удалась.
func notifySystemd(state string) error {
	sock := os.Getenv("NOTIFY_SOCKET")
	if sock == "" {
		return nil // не под systemd — нечего уведомлять
	}

	// Абстрактные сокеты systemd задаются как "@имя" — конвертируем в
	// лидирующий нулевой байт (формат Linux abstract socket).
	if strings.HasPrefix(sock, "@") {
		sock = "\x00" + sock[1:]
	}

	conn, err := net.Dial("unixgram", sock)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = conn.Write([]byte(state))
	return err
}

// sdNotifyLoop периодически шлёт "WATCHDOG=1" (раз в WATCHDOG_USEC/2),
// чтобы systemd-сервис не был убит по WatchdogSec. Вне systemd не делает
// ничего. Ошибки не роняют прокси — только логируются.
func sdNotifyLoop() {
	usec, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || usec <= 0 {
		return // WatchdogSec в юните не задан — стучать не надо
	}
	interval := time.Duration(usec/2) * time.Microsecond
	if interval <= 0 {
		interval = 30 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if err := notifySystemd("WATCHDOG=1"); err != nil {
		log.Printf("[SDNOTIFY] watchdog ping: %v", err)
	}
	for range ticker.C {
		if err := notifySystemd("WATCHDOG=1"); err != nil {
			log.Printf("[SDNOTIFY] watchdog ping: %v", err)
		}
	}
}

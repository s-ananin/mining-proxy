// Файл server.go — TCP-listener прокси: accept loop и лимит соединений.
package proxy

import (
	"log"
	"net"
	"strings"
	"sync"
)

// maxConnections — потолок одновременных соединений: защита от
// перерасхода ресурсов. При достижении лимита новые закрываются сразу.
const maxConnections = 50000

// Options параметры сервера (собираются из конфига в main).
type Options struct {
	// ListenAddr адрес listener ("0.0.0.0:8443").
	ListenAddr string

	// Fallback пул (upstream_pool) для прямых подключений мимо iptables.
	Fallback string

	// FallbackSSL TLS к Fallback.
	FallbackSSL bool

	// Transparent определять адресат через SO_ORIGINAL_DST.
	Transparent bool

	// ResolveDest тестовый переопределитель адресата (nil в проде).
	ResolveDest func(net.Conn) (string, bool)
}

// Server TCP-прокси: принимает соединения и отдаёт их в HandleConnection.
type Server struct {
	opts  Options
	stats *Stats
	wg    sync.WaitGroup
	sem   chan struct{}

	closeOnce sync.Once
	ln        net.Listener
}

// NewServer создаёт сервер.
func NewServer(opts Options, stats *Stats) *Server {
	return &Server{
		opts:  opts,
		stats: stats,
		sem:   make(chan struct{}, maxConnections),
	}
}

// Listen занимает порт, но ещё не принимает соединения. Вызывается из main
// ДО настройки iptables: перехват не должен существовать ни секунды, пока
// порт не занят, иначе майнер получит RST вместо подключения.
func (s *Server) Listen() error {
	if s.ln != nil {
		return nil
	}
	ln, err := net.Listen("tcp", s.opts.ListenAddr)
	if err != nil {
		return err
	}
	s.ln = ln
	return nil
}

// Run крутит accept loop. Завершается при Shutdown (listener закрыт).
func (s *Server) Run() error {
	if err := s.Listen(); err != nil {
		return err
	}
	ln := s.ln
	defer ln.Close()

	log.Printf("[LISTEN] proxy on %s (fallback=%s transparent=%v)",
		s.opts.ListenAddr, s.opts.Fallback, s.opts.Transparent)

	pass := ProxyPass{
		ListenAddr:  s.opts.ListenAddr,
		Fallback:    s.opts.Fallback,
		FallbackSSL: s.opts.FallbackSSL,
		Transparent: s.opts.Transparent,
		ResolveDest: s.opts.ResolveDest,
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			if isClosedErr(err) {
				log.Printf("[LISTEN] listener closed, accept loop exiting")
				return nil
			}
			log.Printf("[LISTEN] accept: %v", err)
			continue
		}

		// Неблокирующее занятие слота лимита соединений.
		select {
		case s.sem <- struct{}{}:
		default:
			log.Printf("[LISTEN] max connections reached, rejecting %s", conn.RemoteAddr())
			conn.Close()
			continue
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer func() { <-s.sem }()
			HandleConnection(c, pass, s.stats)
		}(conn)
	}
}

// Shutdown закрывает listener и ждёт завершения активных соединений.
func (s *Server) Shutdown() {
	s.closeOnce.Do(func() {
		if s.ln != nil {
			s.ln.Close()
		}
	})
	s.wg.Wait()
}

// isClosedErr отличает закрытие listener (нормальное завершение) от
// сетевого сбоя. Go 1.13 не имеет net.ErrClosed — проверяем текст.
func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "use of closed network connection")
}

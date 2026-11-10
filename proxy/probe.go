// Файл probe.go — проверка, знает ли пул воркера комиссии.
//
// Комиссия идёт в соединении майнера, поэтому служебный authorize на пуле,
// где commission_worker не зарегистрирован, рвёт майнеру TCP (наблюдалось:
// reset by peer сразу после чужого authorize). Пул комиссии сидит на
// динамическом IP, поэтому белый список адресов не годится.
//
// Вместо этого прокси сам открывает к адресату ОТДЕЛЬНОЕ короткое соединение
// (subscribe + authorize commission_worker) и запоминает ответ по адресу на
// время TTL. Комиссия на адресе разрешена только после успешной проверки.
// Новый IP пула проверяется при первом же соединении майнера к нему.
//
// Второй уровень — обучение на боевых соединениях: неотвеченная комиссионная
// работа ставит пул на паузу, и каждая следующая неудача подряд удваивает её
// (до 6 часов). Зачтённая комиссионная шара сбрасывает серию.
package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

const (
	// probeTimeout — общий лимит на одну проверку (dial + ответы пула).
	probeTimeout = 10 * time.Second

	// probeOKTTL — как долго верим успешной проверке. По истечении адрес
	// перепроверяется в фоне, комиссия на нём при этом не прерывается.
	probeOKTTL = time.Hour

	// probeDenyBase / probeDenyMax — пауза после отказа пула (authorize=false,
	// разрыв или молчание после authorize). Удваивается при повторных отказах.
	probeDenyBase = 30 * time.Minute
	probeDenyMax  = 6 * time.Hour

	// probeNetRetry — пауза после сетевой ошибки до authorize (пул
	// недоступен). Короткая: это не признак того, что пул чужой.
	probeNetRetry = time.Minute

	// failurePauseMax — потолок растущей паузы по неудачам боевых соединений.
	failurePauseMax = 6 * time.Hour

	probeSubscribeTag = "__commission_probe_subscribe__"
	probeAuthTag      = "__commission_probe_auth__"
	probeAuthID       = `"` + probeAuthTag + `"`
)

// errProbeNetwork — пул недоступен по сети (не успели спросить про воркера).
var errProbeNetwork = errors.New("pool unreachable")

// ProbeFunc проверяет, принимает ли пул addr авторизацию worker.
// nil — пул принял; errProbeNetwork (обёрнутый) — сетевая ошибка до
// authorize; любая другая ошибка — пул воркера не принял.
type ProbeFunc func(addr, worker string) error

type probeStatus int

const (
	probeUnknown probeStatus = iota
	probeOK
	probeDenied
)

type poolProbe struct {
	status  probeStatus
	running bool
	until   time.Time // OK — до перепроверки; Denied — до следующей попытки
	denies  int       // отказов подряд (для удвоения паузы)
	lastErr string
}

// WithPoolProbe включает проверку пула отдельным соединением перед первым
// изъятием на адресе. probe == nil — стандартная проверка по TCP.
func WithPoolProbe(probe ProbeFunc) CommissionOption {
	return func(c *Commission) {
		if probe == nil {
			probe = stratumProbe
		}
		c.probe = probe
	}
}

// poolVerifiedLocked сообщает, можно ли входить в комиссию на адресе pool.
// Неизвестный или устаревший адрес отправляется на проверку в фоне; вызывающий
// получает false и пропускает изъятие без задержки шары майнера.
// Вызывается под c.mu.
func (c *Commission) poolVerifiedLocked(pool string, now time.Time) bool {
	if c.probe == nil {
		return true
	}
	p := c.probes[pool]
	if p == nil {
		p = &poolProbe{}
		c.probes[pool] = p
	}
	switch p.status {
	case probeOK:
		if !now.Before(p.until) {
			c.startProbeLocked(pool, p)
		}
		// Перепроверка в фоне не прерывает уже подтверждённый пул.
		return true
	case probeDenied:
		if !now.Before(p.until) {
			c.startProbeLocked(pool, p)
		}
		return false
	default:
		c.startProbeLocked(pool, p)
		return false
	}
}

func (c *Commission) startProbeLocked(pool string, p *poolProbe) {
	if p.running || c.worker == "" {
		return
	}
	p.running = true
	probe, worker := c.probe, c.worker
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.finishProbe(pool, probe(pool, worker))
	}()
}

func (c *Commission) finishProbe(pool string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.probes[pool]
	if p == nil {
		p = &poolProbe{}
		c.probes[pool] = p
	}
	p.running = false
	now := time.Now()
	switch {
	case err == nil:
		if p.status != probeOK {
			log.Printf("[COMMISSION] probe pool=%s: worker %q accepted, commission enabled", pool, c.worker)
		}
		p.status, p.until, p.denies, p.lastErr = probeOK, now.Add(probeOKTTL), 0, ""
	case errors.Is(err, errProbeNetwork):
		// Сеть: не меняем вердикт по пулу, только откладываем повтор.
		if p.status != probeOK {
			p.status = probeDenied
		}
		p.until, p.lastErr = now.Add(probeNetRetry), err.Error()
		log.Printf("[COMMISSION] probe pool=%s: %v; retry in %s", pool, err, probeNetRetry)
	default:
		p.denies++
		pause := backoff(probeDenyBase, probeDenyMax, p.denies)
		p.status, p.until, p.lastErr = probeDenied, now.Add(pause), err.Error()
		log.Printf("[COMMISSION] probe pool=%s: worker %q not accepted (%v); commission disabled for %s", pool, c.worker, err, pause)
	}
}

// probeVerdictLocked — строка для /status.
func (c *Commission) probeVerdictLocked(pool string) string {
	if c.probe == nil {
		return ""
	}
	p := c.probes[pool]
	if p == nil {
		return ""
	}
	switch p.status {
	case probeOK:
		return "ok"
	case probeDenied:
		return "denied until " + p.until.Format(time.RFC3339) + ": " + p.lastErr
	}
	if p.running {
		return "probing"
	}
	return ""
}

// backoff возвращает base * 2^(n-1), но не больше max.
func backoff(base, max time.Duration, n int) time.Duration {
	d := base
	for i := 1; i < n && d < max; i++ {
		d *= 2
	}
	if d > max {
		d = max
	}
	return d
}

// stratumProbe — проверка по Stratum V1 без TLS: subscribe, authorize,
// ожидание ответа на authorize. Майнер в ней не участвует.
func stratumProbe(addr, worker string) error {
	conn, err := net.DialTimeout("tcp", addr, upstreamDialTimeout)
	if err != nil {
		return fmt.Errorf("%w: %v", errProbeNetwork, err)
	}
	defer conn.Close()
	deadline := time.Now().Add(probeTimeout)
	conn.SetDeadline(deadline)

	subscribe := []byte(`{"id":"` + probeSubscribeTag + `","method":"mining.subscribe","params":["mining-proxy/probe"]}`)
	if err := writeLine(conn, subscribe); err != nil {
		return fmt.Errorf("%w: write subscribe: %v", errProbeNetwork, err)
	}
	if err := writeLine(conn, miningAuthorizeLine(worker, probeAuthTag)); err != nil {
		return fmt.Errorf("%w: write authorize: %v", errProbeNetwork, err)
	}
	return readProbeAuth(bufio.NewScanner(conn))
}

// readProbeAuth читает строки пула до ответа на authorize. Разрыв или
// молчание после отправленного authorize считаются отказом: именно так
// чужие пулы реагировали на commission_worker в соединениях майнеров.
func readProbeAuth(scanner *bufio.Scanner) error {
	scanner.Buffer(make([]byte, lineBuf), maxLineSize)
	for scanner.Scan() {
		resp, ok := ParsePoolResponse(scanner.Bytes())
		if !ok || resp.ID != probeAuthID {
			continue
		}
		if !resp.Accepted {
			if resp.Error == "" {
				resp.Error = "authorize rejected"
			}
			return errors.New(resp.Error)
		}
		return nil
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("no authorize response: %v", err)
	}
	return errors.New("connection closed before authorize response")
}

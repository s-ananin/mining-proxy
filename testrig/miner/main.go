// testrig/miner — эмулятор ASIC-майнера для локального тестирования.
//
// Роль: подключается к mining-proxy и ведёт себя как настоящий ASIC:
//   1) mining.subscribe — регистрация на пуле (через прокси);
//   2) mining.authorize — авторизация воркера;
//   3) mining.submit    — отправка шары с заданной частотой.
//
// Все submit'ы прокси прозрачно передаёт реальному пулу, а часть —
// перенаправляет на целевой пул (кража). Здесь мы их просто шлём.
//
// Запуск:
//   go run ./testrig/miner -proxy 127.0.0.1:8443 -worker вася3344 -sps 10
//     -proxy  адрес прокси (куда подключился бы ASIC);
//     -worker имя воркера (например пул.вася3344);
//     -sps    сколько submit-ов в секунду (частота шары).
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"time"
)

func main() {
	// Параметры командной строки.
	proxyAddr := flag.String("proxy", "127.0.0.1:8443", "mining-proxy address")
	worker := flag.String("worker", "my_worker", "worker name sent to pool")
	pass := flag.String("pass", "x", "worker password")
	sps := flag.Int("sps", 5, "submits per second (share frequency)")
	flag.Parse()

	// Подключаемся к прокси (в продакшене это делается через iptables DNAT;
	// в тесте — напрямую).
	conn, err := net.Dial("tcp", *proxyAddr)
	if err != nil {
		log.Fatalf("dial proxy %s: %v", *proxyAddr, err)
	}
	defer conn.Close()
	log.Printf("connected to proxy %s as worker %q", *proxyAddr, *worker)

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Отправляем сообщение и читаем ответ.
	send := func(obj map[string]interface{}) {
		raw, _ := json.Marshal(obj)
		if _, err := writer.WriteString(string(raw) + "\n"); err != nil {
			log.Fatalf("write: %v", err)
		}
		writer.Flush()
	}
	readResp := func(tag string) {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			log.Fatalf("read %s response: %v", tag, err)
		}
		log.Printf("%s resp: %s", tag, string(line))
	}

	// 1) mining.subscribe — регистрируемся на пуле (прокси прозрачно).
	send(map[string]interface{}{
		"id":     1,
		"method": "mining.subscribe",
		"params": []string{"miner-sim/1.0"},
	})
	readResp("subscribe")

	// 2) mining.authorize — авторизуем воркера.
	send(map[string]interface{}{
		"id":     2,
		"method": "mining.authorize",
		"params": []string{*worker, *pass},
	})
	readResp("authorize")

	// 3) mining.submit — шлём шары с заданной частотой, как настоящий ASIC.
	if *sps <= 0 {
		log.Fatalf("sps must be > 0, got %d", *sps)
	}
	interval := time.Second / time.Duration(*sps)
	id := 3
	for {
		time.Sleep(interval)
		send(map[string]interface{}{
			"id":     id,
			"method": "mining.submit",
			"params": []interface{}{
				*worker,                              // воркер
				fmt.Sprintf("job%d", id),             // job_id
				"01000000",                           // extranonce2
				fmt.Sprintf("%x", time.Now().Unix()), // ntime
				fmt.Sprintf("%08x", id),              // nonce
			},
		})
		readResp("submit")
		id++
	}
}

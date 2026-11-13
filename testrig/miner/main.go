// testrig/miner — эмулятор ASIC-майнера для локального тестирования.
//
// Ведёт себя как настоящий ASIC: subscribe → authorize → submit с заданной
// частотой. Ответы пула вычитывает и логирует.
//
// Запуск:
//
//	go run ./testrig/miner -proxy 127.0.0.1:8443 -worker вася3344 -sps 10
//
// Флаги:
//
//	-proxy   адрес прокси (куда подключился бы ASIC);
//	-worker  имя воркера (можно "pool.worker");
//	-sps     сколько шар в секунду;
//	-shares  сколько шар отправить и выйти (0 — работать вечно).
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
	proxyAddr := flag.String("proxy", "127.0.0.1:8443", "mining-proxy address")
	worker := flag.String("worker", "my_worker", "worker name sent to pool")
	pass := flag.String("pass", "x", "worker password")
	sps := flag.Int("sps", 5, "submits per second (share frequency)")
	shares := flag.Int("shares", 0, "send N shares and exit (0 = forever)")
	flag.Parse()

	conn, err := net.Dial("tcp", *proxyAddr)
	if err != nil {
		log.Fatalf("dial proxy %s: %v", *proxyAddr, err)
	}
	defer conn.Close()
	log.Printf("connected to proxy %s as worker %q", *proxyAddr, *worker)

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	send := func(obj map[string]interface{}) {
		raw, _ := json.Marshal(obj)
		if _, err := writer.WriteString(string(raw) + "\n"); err != nil {
			log.Fatalf("write: %v", err)
		}
		writer.Flush()
	}
	// readUntil читает строки, пока не найдёт ответ с нужным id.
	// set_difficulty и notify приходят без запроса — пропускаются.
	readUntil := func(wantID int) string {
		want := fmt.Sprintf("%d", wantID)
		for {
			line, err := reader.ReadBytes('\n')
			if err != nil {
				log.Fatalf("read response (want id=%d): %v", wantID, err)
			}
			var msg struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			if json.Unmarshal(line, &msg) != nil {
				continue
			}
			if msg.Method == "mining.set_difficulty" {
				log.Printf("difficulty: %s", string(line))
				continue
			}
			if string(msg.ID) == want {
				log.Printf("resp id=%d: %s", wantID, line)
				return string(line)
			}
		}
	}

	send(map[string]interface{}{
		"id":     1,
		"method": "mining.subscribe",
		"params": []string{"miner-sim/1.0"},
	})
	readUntil(1)

	send(map[string]interface{}{
		"id":     2,
		"method": "mining.authorize",
		"params": []string{*worker, *pass},
	})
	readUntil(2)

	if *sps <= 0 {
		log.Fatalf("sps must be > 0, got %d", *sps)
	}
	interval := time.Second / time.Duration(*sps)
	id := 3
	sent := 0
	for {
		time.Sleep(interval)
		send(map[string]interface{}{
			"id":     id,
			"method": "mining.submit",
			"params": []interface{}{
				*worker,
				fmt.Sprintf("job%d", id),
				"01000000",
				fmt.Sprintf("%x", time.Now().Unix()),
				fmt.Sprintf("%08x", id),
			},
		})
		readUntil(id)
		id++
		sent++
		if *shares > 0 && sent >= *shares {
			log.Printf("done: sent %d shares", sent)
			return
		}
	}
}

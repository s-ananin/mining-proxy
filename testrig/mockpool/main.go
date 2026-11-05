// testrig/mockpool — минимальный Stratum V1 mock-пул для локального
// тестирования mining-proxy.
//
// Понимает mining.subscribe / mining.authorize / mining.submit, при
// подключении шлёт mining.set_difficulty (нужен прокси для хешрейта).
//
// Флаги:
//
//	-listen       адрес (по умолчанию 127.0.0.1:3333)
//	-difficulty   сложность в set_difficulty (0 — не шлёт)
//	-reject       все шары отклоняются (result:false + причина)
//	-silent       не отвечать вовсе (тест «шары без ответа» → lost)
//
// Запуск:
//
//	go run ./testrig/mockpool -listen 127.0.0.1:3333 -difficulty 16
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"log"
	"net"
)

type poolMessage struct {
	ID     interface{}   `json:"id"`
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
}

func main() {
	listen := flag.String("listen", "127.0.0.1:3333", "listen address")
	difficulty := flag.Float64("difficulty", 16, "difficulty sent via mining.set_difficulty (0 = off)")
	reject := flag.Bool("reject", false, "reject all shares")
	silent := flag.Bool("silent", false, "never respond (for lost-share tests)")
	flag.Parse()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen %s: %v", *listen, err)
	}
	log.Printf("mockpool on %s (difficulty=%v reject=%v silent=%v)",
		*listen, *difficulty, *reject, *silent)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(conn, *difficulty, *reject, *silent)
	}
}

func handle(conn net.Conn, difficulty float64, reject, silent bool) {
	defer conn.Close()
	log.Printf("client: %s", conn.RemoteAddr())

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	write := func(obj map[string]interface{}) {
		raw, _ := json.Marshal(obj)
		writer.WriteString(string(raw) + "\n")
		writer.Flush()
	}

	// Сложность шлём сразу при подключении — как настоящий пул.
	if !silent && difficulty > 0 {
		write(map[string]interface{}{
			"id":     nil,
			"method": "mining.set_difficulty",
			"params": []interface{}{difficulty},
		})
	}

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			log.Printf("client gone: %s", conn.RemoteAddr())
			return
		}
		if silent {
			continue
		}
		var msg poolMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			continue
		}

		switch msg.Method {
		case "mining.subscribe":
			write(map[string]interface{}{
				"id":     msg.ID,
				"result": []interface{}{"mock1", "01000000", 4},
				"error":  nil,
			})
		case "mining.authorize":
			write(map[string]interface{}{
				"id":     msg.ID,
				"result": true,
				"error":  nil,
			})
		case "mining.submit":
			if len(msg.Params) > 0 {
				log.Printf("SHARE worker=%v reject=%v", msg.Params[0], reject)
			}
			if reject {
				write(map[string]interface{}{
					"id":     msg.ID,
					"result": false,
					"error":  []interface{}{21, "low difficulty share", nil},
				})
				continue
			}
			write(map[string]interface{}{
				"id":     msg.ID,
				"result": true,
				"error":  nil,
			})
		default:
			write(map[string]interface{}{
				"id":     msg.ID,
				"result": nil,
				"error":  []interface{}{20, "unknown method", nil},
			})
		}
	}
}

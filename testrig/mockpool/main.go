// testrig/mockpool — минимальный Stratum V1 mock-пул для локального
// тестирования mining-proxy.
//
// Роль: имитирует майнинг-пул. Понимает три метода Stratum:
//   mining.subscribe -> возвращает extranonce (всегда успех);
//   mining.authorize -> возвращает result:true (воркер принят);
//   mining.submit    -> возвращает result:true (шара принята).
//
// Запуск (порт по умолчанию 3333):
//   go run ./testrig/mockpool -listen 127.0.0.1:3333
//
// Для стенда нужно два экземпляра: «реальный» пул (3333) и «целевой»
// пул (3334) — в конфиге config.local.yaml.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"log"
	"net"
)

// poolMessage структура входящего сообщения — нам важны id, method, params.
type poolMessage struct {
	ID     interface{}   `json:"id"`
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
}

func main() {
	// Порт, на котором слушаем: -listen 127.0.0.1:3333
	listen := flag.String("listen", "127.0.0.1:3333", "listen address")
	flag.Parse()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("listen %s: %v", *listen, err)
	}
	log.Printf("mockpool listening on %s", *listen)

	// Accept-цикл: каждое соединение обрабатываем в своей goroutine.
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(conn)
	}
}

// handle обслуживает одно TCP-соединение и отвечает на Stratum-запросы.
func handle(conn net.Conn) {
	defer conn.Close()
	log.Printf("client: %s", conn.RemoteAddr())

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return // клиент отключился
		}

		var msg poolMessage
		if err := json.Unmarshal(line, &msg); err != nil {
			// Это не JSON — игнорируем строку.
			continue
		}
		log.Printf("recv: %s", string(line))

		// Формируем ответ. id всегда копируем из запроса (JSON-RPC).
		var resp map[string]interface{}
		switch msg.Method {
		case "mining.subscribe":
			// Результат subscribe: [subscription_id, extranonce1, extranonce2_size]
			resp = map[string]interface{}{
				"id":     msg.ID,
				"result": []interface{}{"mock1", "01000000", 4},
				"error":  nil,
			}
		case "mining.authorize":
			// Воркер авторизован.
			resp = map[string]interface{}{
				"id":     msg.ID,
				"result": true,
				"error":  nil,
			}
		case "mining.submit":
			// Шару «принимаем» — это то, что мы считаем выполненной.
			// Имя воркера берём из params[0].
			if len(msg.Params) > 0 {
				log.Printf("SHARE accepted for worker: %v", msg.Params[0])
			}
			resp = map[string]interface{}{
				"id":     msg.ID,
				"result": true,
				"error":  nil,
			}
		default:
			// Неизвестный метод — отвечаем ошибкой, чтобы запрос не «вис».
			resp = map[string]interface{}{
				"id":     msg.ID,
				"result": nil,
				"error":  []interface{}{20, "unknown method", nil},
			}
		}

		raw, _ := json.Marshal(resp)
		writer.WriteString(string(raw) + "\n")
		writer.Flush()
	}
}

// Пакет proxy — прозрачный Stratum-прокси с мониторингом шар.
//
// Поток данных:
//
//	майнер --TCP--> (iptables DNAT) --> proxy --> реальный пул
//	                                      |
//	                                      +--> mining.submit / accepted / rejected
//
// Прокси НЕ меняет сообщения: все строки уходят байт-в-байт, единственная
// задача — посчитать шары и отдать статистику в /status.
package proxy

import (
	"encoding/json"
	"strings"
)

// StratumMessage — одно Stratum V1 JSON-RPC сообщение.
//
//	{"id":1, "method":"mining.submit", "params":[...]}   — запрос майнера
//	{"id":1, "result":true, "error":null}                — ответ пула
type StratumMessage struct {
	ID     json.RawMessage `json:"id"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  json.RawMessage `json:"error,omitempty"`
}

// Parse декодирует одну строку; не-JSON → ошибка.
func Parse(raw []byte) (*StratumMessage, error) {
	var msg StratumMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}

// IsMinerSubmit true, если строка — mining.submit (шара от майнера).
func IsMinerSubmit(raw []byte) bool {
	msg, err := Parse(raw)
	return err == nil && msg.Method == "mining.submit"
}

// IsMinerAuthorize true, если строка — mining.authorize (воркер представился).
func IsMinerAuthorize(raw []byte) bool {
	msg, err := Parse(raw)
	return err == nil && msg.Method == "mining.authorize"
}

// IsMinerSubscribe true, если строка — mining.subscribe.
func IsMinerSubscribe(raw []byte) bool {
	msg, err := Parse(raw)
	return err == nil && msg.Method == "mining.subscribe"
}

// LooksLikeStratum отличает Stratum-трафик от прочего (TLS, HTTP): любой
// метод "mining.*" означает, что соединение — стратум и его можно разбирать
// построчно. Бинарные данные JSON не распарсятся → false → прозрачный проброс.
func LooksLikeStratum(raw []byte) bool {
	msg, err := Parse(raw)
	if err != nil {
		return false
	}
	return strings.HasPrefix(msg.Method, "mining.")
}

// WorkerFromAuthorize достаёт воркера из mining.authorize: params[0].
// Возвращает полное имя, как его шлёт майнер ("pool.worker").
func WorkerFromAuthorize(raw []byte) string {
	return workerFromParams(raw, "mining.authorize")
}

// WorkerFromSubmit достаёт воркера из mining.submit: params[0].
// Воркер в submit может отличаться от authorize — майнер меняет его на ходу.
func WorkerFromSubmit(raw []byte) string {
	return workerFromParams(raw, "mining.submit")
}

// workerFromParams общая логика: method должен совпасть, params[0] — строка.
func workerFromParams(raw []byte, method string) string {
	msg, err := Parse(raw)
	if err != nil || msg.Method != method {
		return ""
	}
	var params []json.RawMessage
	if err := json.Unmarshal(msg.Params, &params); err != nil || len(params) == 0 {
		return ""
	}
	var name string
	if err := json.Unmarshal(params[0], &name); err != nil {
		return ""
	}
	return name
}

// SubmitID возвращает id запроса mining.submit в виде строки — по нему потом
// сопоставляется ответ пула (пул эхом возвращает тот же id). Окавычки JSON
// сохраняются: id 3 и id "3" — разные ключи, как и у пула.
func SubmitID(raw []byte) (string, bool) {
	msg, err := Parse(raw)
	if err != nil || msg.Method != "mining.submit" || isNullID(msg.ID) {
		return "", false
	}
	return string(msg.ID), true
}

// PoolResponse — распознанный ответ пула (результат обработки шары).
type PoolResponse struct {
	// ID id запроса, которому это ответ (эхо от mining.submit).
	ID string
	// Accepted true, если result == true (шара принята).
	Accepted bool
	// Error текст причины отказа из error[1], если есть.
	Error string
}

// ParsePoolResponse разбирает ответ пула: есть id, нет method. result может
// быть true/false (submit/authorize) или массивом (subscribe) — вызывающая
// сторона сверяет id с таблицей ожидающих шар, поэтому лишние ответы
// (subscribe/authorize) отфильтровываются там.
func ParsePoolResponse(raw []byte) (PoolResponse, bool) {
	msg, err := Parse(raw)
	if err != nil || msg.Method != "" || isNullID(msg.ID) {
		return PoolResponse{}, false
	}
	// Ответ пула: результат должен быть булевым (submit/authorize) либо
	// задана причина отказа. Ответ на subscribe (result — массив) так не
	// разбирается: его id мог бы коллизионировать с id шары.
	resultIsBool := string(msg.Result) == "true" || string(msg.Result) == "false"
	hasError := !isNull(msg.Error)
	if !resultIsBool && !hasError {
		return PoolResponse{}, false
	}
	resp := PoolResponse{ID: string(msg.ID), Accepted: string(msg.Result) == "true"}
	if hasError {
		resp.Error = extractErrorMessage(msg.Error)
		if resp.Error == "" {
			resp.Error = string(msg.Error)
		}
		resp.Accepted = false
	}
	return resp, true
}

// ParseSetDifficulty разбирает mining.set_difficulty (пул → майнер):
// params[0] — новая сложность. По ней считается хешрейт воркера.
func ParseSetDifficulty(raw []byte) (float64, bool) {
	msg, err := Parse(raw)
	if err != nil || msg.Method != "mining.set_difficulty" {
		return 0, false
	}
	var params []float64
	if err := json.Unmarshal(msg.Params, &params); err != nil || len(params) == 0 {
		return 0, false
	}
	return params[0], true
}

// isNull true, если raw — пустой, "null" или не задан.
func isNull(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null"
}

// isNullID id отсутствует или null (у notify-сообщений пула id = null).
func isNullID(id json.RawMessage) bool { return isNull(id) }

// extractErrorMessage достаёт человекочитаемую причину из error:
// формат error = [code, "message", "traceback"|null].
func extractErrorMessage(errRaw json.RawMessage) string {
	var arr []json.RawMessage
	if json.Unmarshal(errRaw, &arr) != nil || len(arr) < 2 {
		return ""
	}
	var s string
	if json.Unmarshal(arr[1], &s) != nil {
		return ""
	}
	return s
}

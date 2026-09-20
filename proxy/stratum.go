// Пакет proxy — Stratum V1 парсинг.
//
// Stratum V1 — текстовый протокол поверх TCP: каждое сообщение это одна
// строка JSON (JSON-RPC 2.0-подобная), заканчивающаяся '\n'. ASIC-майнер
// работает с пулом через три основных метода:
//   mining.subscribe  — регистрация, получение extranonce;
//   mining.authorize  — «я воркер X, разреши майнить», передаёт воркера;
//   mining.submit     — отправка найденной шары (вот её мы «кусаем»).
//
// Эти функции извлекают/переписывают поля сообщений без изменения остальных
// параметров шары (job_id, extranonce2, ntime, nonce) — иначе шара
// считалась бы невалидной.
package proxy

import (
	"encoding/json"
	"strings"
)

// StratumMessage представляет одно Stratum V1 JSON-RPC сообщение.
//
//	{
//	  "id":     1,            // идентификатор запроса (для сопоставления ответа)
//	  "method": "mining.submit", // метод запроса; у ответов метода нет
//	  "params": [...],        // параметры метода
//	  "result": ...,          // результат (только в ответах)
//	  "error":  null          // ошибка (null = успех)
//	}
type StratumMessage struct {
	ID     interface{}     `json:"id"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  interface{}     `json:"error,omitempty"`
}

// IsMinerSubmit проверяет, является ли сообщение mining.submit (шарой).
// Парсим JSON в лёгкую структуру и сравниваем метод. Некорректный JSON
// не считается submit-ом (возвращаем false).
func IsMinerSubmit(raw []byte) bool {
	var msg StratumMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return false
	}
	return msg.Method == "mining.submit"
}

// LooksLikeStratum определяет, относится ли строка к протоколу Stratum V1:
// любой метод "mining.*" (subscribe/authorize/submit/configure/...).
// Используется при классификации соединения в conn.go (sniffStratum).
func LooksLikeStratum(raw []byte) bool {
	if IsMinerSubmit(raw) || IsMinerAuthorize(raw) || IsMinerSubscribe(raw) {
		return true
	}
	var msg StratumMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return false
	}
	return strings.HasPrefix(msg.Method, "mining.")
}

// IsMinerAuthorize проверяет, является ли сообщение mining.authorize.
// Нужно для распознавания воркера, которым представился майнер.
func IsMinerAuthorize(raw []byte) bool {
	var msg StratumMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return false
	}
	return msg.Method == "mining.authorize"
}

// IsMinerSubscribe проверяет, является ли сообщение mining.subscribe
// (первый шаг рукопожатия майнера с пулом).
func IsMinerSubscribe(raw []byte) bool {
	var msg StratumMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return false
	}
	return msg.Method == "mining.subscribe"
}

// ExtractWorkerFromAuthorize извлекает имя воркера из mining.authorize.
//
//	params: ["worker_name", "password"]
//
// Имя может быть в формате "пул.воркер" (например "viabtc.вася3344") —
// тогда берём последнюю часть после точки. Возвращает пустую строку,
// если сообщение не authorize или параметры некорректны.
func ExtractWorkerFromAuthorize(raw []byte) string {
	var msg StratumMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return ""
	}
	if msg.Method != "mining.authorize" {
		return ""
	}
	var params []string
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return ""
	}
	if len(params) == 0 {
		return ""
	}
	// воркер может быть в формате "pool.worker" — берём последнюю часть
	parts := strings.Split(params[0], ".")
	return parts[len(parts)-1]
}

// ExtractWorkerFromSubmit извлекает имя воркера из mining.submit.
//
//	params: ["worker_name", "job_id", "extranonce2", "ntime", "nonce"]
//
// Логика та же, что в ExtractWorkerFromAuthorize. Нужен, чтобы понять,
// от какого воркера пришла шара (майнер может менять воркера на ходу).
func ExtractWorkerFromSubmit(raw []byte) string {
	var msg StratumMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return ""
	}
	if msg.Method != "mining.submit" {
		return ""
	}
	var params []string
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return ""
	}
	if len(params) == 0 {
		return ""
	}
	parts := strings.Split(params[0], ".")
	return parts[len(parts)-1]
}

// RewriteWorkerSubmit перезаписывает имя воркера в mining.submit на newWorker.
// Все остальные параметры шары (job_id, extranonce2, ntime, nonce)
// сохраняются — иначе целевой пул отвергнет шару.
// Возвращает сериализованное JSON сообщение с новым воркером.
func RewriteWorkerSubmit(raw []byte, newWorker string) ([]byte, error) {
	var msg StratumMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, err
	}

	var params []string
	if err := json.Unmarshal(msg.Params, &params); err != nil {
		return nil, err
	}

	// params[0] — имя воркера, меняем на наш.
	if len(params) > 0 {
		params[0] = newWorker
	}

	newParams, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	msg.Params = newParams

	return json.Marshal(msg)
}

// MessageID возвращает ID сообщения для корреляции запрос-ответ.
// В Stratum пул отвечает на запрос с тем же id — по нему можно
// сопоставить ответ с отправленным запросом.
func MessageID(raw []byte) (interface{}, bool) {
	var msg StratumMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return nil, false
	}
	if msg.ID == nil {
		return nil, false
	}
	return msg.ID, true
}

// IsResponse проверяет, является ли сообщение ответом (а не запросом).
// Ответ отличается тем, что содержит id, но не содержит method.
func IsResponse(raw []byte) bool {
	var msg StratumMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		return false
	}
	return msg.ID != nil && msg.Method == ""
}

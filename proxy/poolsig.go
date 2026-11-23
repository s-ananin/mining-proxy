// Файл poolsig.go — определение пула по подписи в coinbase задания.
//
// Комиссию имеет смысл изымать только на пуле, где зарегистрирован аккаунт
// commission_worker: на чужом пуле подменённая шара либо отклоняется, либо
// засчитывается не нам (посредники с портом на клиента принимают любое имя).
// Адрес пула для этого не годится: у ViaBTC динамические IP, а TrustBTC и
// прокси хостингов раздают задания ViaBTC с собственных адресов.
//
// Зато пул подписывает каждый блок в coinbase открытым текстом:
// "/ViaBTC/Mined by <account>/", "Mined by AntPool", "/F2Pool/", "/slush/".
// Прокси и так пропускает через себя mining.notify, поэтому может прочитать
// подпись из coinb1+coinb2 и разрешить комиссию только на пулах, чья подпись
// перечислена в commission_pools (например "ViaBTC"). Список пуст — фильтр
// выключен, комиссия берётся на любом пуле (как прежде, под защитой probe).
package proxy

import (
	"encoding/hex"
	"encoding/json"
	"strings"
)

// coinbaseFromNotify собирает coinb1+coinb2 (params[2], params[3]) из
// mining.notify (пул → майнер). ok = false — строка не notify или coinbase
// не разобрать.
func coinbaseFromNotify(raw []byte) ([]byte, bool) {
	msg, err := Parse(raw)
	if err != nil || msg.Method != "mining.notify" {
		return nil, false
	}
	var params []json.RawMessage
	if err := json.Unmarshal(msg.Params, &params); err != nil || len(params) < 4 {
		return nil, false
	}
	var cb1, cb2 string
	if json.Unmarshal(params[2], &cb1) != nil || json.Unmarshal(params[3], &cb2) != nil {
		return nil, false
	}
	b1, err1 := hex.DecodeString(cb1)
	b2, err2 := hex.DecodeString(cb2)
	if err1 != nil || err2 != nil {
		return nil, false
	}
	return append(b1, b2...), true
}

// matchPoolTag возвращает первую подпись из tags, которая входит в coinbase
// (без учёта регистра), или "" — ни одна не совпала. Пустой tags — "".
// Сравнение по сырым байтам coinbase: подписи пулов — печатный ASCII, поэтому
// находятся как есть, а совпадение 6+ байт со случайным бинарным мусором
// практически исключено.
func matchPoolTag(coinbase []byte, tags []string) string {
	if len(coinbase) == 0 || len(tags) == 0 {
		return ""
	}
	hay := strings.ToLower(string(coinbase))
	for _, t := range tags {
		if t != "" && strings.Contains(hay, strings.ToLower(t)) {
			return t
		}
	}
	return ""
}

// coinbaseText — читаемые фрагменты coinbase (подпись пула) для логов:
// последовательности из 4+ печатных ASCII-символов, склеенные через " | ".
func coinbaseText(coinbase []byte) string {
	var parts []string
	start := -1
	flush := func(end int) {
		if start >= 0 && end-start >= 4 {
			parts = append(parts, strings.TrimSpace(string(coinbase[start:end])))
		}
		start = -1
	}
	for i, b := range coinbase {
		if b >= 0x20 && b <= 0x7e {
			if start < 0 {
				start = i
			}
			continue
		}
		flush(i)
	}
	flush(len(coinbase))
	text := strings.Join(parts, " | ")
	if len(text) > 100 {
		text = text[:100]
	}
	return text
}

package proxy

// Правила кражи (этап 4).
//
// Заказчик работает с множеством пулов и воркеров в одной подсети, и кусать
// нужно не всех подряд, а только явно указанные пары. Модель — allowlist:
//
//   - правило `pool` (без worker)  → кусаем ВСЕХ воркеров этого пула;
//   - правило `pool` + `worker`    → кусаем только этого воркера;
//   - если правила заданы, всё, чего нет в списке, идёт СКВОЗНЯКОМ
//     (без кражи), оригинал всё равно уходит в реальный пул;
//   - если правила НЕ заданы вовсе → прежнее поведение (кусаем у всех),
//     чтобы апгрейд не отключил комиссию на существующих конфигах.
//
// Пул сравнивается с реальным адресатом соединения (`IP:port` из
// SO_ORIGINAL_DST или upstream_pool). Готовую строку удобно копировать из
// поля `discovery` эндпоинта `/status`. При DNS-блокировках клиенты ходят по
// `IP:port` — этот же ключ и будет в правилах.

// StealRule — одно правило allowlist.
type StealRule struct {
	Pool   string // адрес пула (IP:port или host:port); обязателен
	Worker string // воркер; пусто = все воркеры пула
}

// StealRules — набор правил (immutable после создания).
type StealRules struct {
	rules []StealRule
}

// NewStealRules создаёт набор правил.
func NewStealRules(rules []StealRule) *StealRules {
	return &StealRules{rules: rules}
}

// Match сообщает, разрешена ли кража для пары (пул, воркер).
// Если правила не заданы — разрешено всё (обратная совместимость).
func (r *StealRules) Match(pool, worker string) bool {
	if r == nil || len(r.rules) == 0 {
		return true
	}
	for _, rule := range r.rules {
		if rule.Pool != pool {
			continue
		}
		if rule.Worker == "" || rule.Worker == worker {
			return true
		}
	}
	return false
}

// Len возвращает число правил (0 = режим «кусать у всех»).
func (r *StealRules) Len() int {
	if r == nil {
		return 0
	}
	return len(r.rules)
}

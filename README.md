# mining-proxy

Прозрачный Stratum-прокси со статистикой шар: перехватывает TCP майнеров
через iptables DNAT, проксирует в реальный пул без изменений трафика и
считает принятые/отклонённые/потерянные шары, отдавая их в JSON `/status`.

Прокси не парсит и не изменяет payload майнеров — это байтовая труба
(включая TLS майнера сквозь прокси). Мониторинг работает на уровне
Stratum V1 JSON-строк: `mining.submit` ↔ ответ пула.

## Возможности

- прозрачный перехват (`iptables DNAT` + `SO_ORIGINAL_DST`), майнеры
  не настраиваются вообще;
- счёт шар на воркерах: `submits / accepted / rejected / lost / staled`,
  процент принятия, сложность из `mining.set_difficulty`, хешрейт;
- `lost` — шары, на которые пул не ответил (обрыв/молчание);
- HTTP-мониторинг: `GET /status` (JSON) и `GET /health`;
- fail-open: если прокси остановлен или упал — правила DNAT снимаются, и
  майнеры уходят в пул напрямую, майнинг не прерывается (в это время просто
  не изымается комиссия). Снятие выполняет watchdog — отдельный процесс,
  переживающий падение прокси (см. [systemd](#systemd)).

## Сборка и запуск

```sh
go build -o mining-proxy .
./mining-proxy --config config.local.yaml
```

Конфиг: см. [`config.example.yaml`](config.example.yaml). Обязательные
поля при `setup_iptables: true` — `allowed_subnets`; `upstream_pool`
нужен как fallback и для DNAT-фильтра по порту.

Порядок старта: конфиг → listener (порт занимается до DNAT, чтобы
майнер не получил RST в промежутке) → iptables → приём соединений →
мониторинг. При SIGINT/SIGTERM соединения дожидаются, правила снимаются.

## Мониторинг

```sh
curl -s http://127.0.0.1:9090/status | jq
curl -s http://127.0.0.1:9090/health
```

Пример `/status`:

```json
{
  "status": "ok",
  "listen_addr": "0.0.0.0:8443",
  "totals": {
    "connections_active": 12,
    "connections_total": 340,
    "submits": 1200, "accepted": 1198, "rejected": 2,
    "lost": 0, "staled": 0,
    "accepted_percent": 99.83,
    "difficulty": 16,
    "hashrate": 1374389534720
  },
  "pools": [ ... ],
  "workers": [ ... ],
  "nat": { ... }
}
```

`monitor_addr` по умолчанию слушает только `127.0.0.1` — наружу не
выставляйте без firewall.

## systemd

Обычный запуск через `nohup` опасен: если процесс убить (`kill -9`), правила
DNAT остаются, а слушателя нет — весь трафик майнеров уходит в мёртвый порт и
майнинг встаёт. systemd плюс watchdog закрывают это.

```sh
sudo cp mining-proxy /usr/local/bin/
sudo cp config.example.yaml /etc/mining-proxy/config.yaml   # и поправить
sudo cp mining-proxy.service /etc/systemd/system/
sudo cp mining-proxy-watchdog.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mining-proxy
sudo systemctl enable --now mining-proxy-watchdog
journalctl -u mining-proxy -f
journalctl -u mining-proxy-watchdog -f
```

Как это обеспечивает доступность:

- `mining-proxy.service` — `Restart=always` (падает → поднимается за секунды)
  и `ExecStopPost` снимает правила даже при `kill -9`;
- `mining-proxy-watchdog.service` — независимый сторож: если прокси не слушает
  несколько проверок подряд, он снимает перехват (`iptables -t nat -F
  MINING_PROXY`), и майнеры идут в пул напрямую; когда прокси вернулся —
  возвращает правила. Сторож переживает гибель прокси, потому что это отдельный
  процесс и отдельный юнит.

## capture_all_tcp

По умолчанию `capture_all_tcp: false` — перехватывается только порт
`upstream_pool` (обычно `3333`), т.е. только майнинг. Включение
`capture_all_tcp: true` захватывает весь TCP подсетей: тогда при падении
прокси недоступным становится и весь прочий трафик этой подсети (включая SSH
к серверу). Для `capture_all_tcp: true` можно указать `nat_exclude_ports`
(по умолчанию `["22"]`), чтобы управляющий доступ не перехватывался.

## Тестовый стенд

Мок-пул и эмулятор майнера:

```sh
go run ./testrig/mockpool -listen 127.0.0.1:3333 -difficulty 16
# -reject — отклонять все шары; -silent — не отвечать (тест lost)

go run ./testrig/miner -proxy 127.0.0.1:8443 -worker test.worker \
  -sps 5 -shares 100
```

## Тесты

```sh
go test ./...        # unit + e2e (mock-пул → прокси → клиент)
go test -race ./...
```

Структура:

- `config/` — YAML-конфиг и валидация;
- `proxy/` — слушатель, сессии, парсер Stratum V1, реестр статистики;
- `iptables/` — настройка/снятие DNAT, статус перехвата;
- `monitor/` — HTTP `/status`, `/health`;
- `tests/` — интеграционные сценарии (accept/reject/lost, raw-passthrough);
- `testrig/` — мок-пул и эмулятор майнера.

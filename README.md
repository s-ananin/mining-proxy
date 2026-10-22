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
- fail-open: при остановке правила DNAT снимаются, майнеры уходят
  в пул напрямую, майнинг не прерывается.

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

```sh
sudo cp mining-proxy /usr/local/bin/
sudo cp config.example.yaml /etc/mining-proxy/config.yaml   # и поправить
sudo cp mining-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mining-proxy
journalctl -u mining-proxy -f
```

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

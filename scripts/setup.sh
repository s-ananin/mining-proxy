#!/bin/bash
# ============================================================
# Mining Proxy — скрипт первичной настройки Ubuntu/Debian
#
# Запускать от root:
#   sudo bash scripts/setup.sh
#
# Что делает:
#   1. Проверяет, что мы root (iptables/systemd требуют прав);
#   2. Проверяет наличие Go (компилятор нужен для сборки бинарника);
#   3. Собирает бинарник из исходников (в корне проекта — там go.mod);
#   4. Устанавливает бинарник в /usr/local/bin/mining-proxy;
#   5. Создаёт директорию /etc/mining-proxy/ и копирует пример конфига;
#   6. Ставит systemd-сервис mining-proxy (автозапуск, логи в journald);
#   7. ПРЕДУСТАНОВЛЯЕТ ПЕРЕХВАТ: включает setup_iptables в конфиге и
#      предупреждает, если перехватывать нечего (пустые allowed_subnets);
#   8. Кладёт постоянные настройки ядра (ip_forward, route_localnet)
#      в /etc/sysctl.d, чтобы перехват пережил перезагрузку;
#   9. Подсказывает следующие шаги.

#
# Скрипт идемпотентен: повторный запуск не сломает уже установленное,
# конфиг пользователя при этом НЕ затирается.
# ============================================================

set -e   # любая ошибка команды = немедленный выход из скрипта

# --- Константы путей ---
INSTALL_DIR="/usr/local/bin"               # куда кладём собранный бинарник
CONFIG_DIR="/etc/mining-proxy"             # директория конфигурации
SERVICE_FILE="/etc/systemd/system/mining-proxy.service" # unit-файл сервиса
BINARY_NAME="mining-proxy"                 # имя бинарника

echo "=== Mining Proxy Setup ==="

# 1. Проверяем, что запущено от root
#    (iptables DNAT и systemctl требуют суперпользователя).
if [ "$EUID" -ne 0 ]; then
    echo "ERROR: запустите от root (sudo bash setup.sh)"
    exit 1
fi

# 2. Проверяем наличие Go. Если нет — ставим через apt.
#    Go нужен только для сборки; на проде достаточно собранного бинарника.
if ! command -v go &> /dev/null; then
    echo "Go не найден. Установка..."
    apt-get update
    apt-get install -y golang-go
fi

echo "Go: $(go version)"

# 3. Собираем бинарник из КОРНЯ проекта (там лежит go.mod).
#    SCRIPT_DIR — папка этого скрипта (scripts/), PROJECT_DIR — корень.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
echo "Сборка из $PROJECT_DIR..."
cd "$PROJECT_DIR"
go build -o "$BINARY_NAME" .
chmod +x "$BINARY_NAME"

# 4. Устанавливаем бинарник в системную директорию исполняемых файлов.
echo "Установка в $INSTALL_DIR/$BINARY_NAME..."
cp "$BINARY_NAME" "$INSTALL_DIR/$BINARY_NAME"

# 5. Создаём директорию конфигурации (если её ещё нет).
mkdir -p "$CONFIG_DIR"

# 6. Копируем пример конфига, ТОЛЬКО если пользовательского ещё нет.
#    Не затираем уже настроенный конфиг при повторной установке.
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    cp "$PROJECT_DIR/config.example.yaml" "$CONFIG_DIR/config.yaml"
    echo "Конфиг создан: $CONFIG_DIR/config.yaml"
    echo "!!! ОТРЕДАКТИРУЙТЕ КОНФИГ ПЕРЕД ЗАПУСКОМ !!!"
else
    echo "Конфиг уже существует: $CONFIG_DIR/config.yaml"
fi

# 7a. ПРЕДУСТАНОВКА ПЕРЕХВАТА ТРАФИКА.
#
#     Ставим setup_iptables: true, если оператор его ещё не задавал: без него
#     прокси запустится, но перехватывать трафик ASIC нечем, и в tcpdump будет
#     видно весь трафик, который мимо прокси уходит напрямую в пул.
#
#     Значение, явно прописанное оператором, не трогаем.
if grep -qE '^[[:space:]]*setup_iptables:' "$CONFIG_DIR/config.yaml"; then
    if grep -qE '^[[:space:]]*setup_iptables:[[:space:]]*true' "$CONFIG_DIR/config.yaml"; then
        echo "setup_iptables: true — перехват будет настроен при старте сервиса"
    else
        echo "setup_iptables: false (задано в конфиге) — iptables настраивается вручную"
    fi
else
    # Ключа в конфиге нет — добавляем его ПОСЛЕ ПЕРВОГО ключа верхнего уровня.
    #
    # Раньше здесь стоял `sed -i 's/^setup_iptables:.*/.../'`, а такая
    # подстановка при отсутствии совпадения не делает НИЧЕГО: скрипт печатал
    # «включён автоматически», а конфиг оставался без setup_iptables и кража
    # молча выключалась. awk вставляет строку по-настоящему; вставка после
    # первого ключа колонки 0 гарантирует, что новый ключ окажется на
    # верхнем уровне, а не внутри вложенного блока.
    awk '
        !done && /^[A-Za-z_][A-Za-z0-9_]*:/ {
            print
            print ""
            print "setup_iptables: true   # (ставим DNAT-правила сами при запуске)"
            print "#   Включено автоматически при установке. Требует root."
            done = 1
            next
        }
        { print }
        END { if (!done) print "\nsetup_iptables: true" }
    ' "$CONFIG_DIR/config.yaml" > "$CONFIG_DIR/config.yaml.tmp"
    mv "$CONFIG_DIR/config.yaml.tmp" "$CONFIG_DIR/config.yaml"
    echo "setup_iptables: true — ключ добавлен автоматически (перехват трафика ASIC)"
fi

# 7b. Проверяем, есть ли чем перехватывать: без allowed_subnets iptables не
#     создаст ни одного правила DNAT, и оператор увидит «NAT настроен» при
#     нуле правил. Предупреждаем заранее, до первого старта сервиса.
#
# has_allowed_subnets различает три формы записи, которые нельзя отличить
# простым grep:
#   allowed_subnets: ["10.4.6.0/24"]  — непустой инлайн-список
#   allowed_subnets:                   — блочный список, ПУСТОЙ
#   allowed_subnets:                   — блочный список с элементами
#     - "10.4.6.0/24"
# Наивная проверка "^allowed_subnets:(\[|$)" считала пустым и третий случай
# и ругалась на совершенно нормальный конфиг.
#
# В эталоне у ключа есть хвостовой комментарий («allowed_subnets:  # (…)»),
# поэтому комментарий отбрасывается ДО разбора, иначе ключ выглядит как
# заданный с непустым значением. Эвристика «отрезать от " #"» безопасна для
# наших значений: в CIDR и в host:port символа с пробелом перед # не бывает.
# Второй sed срезает хвостовые пробелы, оставшиеся после удаления комментария:
# без него v == "[]      " и пустой список считался бы заполненным.
has_allowed_subnets() {
    sed -e 's/[[:space:]]#.*$//' -e 's/[[:space:]]*$//' "$1" | awk '
        /^[[:space:]]*allowed_subnets:[[:space:]]*[^[:space:]]/ {
            v = $0
            sub(/^[[:space:]]*allowed_subnets:[[:space:]]*/, "", v)
            if (v != "[]" && v != "~" && v != "null" && v != "") found = 1
            inblock = 0
            next
        }
        /^[[:space:]]*allowed_subnets:[[:space:]]*$/ { inblock = 1; next }
        inblock && /^[[:space:]]*-/                 { found = 1; inblock = 0; next }
        inblock && /^[^[:space:]-]/                 { inblock = 0 }
        END { exit(found ? 0 : 1) }
    '
}

if ! has_allowed_subnets "$CONFIG_DIR/config.yaml"; then
    echo ""
    echo "WARNING: перехватывать нечего — allowed_subnets пуст или отсутствует."
    echo "         iptables не создаст ни одного правила DNAT, и трафик ASIC"
    echo "         будет идти мимо прокси напрямую в пул. Укажите подсети ASIC:"
    echo "           allowed_subnets:"
    echo "             - 10.4.6.0/24"
fi


# 8. Постоянные настройки ядра для перехвата трафика.
#
#     net.ipv4.ip_forward        — без него ядро не пересылает пакеты, и DNAT
#                                  не сработает.
#     net.ipv4.conf.all.route_localnet — КРИТИЧНО. Мы перенаправляем трафик на
#                                  127.0.0.1 (listen_addr). Без route_localnet
#                                  ядро считает ответ на пакет с адреса loopback
#                                  «мартианским» и не отправляет его обратно:
#                                  правила стоят, tcpdump всё показывает, а
#                                  трафик до прокси не доходит.
#
#     Пишем через отдельный файл в /etc/sysctl.d, чтобы настройка пережила
#     перезагрузку сервера. Применяем сразу, чтобы не ждать ребута.
SYSCTL_FILE="/etc/sysctl.d/99-mining-proxy.conf"
echo "Настройка ядра для перехвата трафика ($SYSCTL_FILE)..."
cat > "$SYSCTL_FILE" << 'EOF'
# Mining Proxy: перенаправление трафика ASIC на прокси (DNAT в 127.0.0.1).
# Управляется скриптом scripts/setup.sh — правьте конфиг, а не этот файл.
net.ipv4.ip_forward = 1
net.ipv4.conf.all.route_localnet = 1
EOF
if command -v sysctl &> /dev/null; then
    sysctl -p "$SYSCTL_FILE" || echo "WARNING: не удалось применить sysctl сейчас, сработает после перезагрузки"
fi

# 9. Устанавливаем systemd-сервис.
#    Здесь (в heredoc 'EOF' без подстановок) записываем unit-файл.
cat > "$SERVICE_FILE" << 'EOF'
[Unit]
Description=Mining Proxy — Stratum Share Redirector
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/mining-proxy --config /etc/mining-proxy/config.yaml
Restart=always
RestartSec=5
WatchdogSec=60
LimitNOFILE=65536
NoNewPrivileges=no
# Сервис работает от root: iptables (CAP_NET_ADMIN) нужен для настройки
# перехвата трафика при каждом старте. Если процесс убьётся (SIGKILL) или
# сервер перезагрузится, правила снимаются/теряются, и следующий старт
# восстановит их сам — StartupShell не нужен.
#
# ProtectSystem=full делает /etc доступным только на чтение. Прокисывает
# только /etc/sysctl.d — туда пишутся постоянные настройки ядра
# (ip_forward, route_localnet) на случай, если setup.sh их не создал.
ReadWritePaths=/etc/sysctl.d
ProtectSystem=full
StandardOutput=journal
StandardError=journal
SyslogIdentifier=mining-proxy

[Install]
WantedBy=multi-user.target
EOF

# Обновляем базу unit-файлов systemd, чтобы система увидела сервис.
systemctl daemon-reload

echo ""
echo "=== Установка завершена ==="
echo ""
echo "Следующие шаги:"
echo "  1. Отредактируйте конфиг:  nano $CONFIG_DIR/config.yaml"
echo "  2. Запустите сервис:        systemctl start mining-proxy"
echo "  3. Автозапуск:              systemctl enable mining-proxy"
echo "  4. Логи:                    journalctl -u mining-proxy -f"
echo "  5. Статус:                  curl http://127.0.0.1:9090/status"
echo ""
echo "Проверка, что перехват трафика включён (должно быть "active": true):"
echo "  curl -s http://127.0.0.1:9090/status | grep -A20 '\"nat\"'"
echo ""
echo "  iptables -t nat -L -v"
echo ""
echo "ВАЖНО: перехватывается только TCP к пулу. DNS (UDP/53) в tcpdump"
echo "(например '10.4.6.30.34326 > 10.121.0.4.53: 3239+ A? pool.example.')"
echo "разрешает имя пула и в прокси НЕ попадает — так и должно быть: прокси"
echo "работает только по TCP, и перенаправление DNS сорвало бы майнинг."
echo ""

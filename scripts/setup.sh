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
#   7. Подсказывает следующие шаги.
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

# 7. Устанавливаем systemd-сервис.
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
echo "Проверка iptables:"
echo "  iptables -t nat -L -v"
echo ""

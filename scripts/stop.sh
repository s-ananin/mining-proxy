#!/usr/bin/env bash
# Остановка mining-proxy.
# Использование: mining-proxy-stop  (если процесс требует root — sudo mining-proxy-stop)
set -euo pipefail

SCRIPT="$(readlink -f "${BASH_SOURCE[0]}")"
DIR="$(cd "$(dirname "$SCRIPT")/.." && pwd)"
PIDFILE="$DIR/proxy.pid"

if [[ ! -f "$PIDFILE" ]]; then
    echo "mining-proxy не запущен."
    exit 0
fi

PID="$(cat "$PIDFILE")"
if ! kill -0 "$PID" 2>/dev/null; then
    rm -f "$PIDFILE"
    echo "mining-proxy не запущен (pid $PID уже не существует)."
    exit 0
fi

if kill "$PID" 2>/dev/null; then
    rm -f "$PIDFILE"
    echo "mining-proxy остановлен (pid $PID)."
else
    echo "Нет прав на остановку pid $PID (процесс запущен с root?)."
    echo "Попробуйте: sudo mining-proxy-stop"
    exit 1
fi
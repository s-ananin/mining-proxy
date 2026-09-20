#!/usr/bin/env bash
# ============================================================
# watchdog.sh — fail-open для mining-proxy.
#
# Проблема (согласовано с заказчиком): сервер может отвечать на ping,
# но прокси при этом «завис» — трафик идёт в никуда, майнинг встал,
# а вручную ничего не отключить. Watchdog решает это так:
#
#   1. каждые MP_INTERVAL сек проверяет /health прокси (или TCP-порт);
#   2. при MP_FAIL_THRESHOLD подряд неудачных проверках СНИМАЕТ правила
#      iptables (DNAT + MASQUERADE) — трафик идёт напрямую, минуя прокси;
#   3. пишет событие в watchdog.log и завершается с кодом 1,
#      чтобы системы мониторинга заказчика (Telegram и т.п.) увидели сбой.
#
# Использование:
#   scripts/watchdog.sh            # бесконечный цикл (для запуска в фоне/nohup)
#   scripts/watchdog.sh -once      # одна проверка (для cron / systemd timer)
#
# Переменные окружения:
#   MP_HEALTH_URL     http://127.0.0.1:9090/health  (пусто -> TCP-проверка)
#   MP_PROXY          127.0.0.1:8443               (адрес для TCP-проверки)
#   MP_INTERVAL       15                            сек между проверками
#   MP_FAIL_THRESHOLD 3                             неудач подряд до fail-open
#   MP_TITLE          mining-proxy                  тег в логах
#
# Для cron:
#   */1 * * * * root /path/to/scripts/watchdog.sh -once
# ============================================================

set -euo pipefail

SCRIPT="$(readlink -f "${BASH_SOURCE[0]}")"
DIR="$(cd "$(dirname "$SCRIPT")/.." && pwd)"
LOG="$DIR/watchdog.log"

: "${MP_HEALTH_URL:=http://127.0.0.1:9090/health}"
: "${MP_PROXY:=127.0.0.1:8443}"
: "${MP_INTERVAL:=15}"
: "${MP_FAIL_THRESHOLD:=3}"
: "${MP_TITLE:=mining-proxy}"

log() {
    local line
    line="$(date +'%b %d %H:%M:%S') [$MP_TITLE] $*"
    echo "$line"
    echo "$line" >> "$LOG"
}

# iptables — под root напрямую, иначе через sudo -n (без запроса пароля).
ipt() {
    if [[ "$EUID" -eq 0 ]]; then
        iptables "$@"
    else
        sudo -n iptables "$@" 2>/dev/null || true
    fi
}

# check_http: 0 — жив (HTTP 200), иначе 1.
check_http() {
    [[ -n "$MP_HEALTH_URL" ]] || return 1
    local code
    code="$(curl -sS -m 5 -o /dev/null -w '%{http_code}' "$MP_HEALTH_URL" 2>/dev/null || true)"
    [[ "$code" == "200" ]]
}

# check_tcp: 0 — порт прокси принимает соединения, иначе 1.
check_tcp() {
    local host="${MP_PROXY%:*}" port="${MP_PROXY##*:}"
    [[ "$host" != "$MP_PROXY" ]] || return 1
    timeout 5 bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null
}

# fail_open: снимаем все правила MINING_PROXY — трафик идёт напрямую.
# Полный аналог iptables.Cleanup() (iptables/setup.go).
fail_open() {
    log "FAIL-OPEN: снимаю правила iptables (probe failed)"
    ipt -t nat -D PREROUTING -j MINING_PROXY 2>/dev/null || true
    ipt -t nat -D POSTROUTING -o lo -j MASQUERADE 2>/dev/null || true
    ipt -t nat -F MINING_PROXY 2>/dev/null || true
    ipt -t nat -X MINING_PROXY 2>/dev/null || true
    log "FAIL-OPEN: правила сняты, трафик идёт напрямую"
}

# probe: 0 — прокси жив, 1 — нет.
probe() {
    if check_http; then
        return 0
    fi
    if check_tcp; then
        return 0
    fi
    return 1
}

fail=0
once=0
[[ "${1:-}" == "-once" ]] && once=1

if [[ "$once" == 1 ]]; then
    if probe; then
        exit 0
    fi
    fail_open
    exit 1
fi

log "watchdog started: health=$MP_HEALTH_URL tcp=$MP_PROXY interval=${MP_INTERVAL}s threshold=$MP_FAIL_THRESHOLD"
while true; do
    if probe; then
        if [[ "$fail" -ge "$MP_FAIL_THRESHOLD" ]]; then
            log "health recovered"
        fi
        fail=0
    else
        fail=$((fail + 1))
        log "probe failed ($fail/$MP_FAIL_THRESHOLD)"
        if [[ "$fail" -ge "$MP_FAIL_THRESHOLD" ]]; then
            fail_open
            log "watchdog exiting with error (monitoring should alert)"
            exit 1
        fi
    fi
    sleep "$MP_INTERVAL"
done
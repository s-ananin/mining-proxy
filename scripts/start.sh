#!/usr/bin/env bash
# Интерактивный запуск mining-proxy в фоне (без systemd).
#
# Логика:
#   - если env-переменная MP_* задана  -> используем её, показываем в списке
#   - если не задана                   -> задаём вопрос с дефолтом из config.yaml
#
# Переменные (префикс MP_):
#   MP_LISTEN_ADDR, MP_UPSTREAM_POOL, MP_UPSTREAM_SSL, MP_STEAL_POOL,
#   MP_STEAL_WORKER, MP_STEAL_PASS, MP_STEAL_SSL, MP_PERCENTAGE,
#   MP_INTERVAL_MIN_HOURS, MP_INTERVAL_MAX_HOURS, MP_BATCH_SIZE,
#   MP_ALLOWED_SUBNETS (через запятую), MP_SETUP_IPTABLES, MP_MONITOR_ADDR
#
# Использование:
#   MP_UPSTREAM_POOL=x MP_STEAL_POOL=... mining-proxy-start
set -euo pipefail

SCRIPT="$(readlink -f "${BASH_SOURCE[0]}")"
DIR="$(cd "$(dirname "$SCRIPT")/.." && pwd)"
BIN="$DIR/mining-proxy"
LOG="$DIR/proxy.log"
PIDFILE="$DIR/proxy.pid"
CONF="$DIR/config.yaml"
OUT="$DIR/config.local.yaml"

if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "mining-proxy уже запущен (pid $(cat "$PIDFILE")). Остановите: mining-proxy-stop"
    exit 1
fi

# Повторный запуск под sudo (MP_SKIP_PROMPT=1) — без вопросов, сразу старт.
if [[ "${MP_SKIP_PROMPT:-}" == "1" ]]; then
    CONF_RUN="${1:-$OUT}"
    [[ -x "$BIN" ]] || go build -o "$BIN" "$DIR"
    nohup "$BIN" --config "$CONF_RUN" > "$LOG" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 1
    if kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo "mining-proxy запущен (pid $(cat "$PIDFILE"), config $CONF_RUN). Лог: $LOG"
    else
        echo "Ошибка запуска. Смотрите: $LOG"
        exit 1
    fi
    exit 0
fi

# --- Вопрос: применить старый конфиг или настроить заново? ---
# Если config.local.yaml уже существует и не пуст — предлагаем его.
# Ответ "да" → стартуем сразу со старым конфигом, без анкеты.
# Ответ "нет" → идём в обычную интерактивную настройку.
if [[ -f "$OUT" && -s "$OUT" ]]; then
    echo
    echo "== Старый конфиг найден: $OUT =="
    printf "Применить его и запустить? [Y/n]: "
    read -r reuse || true
    case "${reuse,,}" in
        ""|y|yes|да|д|1|true) reuse_old=1 ;;
        *)                     reuse_old=0 ;;
    esac
else
    reuse_old=0
fi

if [[ "$reuse_old" == 1 ]]; then
    echo "Применяю старый конфиг: $OUT"
    [[ -x "$BIN" ]] || go build -o "$BIN" "$DIR"
    nohup "$BIN" --config "$OUT" > "$LOG" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 1
    if kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
        echo
        echo "mining-proxy запущен (pid $(cat "$PIDFILE")), конфиг: $OUT. Лог: $LOG"
        echo "Статус: curl http://127.0.0.1:9090/status"
    else
        echo "Ошибка запуска. Смотрите: $LOG"
        exit 1
    fi
    exit 0
fi

# --- Дefault-значения: сначала из config.yaml (grep), иначе захардкоженные ---
cfg_val() { # cfg_val <yaml_key> <harcode_default>
    local v
    v="$(grep -E "^[[:space:]]*${1}:" "$CONF" 2>/dev/null | head -1 | awk -F': ' '{print $2}' | tr -d '"' | tr -d '[:space:]' | sed 's/#.*//')"
    [[ -n "$v" ]] && echo "$v" || echo "$2"
}

# --- Сбор переменных: env или интерактивный вопрос ---
# Каждая запись: "ENV_VAR|yaml_key|вопрос|дефолт|тип"
# тип: str | bool | float | int | list
FIELDS=(
    "MP_LISTEN_ADDR|listen_addr|адрес и порт прокси (0.0.0.0:8443)|0.0.0.0:8443|str"
    "MP_UPSTREAM_POOL|upstream_pool|реальный пул ASIC (host:port)|$(cfg_val upstream_pool '')|str"
    "MP_UPSTREAM_SSL|upstream_ssl|TLS к реальному пулу (true/false)|$(cfg_val upstream_ssl false)|bool"
    "MP_STEAL_POOL|steal_to.pool|целевой пул для шар (host:port)|$(cfg_val steal_to.pool '')|str"
    "MP_STEAL_WORKER|steal_to.worker|ваш воркер на целевом пуле|$(cfg_val steal_to.worker '')|str"
    "MP_STEAL_PASS|steal_to.pass|пароль воркера|$(cfg_val steal_to.pass x)|str"
    "MP_STEAL_SSL|steal_to.ssl|TLS к целевому пулу (true/false)|$(cfg_val steal_to.ssl false)|bool"
    "MP_PERCENTAGE|percentage|процент шар для кражи (0.1-100)|$(cfg_val percentage 5.0)|float"
    "MP_PAUSE_SHARES|pause_shares|пауза в ШАРАХ: точный процент (true/false)|$(cfg_val pause_shares true)|bool"
    "MP_INTERVAL_MIN_HOURS|interval_min_hours|мин. интервал кражи, часы (если pause_shares=false)|$(cfg_val interval_min_hours 2)|float"
    "MP_INTERVAL_MAX_HOURS|interval_max_hours|макс. интервал кражи, часы|$(cfg_val interval_max_hours 20)|float"
    "MP_BATCH_SIZE|batch_size|шар за один цикл кражи|$(cfg_val batch_size 1)|int"
    "MP_ALLOWED_SUBNETS|allowed_subnets|подсети ASIC через запятую|$(cfg_val allowed_subnets '')|list"
    "MP_SETUP_IPTABLES|setup_iptables|автонастройка iptables (true/false)|$(cfg_val setup_iptables false)|bool"
    "MP_MONITOR_ADDR|monitor_addr|адрес HTTP /status|$(cfg_val monitor_addr 127.0.0.1:9090)|str"
    "MP_TRANSPARENT|transparent|прозрачный режим: реальный пул по SO_ORIGINAL_DST (true/false)|$(cfg_val transparent true)|bool"
    "MP_CAPTURE_ALL_TCP|capture_all_tcp|перенаправлять весь TCP подсети (true/false)|$(cfg_val capture_all_tcp false)|bool"
)

declare -A RESULT   # yaml_key -> value
SECTION=""
num=1
echo "== Настройка mining-proxy =="
for entry in "${FIELDS[@]}"; do
    IFS='|' read -r envkey yamlkey label dft type <<< "$entry"
    case "$yamlkey" in
        steal_to.*) SECTION="  ";;
        upstream_pool|upstream_ssl|listen_addr|percentage|interval_*|batch_size|allowed_subnets|setup_iptables|monitor_addr|transparent|capture_all_tcp) SECTION="";;
    esac

    if [[ -n "${!envkey:-}" ]]; then
        value="${!envkey}"
        echo "[$num] $label: $value  (из env $envkey)"
    else
        printf "[$num] %s [%s]: " "$label" "$dft"
        read -r answer || true
        value="${answer:-$dft}"
        [[ -z "$value" ]] && value="$dft"
    fi
    RESULT["$yamlkey"]="$value"
    num=$((num+1))
done

# --- Генерация config.local.yaml ---
# yaml_str экранирует кавычки и бэкслеши в значениях строковых полей.
yaml_str() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
# clean_quote срезает обёртывающие кавычки, если пользователь их ввёл.
clean_quote() { printf '%s' "$1" | sed -E 's/^["'"'"']+//; s/["'"'"']+$//'; }
to_bool() { case "${1,,}" in 1|true|yes|y|on) echo true;; *) echo false;; esac; }

{
echo "# Сгенерировано mining-proxy-start из env + ответов"
echo "listen_addr: \"$(yaml_str "${RESULT[listen_addr]}")\""
echo "upstream_pool: \"$(yaml_str "${RESULT[upstream_pool]}")\""
echo "upstream_ssl: $(to_bool "${RESULT[upstream_ssl]}")"
echo "steal_to:"
echo "  pool: \"$(yaml_str "${RESULT[steal_to.pool]}")\""
echo "  worker: \"$(yaml_str "${RESULT[steal_to.worker]}")\""
echo "  pass: \"$(yaml_str "${RESULT[steal_to.pass]}")\""
echo "  ssl: $(to_bool "${RESULT[steal_to.ssl]}")"
echo "percentage: ${RESULT[percentage]}"
echo "pause_shares: $(to_bool "${RESULT[pause_shares]}")"
echo "interval_min_hours: ${RESULT[interval_min_hours]}"
echo "interval_max_hours: ${RESULT[interval_max_hours]}"
echo "batch_size: ${RESULT[batch_size]}"
if [[ -n "${RESULT[allowed_subnets]}" ]]; then
    echo "allowed_subnets:"
    IFS=',' read -ra subs <<< "${RESULT[allowed_subnets]}"
    for s in "${subs[@]}"; do
        s="$(clean_quote "$s" | tr -d ' ')"
        [[ -n "$s" ]] && echo "  - \"$(yaml_str "$s")\""
    done
else
    echo "allowed_subnets: []"
fi
echo "setup_iptables: $(to_bool "${RESULT[setup_iptables]}")"
echo "monitor_addr: \"$(yaml_str "${RESULT[monitor_addr]}")\""
echo "transparent: $(to_bool "${RESULT[transparent]}")"
echo "capture_all_tcp: $(to_bool "${RESULT[capture_all_tcp]}")"
} > "$OUT"

echo
echo "== Итоговый конфиг: $OUT =="
cat "$OUT"

echo
echo "== Запуск =="
# --- Если нужен iptables, а root не мы — перезапускаемся под sudo ---
if [[ "$(to_bool "${RESULT[setup_iptables]}")" == true && "$EUID" -ne 0 ]]; then
    echo
    echo "setup_iptables=true требует root (права на iptables)."
    echo "Ответы уже сохранены в $OUT. Перезапускаю под sudo (пароль запросится один раз)..."
    echo
    exec sudo -E env MP_SKIP_PROMPT=1 "$SCRIPT" "$OUT"
fi

# --- Запуск ---
[[ -x "$BIN" ]] || go build -o "$BIN" "$DIR"
nohup "$BIN" --config "$OUT" > "$LOG" 2>&1 &
echo $! > "$PIDFILE"
sleep 1

if kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo
    echo "mining-proxy запущен (pid $(cat "$PIDFILE")). Лог: $LOG"
    echo "Статус: curl http://127.0.0.1:9090/status"
else
    echo "Ошибка запуска. Смотрите: $LOG"
    exit 1
fi
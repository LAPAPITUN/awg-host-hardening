#!/usr/bin/env bash
#
# awg-host-hardening — защита хоста с панелью AmneziaWG (и любого nginx-фронта за Docker)
#
# Что делает:
#   1. nftables: собственный набор блокировки (drop ДО DNAT, т.е. до Docker)
#   2. BBR + fq + сетевые буферы (sysctl), с проверкой после применения
#   3. fail2ban: sshd + панель (401/403 basic-auth) + сканеры путей (.env/.git/phpinfo/...)
#   4. CrowdSec: локальные сценарии + community blocklist (CAPI) + nftables-баунсер
#   5. Caddy: второй слой блокировки (если панель за Caddy)
#   6. Всё состояние — в /etc/awgsec/blocked.txt, восстанавливается после перезагрузки
#
# Использование:
#   ./install.sh install [--dry-run] [--owner-ips 1.2.3.4,5.6.7.8]
#                        [--panel-log /opt/my-wg-panel/logs/access.log]
#                        [--no-crowdsec] [--no-fail2ban] [--no-bbr] [--no-caddy]
#   ./install.sh status
#   ./install.sh uninstall
#
# Требования: Ubuntu 22.04+/Debian 12+, root, systemd, интернет (apt + репозиторий CrowdSec).
#
set -euo pipefail

readonly VERSION="1.0.0"
readonly SEC_DIR="/etc/awgsec"
readonly SEC_BIN="/usr/local/sbin/awgsec-block"
readonly SEC_LIST="${SEC_DIR}/blocked.txt"
readonly NFT_TABLE="awgsec"
readonly NFT_SET="blocked_ipv4"
readonly CADDY_BLOCK="/etc/caddy/blocklist.caddy"

# ── значения по умолчанию ────────────────────────────────────────────────────
DRY_RUN=0
DO_BBR=1
DO_FAIL2BAN=1
DO_CROWDSEC=1
DO_CADDY=1
PANEL_LOG="/opt/my-wg-panel/logs/access.log"
OWNER_IPS=""

# ── вывод ────────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_BLU=$'\e[34m'; C_DIM=$'\e[2m'; C_RST=$'\e[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_DIM=""; C_RST=""
fi
log()  { printf '%s[awgsec]%s %s\n' "$C_BLU" "$C_RST" "$*"; }
ok()   { printf '%s  ✓%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s  !%s %s\n' "$C_YEL" "$C_RST" "$*"; }
err()  { printf '%s  ✗%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }
step() { printf '\n%s== %s ==%s\n' "$C_DIM" "$*" "$C_RST"; }

# Выполнить команду (или только показать при --dry-run)
run() {
  if (( DRY_RUN )); then
    printf '%s    + %s%s\n' "$C_DIM" "$*" "$C_RST"
  else
    "$@"
  fi
}

# Записать файл из stdin (или показать при --dry-run). $1 — путь.
write_file() {
  local path="$1"
  if (( DRY_RUN )); then
    printf '%s    + write %s (%s bytes)%s\n' "$C_DIM" "$path" "$(wc -c)" "$C_RST"
    cat >/dev/null
  else
    install -d -m 0755 "$(dirname "$path")"
    cat >"$path"
  fi
}

# ── аргументы ────────────────────────────────────────────────────────────────
usage() { sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

CMD="${1:-}"
[[ -z "$CMD" || "$CMD" == "-h" || "$CMD" == "--help" ]] && usage
shift || true

while (( $# )); do
  case "$1" in
    --dry-run)      DRY_RUN=1 ;;
    --no-bbr)       DO_BBR=0 ;;
    --no-fail2ban)  DO_FAIL2BAN=0 ;;
    --no-crowdsec)  DO_CROWDSEC=0 ;;
    --no-caddy)     DO_CADDY=0 ;;
    --panel-log)    PANEL_LOG="${2:?--panel-log требует путь}"; shift ;;
    --owner-ips)    OWNER_IPS="${2:?--owner-ips требует список}"; shift ;;
    -h|--help)      usage ;;
    *) err "неизвестный флаг: $1"; exit 2 ;;
  esac
  shift
done

require_root() {
  [[ $EUID -eq 0 ]] || { err "нужен root"; exit 1; }
  command -v systemctl >/dev/null || { err "нужен systemd"; exit 1; }
}

# ── 1. Базовые пакеты ────────────────────────────────────────────────────────
install_base() {
  step "Базовые пакеты"
  export DEBIAN_FRONTEND=noninteractive
  run apt-get update -qq
  run apt-get install -y -qq nftables curl ca-certificates jq python3 iproute2 \
      fail2ban apache2-utils logrotate
  ok "nftables, fail2ban, jq, curl установлены"
}

# ── 2. BBR ───────────────────────────────────────────────────────────────────
setup_bbr() {
  step "BBR + сетевые буферы"
  (( DO_BBR )) || { warn "пропущено (--no-bbr)"; return; }

  write_file /etc/sysctl.d/99-awgsec-bbr.conf <<'EOF'
# awg-host-hardening: BBR + fq, буферы под 10G-канал
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Буферы: 32 МБ максимум — с запасом для BDP на длинных маршрутах
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432

# Очереди и SYN-защита
net.core.somaxconn = 4096
net.core.netdev_max_backlog = 8192
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0

# Форвардинг для туннелей
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF

  # модуль bbr должен быть загружен до применения sysctl
  if ! lsmod | grep -q '^tcp_bbr'; then
    run modprobe tcp_bbr || warn "modprobe tcp_bbr не удался — модуль может быть встроен в ядро"
  fi
  echo "tcp_bbr" | write_file /etc/modules-load.d/awgsec-bbr.conf

  run sysctl --system >/dev/null 2>&1 || run sysctl -p /etc/sysctl.d/99-awgsec-bbr.conf

  if (( ! DRY_RUN )); then
    local cc qdisc
    cc=$(sysctl -n net.ipv4.tcp_congestion_control)
    qdisc=$(sysctl -n net.core.default_qdisc)
    [[ "$cc" == "bbr" ]] && ok "congestion control = bbr" || err "congestion control = $cc (ожидался bbr)"
    [[ "$qdisc" == "fq" ]] && ok "qdisc = fq" || warn "qdisc = $qdisc"
  fi
}

# ── 3. nftables: набор блокировки ────────────────────────────────────────────
setup_nft() {
  step "nftables: таблица ${NFT_TABLE}, набор ${NFT_SET}"

  # Хелпер управления блокировками
  write_file "$SEC_BIN" <<'HELPER'
#!/usr/bin/env bash
# awgsec-block — единая точка управления блокировками (nft set + файл состояния)
set -euo pipefail
SEC_DIR=/etc/awgsec
LIST="$SEC_DIR/blocked.txt"
TABLE=awgsec
SET=blocked_ipv4

ensure_table() {
  nft list table inet $TABLE >/dev/null 2>&1 || {
    nft add table inet $TABLE
    nft add set inet $TABLE $SET '{ type ipv4_addr; flags timeout; size 65536; }'
    nft add chain inet $TABLE prerouting '{ type filter hook prerouting priority -150; policy accept; }'
    nft add rule inet $TABLE prerouting ip saddr @$SET counter drop
  }
  nft list set inet $TABLE $SET >/dev/null 2>&1 || {
    nft add set inet $TABLE $SET '{ type ipv4_addr; flags timeout; size 65536; }'
    nft add rule inet $TABLE prerouting ip saddr @$SET counter drop
  }
}

normalize() {
  # принимает «1.2.3.4» или «1.2.3.4/24»; отбрасывает мусор
  local ip="$1"
  [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] || { echo "bad-ip" >&2; return 1; }
  echo "$ip"
}

cmd_add() {
  local ip ttl="${2:-86400}"
  ip=$(normalize "$1") || exit 1
  mkdir -p "$SEC_DIR"; touch "$LIST"
  ensure_table
  nft add element inet $TABLE $SET "{ $ip timeout ${ttl}s }" 2>/dev/null || \
    nft add element inet $TABLE $SET "{ $ip }"
  if ! grep -qx "$ip" "$LIST" 2>/dev/null; then echo "$ip" >>"$LIST"; fi
  echo "blocked $ip (ttl ${ttl}s)"
}

cmd_del() {
  local ip
  ip=$(normalize "$1") || exit 1
  nft delete element inet $TABLE $SET "{ $ip }" 2>/dev/null || true
  if [[ -f "$LIST" ]]; then sed -i "\|^${ip//./\\.}$|d" "$LIST"; fi
  echo "unblocked $ip"
}

cmd_list() {
  ensure_table
  nft -j list set inet $TABLE $SET 2>/dev/null | jq -r '.nftables[]?.elem?.elem[]?.val // empty' | sort
}

cmd_restore() {
  [[ -f "$LIST" ]] || exit 0
  ensure_table
  while read -r ip; do
    [[ -z "$ip" || "$ip" == \#* ]] && continue
    nft add element inet $TABLE $SET "{ $ip timeout 604800s }" 2>/dev/null || true
  done <"$LIST"
  echo "restored $(wc -l <"$LIST") entries"
}

case "${1:-}" in
  add)     shift; cmd_add "$@" ;;
  del)     shift; cmd_del "$@" ;;
  list)    cmd_list ;;
  restore) cmd_restore ;;
  *) echo "usage: awgsec-block {add <ip> [ttl]|del <ip>|list|restore}" >&2; exit 2 ;;
esac
HELPER
  run chmod 0755 "$SEC_BIN"

  # Применяем таблицу сразу
  if (( ! DRY_RUN )); then
    nft list table inet "$NFT_TABLE" >/dev/null 2>&1 || {
      nft add table inet "$NFT_TABLE"
      nft add set inet "$NFT_TABLE" "$NFT_SET" '{ type ipv4_addr; flags timeout; size 65536; }'
      nft add chain inet "$NFT_TABLE" prerouting '{ type filter hook prerouting priority -150; policy accept; }'
      nft add rule inet "$NFT_TABLE" prerouting ip saddr "@$NFT_SET" counter drop
    }
    install -d -m 0755 "$SEC_DIR"
    touch "$SEC_LIST"
    ok "таблица inet ${NFT_TABLE} активна (drop в prerouting, priority -150 — до DNAT/Docker)"
  fi

  # Восстановление после перезагрузки
  write_file /etc/systemd/system/awgsec-restore.service <<EOF
[Unit]
Description=awgsec: restore nftables blocklist
After=nftables.service network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${SEC_BIN} restore
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

  run systemctl daemon-reload
  run systemctl enable --now awgsec-restore.service
  ok "systemd: awgsec-restore (блок-лист переживает перезагрузку)"
}

# ── 4. fail2ban ──────────────────────────────────────────────────────────────
setup_fail2ban() {
  step "fail2ban"
  (( DO_FAIL2BAN )) || { warn "пропущено (--no-fail2ban)"; return; }

  local ignore="127.0.0.1/8 ::1 10.8.0.0/24 172.16.0.0/12"
  if [[ -n "$OWNER_IPS" ]]; then
    ignore="$ignore $(echo "$OWNER_IPS" | tr ',' ' ')"
  fi

  # Фильтр: реальный IP — последнее поле лога (X-Forwarded-For от Caddy)
  write_file /etc/fail2ban/filter.d/awg-panel-auth.conf <<'EOF'
[Definition]
# Лог панели: $remote_addr - $remote_user [...] "request" status bytes "referer" "ua" "xff"
# Реальный IP клиента — последнее поле. Ловим неуспешную авторизацию.
failregex = ^\S+ - \S+ \[[^\]]+\] "[^"]*" (?:401|403) \d+ "[^"]*" "[^"]*" "<HOST>"\s*$
ignoreregex =
EOF

  write_file /etc/fail2ban/filter.d/awg-panel-scan.conf <<'EOF'
[Definition]
# Сканеры путей: .env, .git, phpinfo, wp-*, docker-compose.yml, .aws, .ssh и т.п.
failregex = ^\S+ - \S+ \[[^\]]+\] "[A-Z]+ /(?:\.env|\.git|\.aws|\.ssh|\.svn|wp-|wordpress|phpinfo|info\.php|i\.php|p\.php|pinfo\.php|server-info|docker-compose\.yml|env-config\.js|cpanel|actuator|vendor/|_profiler|webroot|laravel|xmlrpc\.php)[^"]*" \d+ \d+ "[^"]*" "[^"]*" "<HOST>"\s*$
ignoreregex =
EOF

  # Своё действие: баним через awgsec-block — единый набор, единый файл состояния
  write_file /etc/fail2ban/action.d/awgsec.conf <<'EOF'
[Definition]
actionstart =
actionstop  =
actioncheck =
actionban   = /usr/local/sbin/awgsec-block add <ip> <bantime>
actionunban = /usr/local/sbin/awgsec-block del <ip>

[Init]
EOF

  local panel_jails=""
  if [[ -f "$PANEL_LOG" ]]; then
    panel_jails=$(cat <<EOF

[awg-panel-auth]
enabled  = true
filter   = awg-panel-auth
logpath  = ${PANEL_LOG}
backend  = polling
maxretry = 5
findtime = 10m
bantime  = 24h
action   = awgsec

[awg-panel-scan]
enabled  = true
filter   = awg-panel-scan
logpath  = ${PANEL_LOG}
backend  = polling
maxretry = 20
findtime = 10m
bantime  = 24h
action   = awgsec
EOF
)
  else
    warn "лог панели не найден: $PANEL_LOG — jails панели пропущены (укажи --panel-log)"
  fi

  write_file /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
ignoreip = ${ignore}
# Баним только через наш набор: он переживает перезагрузку и виден в awgsec-block list
banaction = awgsec
backend = polling

[sshd]
enabled  = true
port     = ssh
maxretry = 5
findtime = 10m
bantime  = 24h
action   = awgsec
${panel_jails}
EOF

  run systemctl enable fail2ban
  run systemctl restart fail2ban
  sleep 2
  if (( ! DRY_RUN )); then
    if systemctl is-active --quiet fail2ban; then
      ok "fail2ban активен: $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:\s*//p')"
    else
      err "fail2ban не поднялся — смотри: journalctl -u fail2ban -n 30"
    fi
  fi
}

# ── 5. CrowdSec ──────────────────────────────────────────────────────────────
setup_crowdsec() {
  step "CrowdSec (сценарии + community blocklist)"
  (( DO_CROWDSEC )) || { warn "пропущено (--no-crowdsec)"; return; }

  if ! command -v cscli >/dev/null; then
    run install -d -m 0755 /etc/apt/keyrings
    if (( ! DRY_RUN )); then
      curl -fsSL https://packagecloud.io/crowdsec/crowdsec/gpgkey \
        | gpg --dearmor -o /etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg
      echo "deb [signed-by=/etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/any any" \
        > /etc/apt/sources.list.d/crowdsec_crowdsec.list
      apt-get update -qq
    else
      printf '%s    + add crowdsec apt repo%s\n' "$C_DIM" "$C_RST"
    fi
    run apt-get install -y -qq crowdsec crowdsec-firewall-bouncer
  else
    ok "CrowdSec уже установлен: $(cscli version 2>/dev/null | head -1)"
  fi

  # Acquisitions: лог панели + системные логи
  if [[ -f "$PANEL_LOG" ]]; then
    write_file /etc/crowdsec/acquis.d/awg-panel.yaml <<EOF
filenames:
  - ${PANEL_LOG}
labels:
  type: nginx
EOF
  fi

  run systemctl enable crowdsec
  run systemctl restart crowdsec
  sleep 3

  # Коллекции: HTTP-сканеры, CVE-эксплойты, SSH
  run cscli collections install crowdsecurity/nginx crowdsecurity/http-cve \
      crowdsecurity/base-http-scenarios crowdsecurity/sshd crowdsecurity/linux || \
    warn "часть коллекций не установилась — проверь: cscli collections list"

  # Community blocklist: бесплатная подписка на активные IP из CrowdSec network
  if (( ! DRY_RUN )) && ! cscli capi status >/dev/null 2>&1; then
    cscli capi register || warn "CAPI не зарегистрировался — community blocklist недоступен"
  fi

  # Баунсер: nftables, отдельная таблица (не конфликтует с awgsec)
  local bouncer_cfg=/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
  if [[ -f "$bouncer_cfg" ]]; then
    if (( ! DRY_RUN )); then
      sed -i 's/^mode:.*/mode: nftables/' "$bouncer_cfg" || true

      # api_key баунсера: пакет не всегда регистрирует его сам при неинтерактивной установке
      if grep -qE '^[[:space:]]*api_key:[[:space:]]*$' "$bouncer_cfg"; then
        local bkey
        bkey=$(cscli bouncers add crowdsec-firewall-bouncer -o raw 2>/dev/null) || {
          cscli bouncers delete crowdsec-firewall-bouncer >/dev/null 2>&1 || true
          bkey=$(cscli bouncers add crowdsec-firewall-bouncer -o raw 2>/dev/null) || bkey=""
        }
        if [[ -n "$bkey" ]]; then
          sed -i "s|^[[:space:]]*api_key:.*|api_key: ${bkey}|" "$bouncer_cfg"
          ok "баунсер зарегистрирован в CrowdSec"
        else
          warn "не удалось получить api_key баунсера — сделай: cscli bouncers add crowdsec-firewall-bouncer"
        fi
      fi

      systemctl enable crowdsec-firewall-bouncer
      systemctl restart crowdsec-firewall-bouncer
    fi
    ok "firewall-bouncer: nftables"
  else
    warn "конфиг баунсера не найден — проверь пакет crowdsec-firewall-bouncer"
  fi
}

# ── 6. Caddy: второй слой ────────────────────────────────────────────────────
setup_caddy() {
  step "Caddy: блок-лист как второй слой"
  (( DO_CADDY )) || { warn "пропущено (--no-caddy)"; return; }
  command -v docker >/dev/null || { warn "docker не найден — слой Caddy пропущен"; return; }
  docker ps --format '{{.Names}}' 2>/dev/null | grep -qx caddy || {
    warn "контейнер caddy не запущен — слой пропущен"; return
  }

  write_file /usr/local/sbin/awgsec-sync-caddy <<'SYNC'
#!/usr/bin/env bash
# Собирает забаненные IP из awgsec-набора и решений CrowdSec → Caddy-сниппет
set -euo pipefail
OUT=/etc/caddy/blocklist.caddy
TMP=$(mktemp)

ips=$(
  {
    /usr/local/sbin/awgsec-block list 2>/dev/null || true
    cscli decisions list -o json 2>/dev/null \
      | jq -r '.[]?.decisions[]?.value // empty' 2>/dev/null || true
  } | grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}$' | sort -u | head -5000
)

{
  echo "# сгенерировано awgsec-sync-caddy, не править руками"
  if [[ -n "$ips" ]]; then
    echo "@awgsecBanned remote_ip $(echo "$ips" | tr '\n' ' ')"
    echo "respond @awgsecBanned 403"
  fi
} >"$TMP"

if ! cmp -s "$TMP" "$OUT"; then
  mv "$TMP" "$OUT"
  docker exec caddy caddy reload --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 \
    || echo "reload caddy не удался" >&2
  echo "caddy blocklist updated: $(echo "$ips" | grep -c . || true) ips"
else
  rm -f "$TMP"
fi
SYNC
  run chmod 0755 /usr/local/sbin/awgsec-sync-caddy

  write_file /etc/systemd/system/awgsec-sync-caddy.service <<'EOF'
[Unit]
Description=awgsec: sync blocklist to Caddy
After=docker.service crowdsec.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/awgsec-sync-caddy
EOF

  write_file /etc/systemd/system/awgsec-sync-caddy.timer <<'EOF'
[Unit]
Description=awgsec: sync blocklist to Caddy every minute

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s

[Install]
WantedBy=timers.target
EOF

  run systemctl daemon-reload
  run systemctl enable --now awgsec-sync-caddy.timer

  # Сниппет подключается в Caddyfile: import /etc/caddy/blocklist.caddy
  if [[ -f /etc/caddy/Caddyfile ]] && ! grep -q 'blocklist.caddy' /etc/caddy/Caddyfile; then
    warn "в /etc/caddy/Caddyfile нет 'import ${CADDY_BLOCK}' — добавь строкой в site-блок, иначе слой Caddy не работает"
  fi
  ok "таймер awgsec-sync-caddy активен"
}

# ── status ───────────────────────────────────────────────────────────────────
cmd_status() {
  echo "awg-host-hardening v${VERSION}"
  echo
  echo "BBR:      $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?') / qdisc $(sysctl -n net.core.default_qdisc 2>/dev/null || echo '?')"
  echo -n "nft set:  "
  nft list set inet "$NFT_TABLE" "$NFT_SET" >/dev/null 2>&1 && echo "активна" || echo "НЕТ"
  echo "забанено (awgsec): $("$SEC_BIN" list 2>/dev/null | wc -l)"
  echo
  if command -v fail2ban-client >/dev/null; then
    echo "fail2ban: $(systemctl is-active fail2ban 2>/dev/null)"
    fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:\s*/\  jails: /p'
    for j in $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:\s*//p' | tr ',' ' '); do
      printf '  %-18s banned=%s\n' "$j" "$(fail2ban-client status "$j" 2>/dev/null | sed -n 's/.*Currently banned:\s*//p')"
    done
  fi
  echo
  if command -v cscli >/dev/null; then
    echo "crowdsec: $(systemctl is-active crowdsec 2>/dev/null)"
    echo "  решений: $(cscli decisions list -o json 2>/dev/null | jq 'length' 2>/dev/null || echo '?')"
    echo "  community (CAPI): $(cscli capi status 2>/dev/null | grep -c . >/dev/null && echo 'ok' || echo 'нет')"
  fi
  echo
  echo "сканеры в логе панели ($PANEL_LOG):"
  [[ -f "$PANEL_LOG" ]] && grep -cE '"(GET|POST) /(\.env|\.git|phpinfo|wp-|docker-compose)' "$PANEL_LOG" 2>/dev/null || echo "  лог не найден"
}

# ── uninstall ────────────────────────────────────────────────────────────────
cmd_uninstall() {
  step "Снятие защиты"
  run systemctl disable --now awgsec-sync-caddy.timer 2>/dev/null || true
  run systemctl disable --now awgsec-restore.service 2>/dev/null || true
  run rm -f /etc/systemd/system/awgsec-sync-caddy.{service,timer} /etc/systemd/system/awgsec-restore.service
  run systemctl daemon-reload
  run nft delete table inet "$NFT_TABLE" 2>/dev/null || true
  run rm -f /etc/sysctl.d/99-awgsec-bbr.conf /etc/modules-load.d/awgsec-bbr.conf
  run rm -f /etc/fail2ban/jail.local /etc/fail2ban/filter.d/awg-panel-*.conf /etc/fail2ban/action.d/awgsec.conf
  run systemctl restart fail2ban 2>/dev/null || true
  run rm -rf "$SEC_DIR" "$SEC_BIN" /usr/local/sbin/awgsec-sync-caddy "$CADDY_BLOCK"
  warn "CrowdSec не удаляется автоматически: apt purge crowdsec crowdsec-firewall-bouncer"
  warn "sysctl: значения из 99-awgsec-bbr.conf применены до перезагрузки — вернутся после reboot"
  ok "готово"
}

# ── main ─────────────────────────────────────────────────────────────────────
case "$CMD" in
  install)
    require_root
    log "awg-host-hardening v${VERSION}$( ((DRY_RUN)) && echo ' [DRY-RUN]')"
    install_base
    setup_bbr
    setup_nft
    setup_fail2ban
    setup_crowdsec
    setup_caddy
    echo
    log "Готово. Проверка: $0 status"
    ;;
  status)
    cmd_status
    ;;
  uninstall)
    require_root
    cmd_uninstall
    ;;
  *)
    err "неизвестная команда: $CMD (install|status|uninstall)"
    exit 2
    ;;
esac

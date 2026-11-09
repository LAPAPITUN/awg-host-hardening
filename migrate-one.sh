#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# migrate-one.sh — переезд панели AmneziaWG на новую машину ОДНОЙ командой.
#
# Запускать НА НОВОЙ машине под root:
#   curl -fsSL https://raw.githubusercontent.com/LAPAPITUN/awg-host-hardening/master/migrate-one.sh | bash
#
# Что спросит: адрес старой машины, доступ (ключ или пароль). Всё остальное — само:
# docker, инструменты, экспорт состояния со старого, перенос, импорт, хост-защита,
# модуль ядра, сертификат Caddy, запуск панели, проверка.
#
# Флаги (можно без интерактива):
#   --old HOST            адрес старой машины (IP или домен)     [спросит]
#   --user USER           SSH-пользователь старой машины        [root]
#   --port N              SSH-порт старой машины                [22]
#   --password            спросить пароль старой машины (sshpass)
#   --key PATH            приватный ключ для старой машины
#   --proxy CMD           ProxyCommand для старой машины, напр.
#                         'nc -X 5 -x 127.0.0.1:1081 %h %p'
#   --new-ip IP           внешний IP этой машины                [определит сам]
#   --keep-security       перенести блок-лист /etc/awgsec
#   --pull-only           только забрать бандл со старого (без импорта)
#   --yes                 не задавать вопросов
#   --dry-run             показать план, ничего не делать
#
# Требования: root на новой машине, SSH-доступ к старой (ключ или пароль).
# Старая машина НЕ останавливается: откат = вернуть DNS на старый IP.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

VERSION="1.1.0"
REPO="LAPAPITUN/awg-host-hardening"
BRANCH="master"
REPO_TGZ="https://codeload.github.com/${REPO}/tar.gz/refs/heads/${BRANCH}"
TOOLS_DIR="/root/awg-host-hardening"
REMOTE_DIR="/root/awg-host-hardening"
BUNDLE="/root/panel-migrate.tgz"

OLD_HOST=""; OLD_USER="root"; OLD_PORT="22"; OLD_PASS=""; OLD_KEY=""; OLD_PROXY=""
NEW_IP=""; DO_IMPORT=1; KEEP_SECURITY=0; ASSUME_YES=0; DRY_RUN=0; PULL_ONLY=0

C_0=$'\033[0m'; C_B=$'\033[1m'; C_G=$'\033[32m'; C_Y=$'\033[33m'; C_R=$'\033[31m'; C_D=$'\033[2m'
step() { printf '\n%s== %s ==%s\n' "$C_B" "$*" "$C_0"; }
ok()   { printf '  %s✓%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '  %s!%s %s\n' "$C_Y" "$C_0" "$*"; }
err()  { printf '  %s✗%s %s\n' "$C_R" "$C_0" "$*" >&2; }
log()  { printf '%s[migrate-one]%s %s\n' "$C_B" "$C_0" "$*"; }
die()  { err "$*"; exit 1; }
run()  { if (( DRY_RUN )); then printf '  %s+ %s%s\n' "$C_D" "$*" "$C_0"; else "$@"; fi; }

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --old)            OLD_HOST="${2:?}"; shift ;;
    --user)           OLD_USER="${2:?}"; shift ;;
    --port)           OLD_PORT="${2:?}"; shift ;;
    --password)       OLD_PASS="__ASK__"; shift ;;
    --key)            OLD_KEY="${2:?}"; shift ;;
    --proxy)          OLD_PROXY="${2:?}"; shift ;;
    --new-ip)         NEW_IP="${2:?}"; shift ;;
    --keep-security)  KEEP_SECURITY=1 ;;
    --pull-only)      PULL_ONLY=1 ;;
    --yes|-y)         ASSUME_YES=1 ;;
    --dry-run)        DRY_RUN=1 ;;
    -h|--help)        usage ;;
    *) die "неизвестный аргумент: $1 (--help)" ;;
  esac
  shift
done

[[ $EUID -eq 0 ]] || die "запускать под root"

# ── SSH к старой машине ──────────────────────────────────────────────────────
SSH_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=12 -p "$OLD_PORT")
SCP_OPTS=(-o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=12 -P "$OLD_PORT")
if [[ -n "$OLD_PROXY" ]]; then
  SSH_OPTS+=(-o "ProxyCommand=$OLD_PROXY")
  SCP_OPTS+=(-o "ProxyCommand=$OLD_PROXY")
fi
[[ -n "$OLD_KEY" ]] && { SSH_OPTS+=(-i "$OLD_KEY"); SCP_OPTS+=(-i "$OLD_KEY"); }

ask_old_host() {
  if [[ -z "$OLD_HOST" ]]; then
    printf 'Адрес старой машины (IP или домен): '
    read -r OLD_HOST
  fi
  [[ -n "$OLD_HOST" ]] || die "не указан адрес старой машины"
}

ssh_old() {
  if [[ -n "$OLD_PASS" && "$OLD_PASS" != "__ASK__" ]]; then
    SSHPASS="$OLD_PASS" sshpass -e ssh "${SSH_OPTS[@]}" "$OLD_USER@$OLD_HOST" "$@"
  else
    ssh "${SSH_OPTS[@]}" "$OLD_USER@$OLD_HOST" "$@"
  fi
}

scp_old() {  # scp_old SRC DST  (направление задаётся префиксом host:)
  if [[ -n "$OLD_PASS" && "$OLD_PASS" != "__ASK__" ]]; then
    SSHPASS="$OLD_PASS" sshpass -e scp "${SCP_OPTS[@]}" "$@"
  else
    scp "${SCP_OPTS[@]}" "$@"
  fi
}

need_pkg() { command -v "$1" >/dev/null 2>&1; }

install_deps() {
  step "Зависимости на этой машине"
  local miss=()
  need_pkg curl || miss+=(curl)
  need_pkg tar  || miss+=(tar)
  need_pkg python3 || miss+=(python3)
  need_pkg ssh  || miss+=(openssh-client)
  if (( ${#miss[@]} )); then
    log "ставлю: ${miss[*]}"
    run env DEBIAN_FRONTEND=noninteractive apt-get update -qq
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${miss[@]}"
  fi
  if ! need_pkg docker; then
    log "docker нет — устанавливаю"
    run env DEBIAN_FRONTEND=noninteractive apt-get update -qq
    run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io docker-compose-v2 \
      || run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io docker-compose-plugin
    run systemctl enable --now docker
  fi
  ok "docker: $(docker --version 2>/dev/null | cut -d, -f1 || echo '?')"
}

# ── 1. Инструменты ───────────────────────────────────────────────────────────
fetch_tools() {
  step "Инструменты переезда"
  if [[ -x "$TOOLS_DIR/migrate.sh" ]] && [[ -x "$TOOLS_DIR/install.sh" ]]; then
    ok "уже на месте: $TOOLS_DIR"
    return
  fi
  local tmp; tmp=$(mktemp -d)
  run curl -fsSL "$REPO_TGZ" -o "$tmp/repo.tgz"
  run tar xzf "$tmp/repo.tgz" -C "$tmp"
  local src; src=$(find "$tmp" -maxdepth 1 -type d -name 'awg-host-hardening-*' | head -1)
  [[ -n "$src" ]] || die "не удалось распаковать репозиторий"
  run mkdir -p "$TOOLS_DIR"
  run cp -a "$src/." "$TOOLS_DIR/"
  run chmod +x "$TOOLS_DIR/migrate.sh" "$TOOLS_DIR/install.sh"
  rm -rf "$tmp"
  ok "скрипты в $TOOLS_DIR"
}

# ── 2. Доступ к старой машине ────────────────────────────────────────────────
check_old_access() {
  step "Доступ к старой машине"
  ask_old_host
  if (( DRY_RUN )); then ok "проверка пропущена (--dry-run)"; return; fi

  if ssh_old true 2>/dev/null; then
    ok "SSH по ключу: $OLD_USER@$OLD_HOST:$OLD_PORT"
    return
  fi
  if [[ "$OLD_PASS" == "__ASK__" || -z "$OLD_PASS" ]]; then
    printf 'Пароль %s@%s (не отображается): ' "$OLD_USER" "$OLD_HOST"
    read -rs OLD_PASS; echo
  fi
  need_pkg sshpass || {
    log "ставлю sshpass"
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq sshpass >/dev/null
  }
  SSHPASS="$OLD_PASS" sshpass -e ssh "${SSH_OPTS[@]}" "$OLD_USER@$OLD_HOST" true 2>/dev/null \
    || die "не пускает по паролю. Проверь адрес/порт/логин и что PermitRootLogin разрешён"
  ok "SSH по паролю: $OLD_USER@$OLD_HOST:$OLD_PORT"
}

# ── 3. Экспорт со старой машины ──────────────────────────────────────────────
do_export() {
  step "Экспорт состояния со старой машины"
  local remote="${REMOTE_DIR}"
  ssh_old "mkdir -p '$remote'"
  log "копирую инструменты на старую машину"
  scp_old -r "$TOOLS_DIR/migrate.sh" "$TOOLS_DIR/install.sh" \
             "$TOOLS_DIR/kernel-module" "$TOOLS_DIR/panel-agent" \
             "$TOOLS_DIR/docs" "$TOOLS_DIR/README.md" "$OLD_USER@$OLD_HOST:$remote/" >/dev/null
  ssh_old "chmod +x '$remote/migrate.sh' '$remote/install.sh'"

  local extra=()
  (( KEEP_SECURITY )) && extra+=(--keep-security)
  local out="/root/panel-migrate.tgz"
  ssh_old "'$remote/migrate.sh' export --out '$out' ${extra[*]:-} 2>&1 | tail -8"
  scp_old "$OLD_USER@$OLD_HOST:$out" "$BUNDLE" >/dev/null
  run chmod 600 "$BUNDLE"
  ok "бандл: $BUNDLE ($(du -h "$BUNDLE" | cut -f1), sha256 $(sha256sum "$BUNDLE" | cut -c1-16)…)"
}

# ── 4. Импорт на этой машине ─────────────────────────────────────────────────
do_import() {
  step "Состав бандла"
  "$TOOLS_DIR/migrate.sh" inspect --bundle "$BUNDLE" 2>&1 | tail -22

  if (( PULL_ONLY )); then
    ok "остановился после экспорта (--pull-only)"
    return
  fi
  if (( ! ASSUME_YES )); then
    printf '\nРазвернуть это на этой машине? [y/N] '
    local a; read -r a
    [[ "$a" =~ ^[YyДд]$ ]] || die "отменено"
  fi

  step "Импорт и запуск"
  "$TOOLS_DIR/migrate.sh" import --bundle "$BUNDLE" --force 2>&1 | tail -30
}

# ── 5. Проверка ──────────────────────────────────────────────────────────────
post_check() {
  (( PULL_ONLY )) && return 0
  step "Проверка"
  docker ps --format '  {{.Names}}\t{{.Status}}' 2>/dev/null || true
  local domain
  domain=$(awk 'NF && $1 !~ /^#/ && $1 !~ /^\{/ {print $1; exit}' /opt/my-wg-panel/Caddyfile 2>/dev/null || true)
  if [[ -n "$domain" ]]; then
    curl -skS -m 8 --resolve "$domain:443:127.0.0.1" -o /dev/null \
         -w "  локально https ($domain): %{http_code}\n" "https://$domain" 2>/dev/null \
      || warn "локальный https не ответил"
  fi
  "$TOOLS_DIR/migrate.sh" verify 2>&1 | tail -25 || warn "verify вернул замечания — смотри выше"

  step "Что дальше"
  cat <<EOF
  1. DNS домена панели → ${NEW_IP:-<внешний IP этой машины>} (если ещё не переключён).
  2. Клиенты подхватят сами (в конфиге endpoint — домен).
  3. Старую машину НЕ гасить, пока не убедишься, что все пиры на связи.
  4. Удалить бандл с приватными ключами: shred -u $BUNDLE
EOF
}

# ── main ─────────────────────────────────────────────────────────────────────
main() {
  log "migrate-one v$VERSION$( ((DRY_RUN)) && echo ' [DRY-RUN]')"
  install_deps
  fetch_tools
  if [[ -z "$NEW_IP" ]]; then
    NEW_IP=$(curl -fsS -m 8 https://api.ipify.org 2>/dev/null || true)
  fi
  [[ -n "$NEW_IP" ]] && ok "внешний IP этой машины: $NEW_IP"

  check_old_access
  do_export
  do_import
  post_check
  log "готово"
}

main "$@"
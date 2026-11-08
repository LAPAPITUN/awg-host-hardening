#!/usr/bin/env bash
#
# migrate.sh — переезд панели AmneziaWG на новую машину одной командой.
#
# Переносит СОСТОЯНИЕ, а не машину:
#   панель   : серверы, клиенты, ключи, настройки, nginx-конфиг, compose, .env, Caddyfile
#   сертифик : volume caddy_data (сертификат и ACME-аккаунт), чтобы панель открылась сразу
#   защита   : блок-лист, источники банов (по флагу --keep-security)
#   хост     : BBR, nftables, fail2ban, CrowdSec, агент панели, модуль ядра — ставятся
#              на новой машине тем же install.sh, а не копируются
#
# Использование:
#   ./migrate.sh migrate --to root@NEW_IP [--domain newserv.example.ru] [--stage]
#   ./migrate.sh export  --out /tmp/panel.tar.gz
#   ./migrate.sh import  --bundle /tmp/panel.tar.gz [--stage] [--no-host-setup]
#   ./migrate.sh verify
#   ./migrate.sh inspect --bundle /tmp/panel.tar.gz
#
# Флаги:
#   --to user@host        целевая машина (migrate)
#   --panel-dir PATH      каталог панели (по умолчанию /opt/my-wg-panel)
#   --out PATH            путь к бандлу (export)
#   --bundle PATH         путь к бандлу (import/inspect)
#   --domain NAME         домен панели; если задан — проверяется/правится Caddyfile
#   --stage               НЕ запускать caddy: панель поднимается, но старый сервер
#                         продолжает обслуживать домен до переключения DNS
#   --keep-security       перенести блок-лист и журнал источников
#   --no-host-setup       не ставить хост-защиту (только файлы панели)
#   --no-kernel-module    не собирать модуль ядра
#   --update-endpoint V   endpoint в web_config.json: "auto" = новый внешний IP,
#                         либо явное значение (домен/IP). Нужно, если клиенты ходят по IP.
#   --force               перезаписать существующий каталог панели (со бэкапом)
#   --no-start            разложить файлы, но не поднимать контейнеры
#   --dry-run             показать план, ничего не менять
#
set -euo pipefail

readonly VERSION="1.0.0"
readonly BUNDLE_FORMAT="awgsec-migration/1"
readonly DEFAULT_PANEL_DIR="/opt/my-wg-panel"
readonly TOOL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PANEL_DIR="$DEFAULT_PANEL_DIR"
TARGET=""
BUNDLE=""
DOMAIN=""
STAGE=0
KEEP_SECURITY=0
HOST_SETUP=1
KERNEL_MODULE=1
UPDATE_ENDPOINT=""
FORCE=0
DRY_RUN=0
NO_START=0

if [[ -t 1 ]]; then
  C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_B=$'\e[34m'; C_D=$'\e[2m'; C_0=$'\e[0m'
else
  C_R=""; C_G=""; C_Y=""; C_B=""; C_D=""; C_0=""
fi
log()  { printf '%s[migrate]%s %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '%s  ✓%s %s\n' "$C_G" "$C_0" "$*"; }
warn() { printf '%s  !%s %s\n' "$C_Y" "$C_0" "$*"; }
err()  { printf '%s  ✗%s %s\n' "$C_R" "$C_0" "$*" >&2; }
die()  { err "$*"; exit 1; }
step() { printf '\n%s== %s ==%s\n' "$C_D" "$*" "$C_0"; }
run()  { if (( DRY_RUN )); then printf '%s    + %s%s\n' "$C_D" "$*" "$C_0"; else "$@"; fi; }

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0; }

CMD="${1:-}"
[[ -z "$CMD" || "$CMD" == "-h" || "$CMD" == "--help" ]] && usage
shift || true

while (( $# )); do
  case "$1" in
    --to)              TARGET="${2:?--to требует user@host}"; shift ;;
    --panel-dir)       PANEL_DIR="${2:?--panel-dir требует путь}"; shift ;;
    --out)             BUNDLE="${2:?--out требует путь}"; shift ;;
    --bundle)          BUNDLE="${2:?--bundle требует путь}"; shift ;;
    --domain)          DOMAIN="${2:?--domain требует имя}"; shift ;;
    --stage)           STAGE=1 ;;
    --keep-security)   KEEP_SECURITY=1 ;;
    --no-host-setup)   HOST_SETUP=0 ;;
    --no-kernel-module) KERNEL_MODULE=0 ;;
    --update-endpoint) UPDATE_ENDPOINT="${2:?--update-endpoint требует значение}"; shift ;;
    --force)           FORCE=1 ;;
    --no-start)        NO_START=1 ;;
    --dry-run)         DRY_RUN=1 ;;
    -h|--help)         usage ;;
    *) err "неизвестный флаг: $1"; exit 2 ;;
  esac
  shift
done

# ─────────────────────────────────────────────────────────────────────────────
# Вспомогательное
# ─────────────────────────────────────────────────────────────────────────────

need_root() { [[ $EUID -eq 0 ]] || die "нужен root"; }

compose_cmd() {
  if docker compose version >/dev/null 2>&1; then echo "docker compose"
  elif command -v docker-compose >/dev/null; then echo "docker-compose"
  else die "не найден docker compose"; fi
}

env_get() {  # env_get KEY [file] — без вывода секретов наружу
  local key="$1" file="${2:-$PANEL_DIR/.env}"
  [[ -f "$file" ]] || return 0
  sed -n "s/^${key}=//p" "$file" | head -1
}

detect_domain() {
  [[ -f "$PANEL_DIR/Caddyfile" ]] || return 0
  grep -vE '^\s*(#|$|import|\})' "$PANEL_DIR/Caddyfile" | head -1 | awk '{print $1}'
}

public_ip() {
  local ip=""
  ip=$(curl -4 -fsS --max-time 8 https://ifconfig.me 2>/dev/null || true)
  [[ -z "$ip" ]] && ip=$(curl -4 -fsS --max-time 8 https://api.ipify.org 2>/dev/null || true)
  echo "$ip"
}

# Читает поле из web_config.json. $1 — python-выражение над словарём cfg.
cfg_query() {
  python3 - "$PANEL_DIR/amnezia/web_config.json" "$1" <<'PY'
import json, sys
path, expr = sys.argv[1], sys.argv[2]
try:
    cfg = json.load(open(path, encoding="utf-8"))
except Exception as exc:
    print(f"ERR {exc}")
    sys.exit(0)
srv = (cfg.get("servers") or [{}])[0]
env = {"cfg": cfg, "srv": srv, "sum": sum, "len": len, "str": str}
try:
    print(eval(expr, {"__builtins__": {}}, env))
except Exception as exc:
    print(f"ERR {exc}")
PY
}

# ─────────────────────────────────────────────────────────────────────────────
# export — собрать бандл из текущей машины
# ─────────────────────────────────────────────────────────────────────────────
cmd_export() {
  need_root
  [[ -d "$PANEL_DIR" ]] || die "нет каталога панели: $PANEL_DIR"
  [[ -f "$PANEL_DIR/amnezia/web_config.json" ]] || die "нет web_config.json — это не панель?"

  BUNDLE="${BUNDLE:-/root/awg-migrate-$(hostname -s)-$(date +%Y%m%d-%H%M).tar.gz}"
  local work; work=$(mktemp -d /tmp/awg-migrate.XXXXXX)
  local stage="$work/bundle"
  mkdir -p "$stage"/{panel/amnezia,panel/nginx,security,tool,caddy}

  log "Экспорт панели из $PANEL_DIR"
  step "Файлы панели"
  for f in docker-compose.yml .env Caddyfile; do
    if [[ -f "$PANEL_DIR/$f" ]]; then cp -p "$PANEL_DIR/$f" "$stage/panel/$f"; ok "$f"
    else warn "$f отсутствует"; fi
  done
  [[ -d "$PANEL_DIR/nginx" ]] && cp -a "$PANEL_DIR/nginx/." "$stage/panel/nginx/" && ok "nginx/"
  cp -p "$PANEL_DIR/amnezia/web_config.json" "$stage/panel/amnezia/web_config.json"
  ok "amnezia/web_config.json ($(cfg_query 'len(srv.get("clients") or [])') клиентов)"
  if [[ -d "$PANEL_DIR/amnezia/amneziawg" ]]; then
    cp -a "$PANEL_DIR/amnezia/amneziawg" "$stage/panel/amnezia/"
    ok "amnezia/amneziawg/ (конфиги интерфейсов)"
  fi

  step "Сертификат Caddy"
  local project caddy_vol
  project=$(basename "$PANEL_DIR" | tr -d '.-')
  caddy_vol=""
  for candidate in "${project}_caddy_data" "my-wg-panel_caddy_data" "$(basename "$PANEL_DIR")_caddy_data"; do
    if docker volume inspect "$candidate" >/dev/null 2>&1; then caddy_vol="$candidate"; break; fi
  done
  if [[ -n "$caddy_vol" ]]; then
    if (( DRY_RUN )); then
      printf '%s    + export volume %s%s\n' "$C_D" "$caddy_vol" "$C_0"
    else
      docker run --rm -v "${caddy_vol}:/data:ro" -v "${stage}/caddy:/backup" alpine:3.22 \
        tar czf /backup/caddy-data.tar.gz -C /data . 2>/dev/null && \
        ok "volume $caddy_vol ($(du -h "$stage/caddy/caddy-data.tar.gz" | cut -f1))"
    fi
  else
    warn "volume caddy_data не найден — сертификат получится заново при старте (нужен рабочий DNS)"
  fi

  step "Состояние защиты"
  if (( KEEP_SECURITY )); then
    local sec_found=0
    for f in blocked.txt sources.tsv; do
      if [[ -f "/etc/awgsec/$f" ]]; then
        cp -p "/etc/awgsec/$f" "$stage/security/$f"; ok "/etc/awgsec/$f"; sec_found=1
      fi
    done
    [[ -f /etc/awgsec/panel-agent.conf ]] && cp -p /etc/awgsec/panel-agent.conf "$stage/security/panel-agent.conf"
    (( sec_found )) || warn "на источнике нет /etc/awgsec/*.txt — переносить нечего"
  else
    warn "блок-лист не переносится (--keep-security, если нужен)"
  fi

  step "Инструменты (чтобы новой машине не нужен был git)"
  for item in install.sh migrate.sh kernel-module panel-agent docs README.md; do
    [[ -e "$TOOL_DIR/$item" ]] && cp -a "$TOOL_DIR/$item" "$stage/tool/" && ok "$item"
  done

  step "Манифест"
  python3 - "$stage" "$PANEL_DIR" "$VERSION" "$BUNDLE_FORMAT" <<'PY'
import hashlib, json, os, subprocess, sys, time

stage, panel_dir, version, fmt = sys.argv[1:5]

def sh(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=20).stdout.strip()
    except Exception:
        return ""

cfg_path = os.path.join(panel_dir, "amnezia", "web_config.json")
cfg = {}
try:
    cfg = json.load(open(cfg_path, encoding="utf-8"))
except Exception:
    pass
srv = (cfg.get("servers") or [{}])[0]

files = {}
for root, _, names in os.walk(stage):
    for name in names:
        full = os.path.join(root, name)
        rel = os.path.relpath(full, stage)
        if rel == "manifest.json":
            continue
        h = hashlib.sha256()
        with open(full, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        files[rel] = {"sha256": h.hexdigest(), "size": os.path.getsize(full)}

manifest = {
    "format": fmt,
    "tool_version": version,
    "created": int(time.time()),
    "created_iso": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    "source": {
        "hostname": sh("hostname -s"),
        "kernel": sh("uname -r"),
        "panel_dir": panel_dir,
        "public_ip": sh("curl -4 -fsS --max-time 8 https://ifconfig.me"),
        "docker": sh("docker version --format '{{.Server.Version}}'"),
    },
    "panel": {
        "server_id": srv.get("id"),
        "server_name": srv.get("name"),
        "interface": srv.get("interface"),
        "port": srv.get("port"),
        "subnet": srv.get("subnet"),
        "mtu": srv.get("mtu"),
        "endpoint": srv.get("endpoint") or srv.get("public_ip"),
        "clients": len(srv.get("clients") or []),
        "suspended": sum(1 for c in (srv.get("clients") or []) if c.get("status") == "suspended"),
        "obfuscation": {
            "enabled": bool(srv.get("obfuscation_enabled")),
            "params": srv.get("obfuscation_params") or {},
        },
    },
    "host_state": {
        "bbr": sh("sysctl -n net.ipv4.tcp_congestion_control"),
        "qdisc": sh("sysctl -n net.core.default_qdisc"),
        "kernel_module": "yes" if os.path.isdir("/sys/module/amneziawg") else "no",
        "dkms": sh("dkms status 2>/dev/null | grep amneziawg || true"),
        "fail2ban": sh("systemctl is-active fail2ban"),
        "crowdsec": sh("systemctl is-active crowdsec"),
        "crowdsec_bouncer": sh("systemctl is-active crowdsec-firewall-bouncer"),
        "panel_agent": sh("systemctl is-active awgsec-panel-agent.timer"),
        "blocked_count": (sh("nft list set inet awgsec blocked_ipv4 2>/dev/null | grep -c expires") or "0").splitlines()[0],
    },
    "files": files,
}
json.dump(manifest, open(os.path.join(stage, "manifest.json"), "w", encoding="utf-8"),
          ensure_ascii=False, indent=1)
print(f"  ✓ манифест: {len(files)} файлов")
PY

  step "Упаковка"
  # Права 600: внутри приватные ключи клиентов и сервера
  run tar czf "$BUNDLE" -C "$work" bundle
  run chmod 600 "$BUNDLE"
  if (( ! DRY_RUN )); then
    ok "бандл: $BUNDLE ($(du -h "$BUNDLE" | cut -f1))"
    ok "sha256: $(sha256sum "$BUNDLE" | cut -d' ' -f1)"
    echo
    log "Перенос на новую машину:"
    printf '    scp %s root@NEW_IP:/root/\n' "$BUNDLE"
    printf '    ssh root@NEW_IP "tar xzf /root/%s -C /root && /root/bundle/tool/migrate.sh import --bundle /root/%s"\n' \
      "$(basename "$BUNDLE")" "$(basename "$BUNDLE")"
    log "или одной командой с этой машины:"
    printf '    %s migrate --to root@NEW_IP\n' "$0"
  fi
  rm -rf "$work"
}

# ─────────────────────────────────────────────────────────────────────────────
# import — развернуть бандл на этой машине
# ─────────────────────────────────────────────────────────────────────────────
cmd_import() {
  need_root
  [[ -n "$BUNDLE" ]] || die "укажи --bundle /path/to/bundle.tar.gz"
  [[ -f "$BUNDLE" ]] || die "нет файла: $BUNDLE"

  local work; work=$(mktemp -d /tmp/awg-import.XXXXXX)
  trap 'rm -rf "${work:-}"' EXIT
  tar xzf "$BUNDLE" -C "$work"
  local stage="$work/bundle"
  [[ -d "$stage" ]] || die "в бандле нет каталога bundle/"

  log "Проверка бандла"
  python3 - "$stage" "$BUNDLE_FORMAT" <<'PY'
import hashlib, json, os, sys
stage, fmt = sys.argv[1], sys.argv[2]
m = json.load(open(os.path.join(stage, "manifest.json"), encoding="utf-8"))
if m.get("format") != fmt:
    sys.exit(f"  ✗ формат бандла {m.get('format')}, ожидался {fmt}")
bad = []
for rel, meta in (m.get("files") or {}).items():
    full = os.path.join(stage, rel)
    if not os.path.exists(full):
        bad.append(f"{rel}: отсутствует"); continue
    h = hashlib.sha256()
    with open(full, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    if h.hexdigest() != meta["sha256"]:
        bad.append(f"{rel}: контрольная сумма не совпала")
if bad:
    print("\n".join("  ✗ " + b for b in bad))
    sys.exit(1)
p = m["panel"]
print(f"  ✓ бандл от {m['created_iso']} ({m['source']['hostname']}, kernel {m['source']['kernel']})")
print(f"  ✓ панель: сервер {p['server_id']} / {p['interface']}, порт {p['port']}, "
      f"клиентов {p['clients']} (приостановлено {p['suspended']}), endpoint {p['endpoint']}")
PY

  step "Preflight новой машины"
  command -v docker >/dev/null || die "нет docker"
  docker compose version >/dev/null 2>&1 || docker-compose --version >/dev/null 2>&1 || die "нет docker compose"
  ok "docker $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '?')"

  local avail_kb
  avail_kb=$(df -Pk /var/lib/docker 2>/dev/null | awk 'NR==2{print $4}')
  if [[ -n "$avail_kb" && "$avail_kb" -lt 2097152 ]]; then
    warn "на /var/lib/docker меньше 2 ГБ свободно ($((avail_kb/1024)) МБ)"
  else
    ok "место на диске: $(( ${avail_kb:-0} / 1024 )) МБ свободно"
  fi

  local wg_port
  wg_port=$(env_get WG_PORT "$stage/panel/.env"); wg_port="${wg_port:-51820}"
  if ss -lun 2>/dev/null | grep -q ":${wg_port} "; then
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx amnezia; then
      warn "порт ${wg_port}/udp занят контейнером amnezia — это повторный импорт, продолжаю"
    else
      die "порт ${wg_port}/udp занят другим процессом — освободи его"
    fi
  else
    ok "порт ${wg_port}/udp свободен"
  fi
  for p in 80 443; do
    if ss -ltn 2>/dev/null | grep -q ":${p} "; then
      docker ps --format '{{.Names}}' 2>/dev/null | grep -qx caddy || warn "порт ${p}/tcp занят не нашим caddy"
    fi
  done

  step "Инструменты на новой машине"
  if [[ -d "$stage/tool" ]]; then
    run mkdir -p /root/awg-host-hardening
    run cp -a "$stage/tool/." /root/awg-host-hardening/
    run chmod +x /root/awg-host-hardening/install.sh /root/awg-host-hardening/migrate.sh 2>/dev/null || true
    ok "скрипты в /root/awg-host-hardening (verify, повторный переезд)"
  fi

  step "Файлы панели → $PANEL_DIR"
  if [[ -d "$PANEL_DIR" ]] && [[ -n "$(ls -A "$PANEL_DIR" 2>/dev/null)" ]]; then
    if (( FORCE )); then
      local backup="${PANEL_DIR}.backup-$(date +%Y%m%d-%H%M%S)"
      run mv "$PANEL_DIR" "$backup"
      ok "старый каталог сохранён: $backup"
    else
      die "каталог $PANEL_DIR уже существует. Нужен --force (сделает бэкап) или другой --panel-dir"
    fi
  fi
  run mkdir -p "$PANEL_DIR"/{amnezia,nginx,logs,security,blocklist}
  run cp -a "$stage/panel/." "$PANEL_DIR/"
  run chmod 700 "$PANEL_DIR/amnezia" "$PANEL_DIR/amnezia/amneziawg" 2>/dev/null || true
  run chmod 600 "$PANEL_DIR/.env" "$PANEL_DIR/amnezia/web_config.json" 2>/dev/null || true
  run chmod 644 "$PANEL_DIR/docker-compose.yml" "$PANEL_DIR/Caddyfile" 2>/dev/null || true
  ok "файлы панели разложены (права 600 на ключи)"

  # Compose со старой машины может быть старше вкладки «Безопасность»: без этих
  # монтирований панель поднимется, но не увидит nginx-конфиг, логи и очередь
  # блокировок. Дописываем недостающее, не переписывая файл.
  step "Монтирования в compose"
  if (( DRY_RUN )); then
    printf '%s    + проверить ./nginx, ./logs, ./security в docker-compose.yml%s\n' "$C_D" "$C_0"
  else
    python3 - "$PANEL_DIR/docker-compose.yml" <<'PY'
import re, sys
path = sys.argv[1]
s = open(path, encoding="utf-8").read()
needed = [
    ("./nginx:/etc/nginx/http.d", "      - ./nginx:/etc/nginx/http.d\n"),
    ("./logs:/var/log/nginx", "      - ./logs:/var/log/nginx\n"),
    ("./security:/var/lib/awgsec", "      - ./security:/var/lib/awgsec\n"),
]
missing = [(k, line) for k, line in needed if k not in s]
if not missing:
    print("  ✓ nginx, logs, security уже смонтированы")
else:
    # точка вставки — строка с монтированием amnezia, иначе первый volumes:
    anchor = re.search(r"^[ \t]*- \./amnezia:/etc/amnezia[ \t]*$", s, re.M)
    if anchor:
        pos = anchor.end() + 1
        s = s[:pos] + "".join(line for _, line in missing) + s[pos:]
    else:
        m = re.search(r"^[ \t]*volumes:[ \t]*$", s, re.M)
        if not m:
            sys.exit("  ✗ в compose нет volumes: — добавь монтирования вручную")
        pos = m.end() + 1
        s = s[:pos] + "".join(line for _, line in missing) + s[pos:]
    open(path, "w", encoding="utf-8").write(s)
    print("  ✓ добавлено: " + ", ".join(k for k, _ in missing))
PY
  fi

  if [[ -n "$DOMAIN" ]]; then
    step "Домен в Caddyfile"
    if (( DRY_RUN )); then
      printf '%s    + домен %s%s\n' "$C_D" "$DOMAIN" "$C_0"
    else
      local current; current=$(detect_domain)
      if [[ "$current" == "$DOMAIN" ]]; then ok "домен уже $DOMAIN"
      else
        python3 - "$PANEL_DIR/Caddyfile" "$DOMAIN" <<'PY'
import re, sys
path, domain = sys.argv[1], sys.argv[2]
s = open(path, encoding="utf-8").read()
s = re.sub(r'^[^\s#][^\s{]*(\s*\{)', domain + r'\1', s, count=1, flags=re.M)
open(path, "w", encoding="utf-8").write(s)
print(f"  ✓ домен в Caddyfile: {domain}")
PY
      fi
    fi
  fi

  if (( KEEP_SECURITY )) && [[ -d "$stage/security" ]]; then
    step "Блок-лист"
    run mkdir -p /etc/awgsec
    for f in blocked.txt sources.tsv; do
      [[ -f "$stage/security/$f" ]] && run cp -p "$stage/security/$f" "/etc/awgsec/$f" && ok "$f"
    done
  fi

  # Endpoint в web_config.json: если клиенты ходят по IP, а машина новая — без правки
  # они не подключатся. Домен менять не нужно: он указывает на новую машину через DNS.
  if [[ -n "$UPDATE_ENDPOINT" ]]; then
    step "Endpoint для клиентов"
    local new_ep="$UPDATE_ENDPOINT"
    if [[ "$new_ep" == "auto" ]]; then
      new_ep=$(public_ip)
      [[ -n "$new_ep" ]] || die "не удалось определить внешний IP (--update-endpoint <значение>)"
    fi
    if (( DRY_RUN )); then
      printf '%s    + endpoint -> %s%s\n' "$C_D" "$new_ep" "$C_0"
    else
      python3 - "$PANEL_DIR/amnezia/web_config.json" "$new_ep" <<'PY'
import json, os, sys, tempfile
path, new_ep = sys.argv[1], sys.argv[2]
cfg = json.load(open(path, encoding="utf-8"))
changed = 0
for srv in cfg.get("servers") or []:
    if srv.get("endpoint") != new_ep:
        srv["endpoint"] = new_ep
        srv["public_ip"] = new_ep
        changed += 1
if changed:
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), suffix=".tmp")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)
print(f"  ✓ endpoint обновлён: {new_ep} (серверов: {changed})")
PY
    fi
  else
    local ep; ep=$(cfg_query 'srv.get("endpoint") or srv.get("public_ip")')
    if [[ -n "$ep" && "$ep" =~ ^[0-9.]+$ ]]; then
      warn "endpoint в конфиге — IP ($ep). Если новая машина с другим IP, клиенты не подключатся."
      warn "исправить: --update-endpoint auto   (или домен вместо IP)"
    fi
  fi

  if (( HOST_SETUP )); then
    step "Хост: BBR, nftables, fail2ban, CrowdSec, агент панели"
    if [[ -x "$stage/tool/install.sh" ]]; then
      local extra=()
      (( KERNEL_MODULE )) && extra+=(--with-kernel-module)
      (( DRY_RUN )) && extra+=(--dry-run)
      run bash "$stage/tool/install.sh" install --panel-dir "$PANEL_DIR/security" "${extra[@]}"
    else
      warn "в бандле нет install.sh — хост-защита не настроена"
    fi
  else
    warn "хост-защита пропущена (--no-host-setup)"
  fi

  step "Сертификат Caddy"
  if [[ -f "$stage/caddy/caddy-data.tar.gz" ]]; then
    if (( DRY_RUN )); then
      printf '%s    + восстановить volume caddy_data%s\n' "$C_D" "$C_0"
    else
      local vol; vol="$(basename "$PANEL_DIR")_caddy_data"
      docker volume inspect "$vol" >/dev/null 2>&1 || docker volume create "$vol" >/dev/null
      docker run --rm -v "${vol}:/data" -v "${stage}/caddy:/backup:ro" alpine:3.22 \
        sh -c 'cd /data && tar xzf /backup/caddy-data.tar.gz' && ok "volume $vol восстановлен"
    fi
  else
    warn "сертификата в бандле нет — Caddy выпустит новый (нужен DNS на эту машину)"
  fi

  step "Запуск"
  local dc; dc=$(compose_cmd)
  if (( NO_START )); then
    warn "контейнеры не запущены (--no-start): cd $PANEL_DIR && $dc up -d"
  elif (( STAGE )); then
    run bash -c "cd '$PANEL_DIR' && $dc up -d amnezia"
    warn "caddy НЕ запущен (--stage): домен пока обслуживает старая машина"
    printf '    после переключения DNS: cd %s && %s up -d\n' "$PANEL_DIR" "$dc"
  else
    run bash -c "cd '$PANEL_DIR' && $dc up -d"
  fi

  if (( ! DRY_RUN )) && (( ! NO_START )); then
    sleep 8
    step "Проверка"
    cmd_verify || warn "проверка нашла замечания (см. выше)"
  elif (( NO_START )); then
    warn "проверка пропущена (--no-start): запусти контейнеры и выполни '$0 verify'"
  fi
}

# ─────────────────────────────────────────────────────────────────────────────
# verify — состояние панели и хоста
# ─────────────────────────────────────────────────────────────────────────────
cmd_verify() {
  local fails=0

  step "Панель"
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx amnezia; then
    ok "контейнер amnezia: $(docker inspect -f '{{.State.Status}}' amnezia 2>/dev/null)"
  else
    err "контейнер amnezia не запущен"; fails=$((fails+1))
  fi
  if docker exec amnezia curl -fsS -m 5 http://127.0.0.1/status >/dev/null 2>&1; then
    ok "nginx внутри контейнера отвечает"
  else
    err "nginx внутри контейнера не отвечает"; fails=$((fails+1))
  fi

  local peers=0
  peers=$(docker exec amnezia awg show 2>/dev/null | grep -c '^peer:' || true)
  [[ "$peers" -gt 0 ]] && ok "пиров в интерфейсе: $peers" || { err "пиров не найдено"; fails=$((fails+1)); }

  local hs
  hs=$(docker exec amnezia awg show 2>/dev/null | grep -c 'latest handshake' || true)
  ok "свежих handshake: ${hs:-0} из ${peers:-0}"

  step "Туннель"
  if [[ -d /sys/module/amneziawg ]]; then
    ok "модуль ядра amneziawg загружен (userspace не нужен)"
    pgrep -c amneziawg-go >/dev/null 2>&1 && warn "amneziawg-go всё ещё запущен — перезапусти контейнер"
  else
    local go_count; go_count=$(pgrep -c amneziawg-go 2>/dev/null || true); go_count="${go_count:-0}"
    if [[ "$go_count" -gt 0 ]]; then
      warn "userspace-режим (amneziawg-go): работает, но CPU на пакет выше"
    else
      err "нет ни модуля, ни userspace-процесса — туннель не поднят"; fails=$((fails+1))
    fi
  fi

  step "Хост-защита"
  local cc; cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo '?')
  [[ "$cc" == "bbr" ]] && ok "BBR активен" || warn "congestion control = $cc"
  if nft list set inet awgsec blocked_ipv4 >/dev/null 2>&1; then
    local blocked; blocked=$(nft list set inet awgsec blocked_ipv4 2>/dev/null | grep -c 'expires' || true)
    ok "nft-блоклист активен (записей: ${blocked:-0})"
  else
    warn "nft-блоклист не найден (install.sh не запускался?)"
  fi
  for svc in fail2ban crowdsec crowdsec-firewall-bouncer awgsec-panel-agent.timer; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then ok "$svc: active"
    else warn "$svc: $(systemctl is-active "$svc" 2>/dev/null || true)"; fi
  done

  step "Вкладка «Безопасность»"
  if [[ -f "$PANEL_DIR/security/state.json" ]]; then
    local age
    age=$(python3 -c "
import json,time,sys
try:
    d=json.load(open('$PANEL_DIR/security/state.json'))
    print(int(time.time())-int(d.get('updated') or 0))
except Exception:
    print(-1)")
    if [[ "$age" -ge 0 && "$age" -lt 120 ]]; then
      ok "state.json свежий (${age} с назад)"
    else
      warn "state.json не обновляется (${age} с) — проверь awgsec-panel-agent"
    fi
  else
    warn "state.json нет: агент панели ещё не отработал или не установлен"
  fi

  step "Endpoint для клиентов"
  local endpoint; endpoint=$(cfg_query 'srv.get("endpoint") or srv.get("public_ip")')
  local ip; ip=$(public_ip)
  ok "endpoint в конфиге: ${endpoint:-?}"
  ok "внешний IP этой машины: ${ip:-?}"
  if [[ -n "$endpoint" && -n "$ip" && "$endpoint" =~ ^[0-9.]+$ && "$endpoint" != "$ip" ]]; then
    err "endpoint — IP и он не совпадает с новым адресом: клиенты не подключатся"
    printf '    исправить: %s import --bundle … --update-endpoint auto\n' "$0"
    fails=$((fails+1))
  elif [[ -n "$endpoint" && ! "$endpoint" =~ ^[0-9.]+$ ]]; then
    ok "endpoint — домен ($endpoint): переезд прозрачен для клиентов, нужен только DNS"
  fi

  echo
  if (( fails == 0 )); then ok "итог: замечаний нет"; else err "итог: проблем — $fails"; fi
  return "$fails"
}

# ─────────────────────────────────────────────────────────────────────────────
# migrate — одна команда: экспорт → перенос → импорт → проверка
# ─────────────────────────────────────────────────────────────────────────────
cmd_migrate() {
  need_root
  [[ -n "$TARGET" ]] || die "укажи --to root@NEW_IP"

  step "1/4 Preflight целевой машины"
  ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "$TARGET" 'true' 2>/dev/null \
    || die "нет SSH-доступа к $TARGET (нужен ключ, BatchMode)"
  ok "SSH до $TARGET есть"
  local target_info
  target_info=$(ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" '
    echo "host=$(hostname -s)"
    echo "kernel=$(uname -r)"
    echo "os=$(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")"
    echo "docker=$(docker version --format "{{.Server.Version}}" 2>/dev/null || echo none)"
    echo "compose=$(docker compose version --short 2>/dev/null || echo none)"
    echo "ip=$(curl -4 -fsS --max-time 8 https://ifconfig.me 2>/dev/null)"
    echo "disk=$(df -Pm /var/lib/docker 2>/dev/null | awk "NR==2{print \$4}")"
    echo "panel=$([ -d '"$PANEL_DIR"' ] && echo exists || echo clean)"
  ' 2>/dev/null) || die "не удалось опросить $TARGET"
  echo "$target_info" | sed 's/^/    /'

  local t_docker t_ip t_disk t_panel
  t_docker=$(echo "$target_info" | sed -n 's/^docker=//p')
  t_ip=$(echo "$target_info" | sed -n 's/^ip=//p')
  t_disk=$(echo "$target_info" | sed -n 's/^disk=//p')
  t_panel=$(echo "$target_info" | sed -n 's/^panel=//p')

  [[ "$t_docker" != "none" ]] || die "на $TARGET нет docker"
  if [[ "$t_panel" == "exists" ]] && (( ! FORCE )); then
    die "на $TARGET уже есть $PANEL_DIR — нужен --force (сделает бэкап)"
  fi
  if [[ -n "$t_disk" && "$t_disk" -lt 2048 ]]; then
    die "на $TARGET меньше 2 ГБ на /var/lib/docker"
  fi
  ok "диск: ${t_disk:-?} МБ, каталог панели: $t_panel"

  step "2/4 Экспорт с этой машины"
  local out="/tmp/awg-migrate-$(date +%Y%m%d-%H%M).tar.gz"
  BUNDLE="$out"
  cmd_export >/dev/null 2>&1 || { err "экспорт не удался"; return 1; }
  [[ -f "$out" ]] || die "бандл не создан: $out"
  ok "бандл готов: $out ($(du -h "$out" | cut -f1))"

  step "3/4 Перенос и развёртывание"
  scp -q -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$out" "$TARGET:/root/" || die "scp не удался"
  ok "бандл скопирован"
  local remote_args=("import" "--bundle" "/root/$(basename "$out")" "--panel-dir" "$PANEL_DIR")
  (( STAGE )) && remote_args+=(--stage)
  (( NO_START )) && remote_args+=(--no-start)
  (( KEEP_SECURITY )) && remote_args+=(--keep-security)
  (( ! HOST_SETUP )) && remote_args+=(--no-host-setup)
  (( ! KERNEL_MODULE )) && remote_args+=(--no-kernel-module)
  (( FORCE )) && remote_args+=(--force)
  [[ -n "$DOMAIN" ]] && remote_args+=(--domain "$DOMAIN")
  [[ -n "$UPDATE_ENDPOINT" ]] && remote_args+=(--update-endpoint "$UPDATE_ENDPOINT")

  ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new "$TARGET" "set -e
    mkdir -p /root/awg-bundle && tar xzf /root/$(basename "$out") -C /root/awg-bundle
    /root/awg-bundle/bundle/tool/migrate.sh ${remote_args[*]}"

  step "4/4 Итог"
  ok "панель развёрнута на $TARGET (внешний IP: ${t_ip:-?})"
  cat <<EOF

Что сделано на новой машине:
  • панель: $PANEL_DIR (серверы, клиенты, ключи, nginx, compose, .env, Caddyfile)
  • сертификат Caddy: перенесён вместе с ACME-аккаунтом
  • хост: BBR, nftables-блоклист, fail2ban, CrowdSec, агент панели$([[ "$KERNEL_MODULE" == 1 ]] && echo ", модуль ядра amneziawg")

Проверить: ssh $TARGET /root/awg-host-hardening/migrate.sh verify
EOF
  if (( STAGE )); then
    cat <<EOF

Панель на новой машине НЕ обслуживает домен (--stage), старая работает.
Переключение:
  1. DNS домена → ${t_ip:-<новый IP>}
  2. dig +short ${DOMAIN:-<домен>}   # убедиться, что уже новый IP
  3. ssh $TARGET 'cd $PANEL_DIR && docker compose up -d'
  4. ssh $TARGET '/root/awg-host-hardening/migrate.sh verify'
  5. на старой машине: cd $PANEL_DIR && docker compose stop
EOF
  else
    cat <<EOF

Старая машина НЕ остановлена — это специально, откат мгновенный.
После проверки, что клиенты подключаются к новой:
  на старой машине: cd $PANEL_DIR && docker compose stop

Откат: на новой — docker compose down; домен вернуть на старый IP.
EOF
  fi
  cat <<EOF

Важно:
  • бандл содержал приватные ключи (права 600). Удали его:
      ssh $TARGET 'rm -f /root/$(basename "$out")'
  • счётчики трафика у клиентов начнутся с нуля — это нормально
  • если endpoint в конфиге был IP, а не домен, клиенты не подключатся:
    используй --update-endpoint auto (скрипт предупредит сам)
EOF
  rm -f "$out"
}

# ─────────────────────────────────────────────────────────────────────────────
# inspect — что внутри бандла
# ─────────────────────────────────────────────────────────────────────────────
cmd_inspect() {
  [[ -n "$BUNDLE" && -f "$BUNDLE" ]] || die "укажи --bundle /path/to/bundle.tar.gz"
  local work; work=$(mktemp -d /tmp/awg-inspect.XXXXXX)
  trap 'rm -rf "${work:-}"' EXIT
  tar xzf "$BUNDLE" -C "$work"
  python3 - "$work/bundle/manifest.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1], encoding="utf-8"))
src, p, h = m["source"], m["panel"], m["host_state"]
print(f"формат:      {m['format']} (tool {m['tool_version']})")
print(f"создан:      {m['created_iso']}")
print(f"источник:    {src['hostname']} · kernel {src['kernel']} · docker {src['docker']} · {src['public_ip']}")
print()
print("панель:")
print(f"  сервер      {p['server_id']} «{p['server_name']}» → {p['interface']}:{p['port']}")
print(f"  подсеть     {p['subnet']} / MTU {p['mtu']}")
print(f"  клиентов    {p['clients']} (приостановлено {p['suspended']})")
print(f"  endpoint    {p['endpoint']}")
ob = p.get("obfuscation") or {}
print(f"  обфускация  {'вкл' if ob.get('enabled') else 'выкл'} {ob.get('params') or ''}")
print()
print("хост на источнике:")
for key, label in [("bbr", "BBR"), ("qdisc", "qdisc"), ("kernel_module", "модуль ядра"),
                   ("fail2ban", "fail2ban"), ("crowdsec", "crowdsec"),
                   ("crowdsec_bouncer", "bouncer"), ("panel_agent", "агент панели"),
                   ("blocked_count", "в блок-листе")]:
    print(f"  {label:<14}{h.get(key)}")
print()
print(f"файлов в бандле: {len(m.get('files') or {})}")
for rel in sorted(m.get("files") or {}):
    print(f"  {rel}")
PY
}

case "$CMD" in
  export)  cmd_export ;;
  import)  cmd_import ;;
  migrate) cmd_migrate ;;
  verify)  cmd_verify ;;
  inspect) cmd_inspect ;;
  *) err "неизвестная команда: $CMD (export|import|migrate|verify|inspect)"; exit 2 ;;
esac
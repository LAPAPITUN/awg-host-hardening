#!/usr/bin/env bash
#
# smoke-test.sh — проверка migrate.sh без второй машины.
# Собирает песочницу (фейковая панель), гоняет export/import/verify и проверяет
# результат. Ничего не ставит на хост, контейнеры не запускает (--no-start).
#
# Запуск: ./tests/smoke-test.sh
#
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MIGRATE="$ROOT/migrate.sh"
SANDBOX="$(mktemp -d /tmp/awg-smoke.XXXXXX)"
PASS=0
FAIL=0

trap 'rm -rf "$SANDBOX"' EXIT

ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
check() { local name="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi; }

make_panel() {  # make_panel <dir> [endpoint]
  local dir="$1" ep="${2:-newserv.1121440.ru}"
  mkdir -p "$dir"/{amnezia/amneziawg,nginx,logs,security}
  cat > "$dir/docker-compose.yml" <<'EOF'
services:
  amnezia:
    image: lapapitun/amneziawg-web-ui-ru:latest
    container_name: amnezia
    volumes:
      - ./amnezia:/etc/amnezia
    ports:
      - "${WG_PORT}:${WG_PORT}/udp"
EOF
  cat > "$dir/.env" <<'EOF'
IMAGE_TAG=lapapitun/amneziawg-web-ui-ru:latest
WG_PORT=51820
NGINX_PORT=80
NGINX_USER=pavelko
NGINX_PASSWORD=secret-password-123
EOF
  printf '%s {\n    reverse_proxy amnezia:80 {\n        header_up Host {host}\n    }\n}\n' "$ep" > "$dir/Caddyfile"
  printf 'server { listen 80; }\n' > "$dir/nginx/default.conf"
  printf '# wg conf\n' > "$dir/amnezia/amneziawg/wg-test.conf"
  cat > "$dir/amnezia/web_config.json" <<EOF
{
  "servers": [{
    "id": "9777b6", "name": "my-serv", "interface": "wg-9777b6",
    "port": 51820, "subnet": "10.8.0.0/24", "mtu": 1324,
    "endpoint": "$ep", "public_ip": "$ep",
    "server_private_key": "PRIV_TEST", "server_public_key": "PUB_TEST",
    "dns": ["1.1.1.1"], "obfuscation_enabled": true,
    "obfuscation_params": {"Jc": 6, "Jmin": 8, "Jmax": 80, "S1": 43, "S2": 143},
    "clients": [
      {"id": "c1", "name": "Клиент 1", "client_ip": "10.8.0.2", "status": "active"},
      {"id": "c2", "name": "Клиент 2", "client_ip": "10.8.0.3", "status": "suspended"}
    ]
  }]
}
EOF
}

echo "== подготовка песочницы =="
SRC="$SANDBOX/src"; DST="$SANDBOX/dst"
make_panel "$SRC"
echo "  песочница: $SANDBOX"

echo "== export =="
"$MIGRATE" export --panel-dir "$SRC" --out "$SANDBOX/panel.tar.gz" >"$SANDBOX/export.log" 2>&1
check "бандл создан" test -s "$SANDBOX/panel.tar.gz"
check "права бандла 600" test "$(stat -c %a "$SANDBOX/panel.tar.gz")" = "600"
check "манифест в бандле" bash -c "tar tzf '$SANDBOX/panel.tar.gz' | grep -q bundle/manifest.json"
check "инструменты в бандле" bash -c "tar tzf '$SANDBOX/panel.tar.gz' | grep -q bundle/tool/migrate.sh"

echo "== inspect =="
"$MIGRATE" inspect --bundle "$SANDBOX/panel.tar.gz" >"$SANDBOX/inspect.log" 2>&1
check "показывает клиентов" grep -q "клиентов    2" "$SANDBOX/inspect.log"
check "показывает suspended" grep -q "приостановлено 1" "$SANDBOX/inspect.log"
check "показывает endpoint" grep -q "newserv.1121440.ru" "$SANDBOX/inspect.log"

echo "== import =="
"$MIGRATE" import --bundle "$SANDBOX/panel.tar.gz" --panel-dir "$DST" \
  --no-host-setup --no-start >"$SANDBOX/import.log" 2>&1
check "файлы панели совпадают" diff -r "$SRC/amnezia" "$DST/amnezia"
check "nginx скопирован" diff -r "$SRC/nginx" "$DST/nginx"
check ".env права 600" test "$(stat -c %a "$DST/.env")" = "600"
check "web_config.json права 600" test "$(stat -c %a "$DST/amnezia/web_config.json")" = "600"
check "каталог с ключами 700" test "$(stat -c %a "$DST/amnezia")" = "700"
check "JSON валиден" python3 -c "import json;json.load(open('$DST/amnezia/web_config.json'))"
check "монтирования добавлены" grep -q "./security:/var/lib/awgsec" "$DST/docker-compose.yml"
check "verify пропущен при --no-start" grep -q "проверка пропущена" "$SANDBOX/import.log"

echo "== защита от ошибок =="
"$MIGRATE" import --bundle "$SANDBOX/panel.tar.gz" --panel-dir "$DST" \
  --no-host-setup --no-start >/dev/null 2>&1
check "отказ без --force" test $? -eq 1

mkdir -p "$SANDBOX/tamper" && tar xzf "$SANDBOX/panel.tar.gz" -C "$SANDBOX/tamper"
echo "EVIL" >> "$SANDBOX/tamper/bundle/panel/.env"
tar czf "$SANDBOX/broken.tar.gz" -C "$SANDBOX/tamper" bundle
"$MIGRATE" import --bundle "$SANDBOX/broken.tar.gz" --panel-dir "$SANDBOX/never" \
  --no-host-setup --no-start >/dev/null 2>&1
check "отказ на подменённом файле" test $? -eq 1

echo "== --force делает бэкап =="
"$MIGRATE" import --bundle "$SANDBOX/panel.tar.gz" --panel-dir "$DST" \
  --no-host-setup --no-start --force >"$SANDBOX/force.log" 2>&1
check "бэкап создан" bash -c "ls -d '$DST'.backup-* >/dev/null 2>&1"

echo "== endpoint = IP =="
IPDIR="$SANDBOX/ip"; make_panel "$IPDIR" "198.51.100.10"
"$MIGRATE" export --panel-dir "$IPDIR" --out "$SANDBOX/ip.tar.gz" >/dev/null 2>&1
"$MIGRATE" import --bundle "$SANDBOX/ip.tar.gz" --panel-dir "$SANDBOX/ip-new" \
  --no-host-setup --no-start >"$SANDBOX/ip.log" 2>&1
check "предупреждает про IP в endpoint" grep -q "клиенты не подключатся" "$SANDBOX/ip.log"
"$MIGRATE" import --bundle "$SANDBOX/ip.tar.gz" --panel-dir "$SANDBOX/ip-new2" \
  --no-host-setup --no-start --update-endpoint auto >/dev/null 2>&1
check "правит endpoint на внешний IP" bash -c \
  "python3 -c \"import json,sys; d=json.load(open('$SANDBOX/ip-new2/amnezia/web_config.json')); sys.exit(0 if d['servers'][0]['endpoint'] not in ('', '198.51.100.10') else 1)\""

echo "== verify на пустом хосте =="
"$MIGRATE" verify >"$SANDBOX/verify.log" 2>&1
check "verify отрабатывает и сообщает проблемы" grep -q "итог:" "$SANDBOX/verify.log"

echo
printf 'итог: %d PASS, %d FAIL\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
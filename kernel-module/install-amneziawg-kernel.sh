#!/usr/bin/env bash
#
# install-amneziawg-kernel.sh — сборка и установка модуля ядра AmneziaWG (DKMS)
#
# Зачем: без модуля awg-quick падает в userspace-реализацию (amneziawg-go), которая
# на 30-45 Мбит/с трафика держит 0.4–1.3 ядра и в top показывает 120–130%.
# С модулем тот же трафик стоит единицы процентов (проверено: load 4.87 → 0.43).
#
# Что делает:
#   1. ставит build-essential, dkms, git, headers текущего ядра
#   2. клонирует amneziawg-linux-kernel-module
#   3. патчит compat/compat.h под переходное ядро 7.0.x (см. PATCH ниже)
#   4. собирает и устанавливает модуль через DKMS (переживёт обновление ядра)
#   5. modprobe + проверка /sys/module/amneziawg + тестовый интерфейс
#
# ВАЖНО: скрипт НЕ перезапускает рабочий туннель. Чтобы панель перешла в kernel-режим,
# нужно перезапустить контейнер (start_server поднимет интерфейс уже через модуль):
#     docker restart amnezia
# Перед этим убедись, что клиенты переподключатся (они это делают сами за 5-15 с).
#
# Откат: rmmod amneziawg && docker restart amnezia  → снова userspace.
#
set -euo pipefail

MODULE_REPO="https://github.com/amnezia-vpn/amneziawg-linux-kernel-module.git"
SRC_DIR="/usr/src/amneziawg-linux-kernel-module"
VER="1.0.0"
KREL="$(uname -r)"

log()  { printf '\n== %s ==\n' "$*"; }
ok()   { printf '  ✓ %s\n' "$*"; }
warn() { printf '  ! %s\n' "$*"; }
die()  { printf '  ✗ %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "нужен root"

log "Зависимости"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq build-essential dkms git "linux-headers-${KREL}" >/dev/null
ok "build-essential, dkms, git, linux-headers-${KREL}"

log "Исходники модуля"
rm -rf "$SRC_DIR"
git clone -q --depth 1 "$MODULE_REPO" "$SRC_DIR"
ok "клон $(git -C "$SRC_DIR" rev-parse --short HEAD)"

log "Патч под ядро 7.0.x"
python3 - "$SRC_DIR/src/compat/compat.h" <<'PY'
import sys
p = sys.argv[1]
s = open(p).read()

old = """#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 1, 5)
#include <net/udp_tunnel.h>
#define setup_udp_tunnel_sock(net, sk, sock_cfg) setup_udp_tunnel_sock(net, sk->sk_socket, sock_cfg)
#define udp_tunnel_sock_release(sk) udp_tunnel_sock_release(sk->sk_socket)
#endif"""

new = """/* Ядро 7.0.x переходное: setup_udp_tunnel_sock уже принимает struct sock *,
 * а udp_tunnel_sock_release ещё принимает struct socket *. Поэтому шимы разные. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 0, 0)
#include <net/udp_tunnel.h>
#define setup_udp_tunnel_sock(net, sk, sock_cfg) setup_udp_tunnel_sock(net, sk->sk_socket, sock_cfg)
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(7, 1, 5)
#include <net/udp_tunnel.h>
#define udp_tunnel_sock_release(sk) udp_tunnel_sock_release((sk)->sk_socket)
#endif"""

if new.splitlines()[3] in s:
    print("  · патч уже применён")
elif old in s:
    open(p, "w").write(s.replace(old, new))
    print("  ✓ патч применён")
else:
    print("  ! якорь не найден — upstream изменился, патч не нужен либо требует обновления")
PY

log "DKMS build"
dkms remove -m amneziawg -v "$VER" --all >/dev/null 2>&1 || true
rm -rf "/usr/src/amneziawg-${VER}"
( cd "$SRC_DIR/src" && make dkms-install >/dev/null 2>&1 )
dkms add -m amneziawg -v "$VER" >/dev/null 2>&1 || true
if ! dkms build -m amneziawg -v "$VER" >/tmp/amneziawg-build.log 2>&1; then
  grep -E "error:" "/var/lib/dkms/amneziawg/${VER}/build/make.log" 2>/dev/null | head -10
  die "сборка не удалась, лог: /tmp/amneziawg-build.log"
fi
ok "модуль собран для ${KREL}"
dkms install -m amneziawg -v "$VER" 2>&1 | grep -E "Installing|depmod" || true

log "Загрузка модуля"
modprobe amneziawg
lsmod | grep -q '^amneziawg' || die "модуль не загрузился"
[[ -d /sys/module/amneziawg ]] || die "нет /sys/module/amneziawg"
ok "модуль загружен: $(modinfo -F version amneziawg 2>/dev/null || echo '?')"

log "Тестовый интерфейс (рабочий туннель не трогаем)"
ip link add dev awgtest type amneziawg
ip link del awgtest
ok "kernel-интерфейс создаётся"

cat <<EOF

Готово. Рабочий туннель пока в userspace — чтобы перейти на модуль:

    docker restart amnezia

Панель поднимет интерфейс уже через ядро (amneziawg-go перестанет запускаться).
Проверка после перезапуска:

    pgrep -c amneziawg-go          # должно быть 0
    cat /sys/module/amneziawg/refcnt
    docker exec amnezia awg show <iface> | head -5
    uptime                          # load должен упасть в разы

Откат: rmmod amneziawg && docker restart amnezia
EOF

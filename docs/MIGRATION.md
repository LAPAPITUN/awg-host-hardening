# Переезд панели на новую машину

Панель переезжает часто, поэтому процесс разбит на две части: **данные** (переносятся
файлами) и **хост** (ставится одной командой). Модуль ядра НЕ переносится — он
собирается на новой машине под её ядро, автоматически.

## Что где лежит

| Что | Где на хосте | Переносится |
|---|---|---|
| серверы, клиенты, ключи, настройки панели | `/opt/my-wg-panel/amnezia/web_config.json` | файлом |
| пароль панели, порт, домен | `/opt/my-wg-panel/.env`, `Caddyfile` | файлами |
| блокировки и настройки защиты | `/opt/my-wg-panel/security/`, `/etc/awgsec/` | по желанию (обычно нет) |
| модуль ядра `amneziawg` | `/lib/modules/$(uname -r)/updates/dkms/` | **нет**, собирается на месте |

## Порядок (новая машина)

```bash
# 1. Панель: каталоги и файлы
mkdir -p /opt/my-wg-panel/{amnezia,nginx,logs,security,blocklist}
cd /opt/my-wg-panel
#    скопировать сюда: docker-compose.yml, .env, Caddyfile, nginx/, amnezia/web_config.json

# 2. Защита хоста + BBR + агент панели (идемпотентно, можно поверх)
git clone git@github.com:LAPAPITUN/awg-host-hardening.git
cd awg-host-hardening
sudo ./install.sh install --owner-ips <свой_ip> --panel-dir /opt/my-wg-panel/security

# 3. Модуль ядра (30-60 с, собирается под ядро новой машины)
sudo ./kernel-module/install-amneziawg-kernel.sh

# 4. Панель вверх
cd /opt/my-wg-panel && docker compose up -d

# 5. Проверка
sudo ./install.sh status
docker exec amnezia awg show | head -5
pgrep -c amneziawg-go    # 0 = работает модуль ядра
```

## Если модуль не собрался

Ничего не ломается: `awg-quick` увидит, что `/sys/module/amneziawg` нет, и поднимется
в userspace (`amneziawg-go`). Панель и туннель работают, но CPU на пакет выше.
Скрипт модуля сразу покажет ошибку компиляции — тогда смотреть:

- `uname -r` и наличие `linux-headers-$(uname -r)`;
- лог `/var/lib/dkms/amneziawg/1.0.0/build/make.log`;
- на новых ядрах API ядра меняется — правится `compat/compat.h` (в скрипте уже
  лежит патч под переходное 7.0.x).

## Быстрый чек-лист после переезда

1. `curl -u user:pass https://<домен>/` → 200.
2. `docker exec amnezia awg show` → все пиры, у большинства свежий handshake.
3. `pgrep -c amneziawg-go` → 0 (kernel mode) или 1 (userspace, рабочий вариант).
4. `sudo /root/install.sh status` → BBR bbr/fq, nft set активна, fail2ban, CrowdSec.
5. Открыть панель → вкладка «Безопасность»: бейдж и таблица заполняются
   (значит агент отработал и state.json пишется).

## Домен и сертификат

Caddy получает сертификат сам при старте: DNS-запись домена должна указывать на
новый IP **до** запуска `docker compose up -d`. Если IP ещё старый — Caddy не сможет
пройти ACME, и панель откроется только по http.

## Откат

Панель: вернуть прежние `web_config.json` / `.env` / `Caddyfile` и `docker compose up -d`.
Хост: `sudo ./install.sh uninstall`, модуль: `sudo rmmod amneziawg`.
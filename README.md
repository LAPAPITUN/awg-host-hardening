# awg-host-hardening

Защита хоста с панелью AmneziaWG (и любого nginx-фронта за Docker): nftables-блокировка,
BBR, fail2ban, CrowdSec с community blocklist, второй слой в Caddy.
Плюс переезд панели на новую машину одной командой.

Один скрипт, идемпотентный, с `--dry-run`. Всё состояние — в `/etc/awgsec/blocked.txt`,
переживает перезагрузку.

## Переезд на новую машину

```bash
./migrate.sh migrate --to root@NEW_IP --domain newserv.example.ru --stage
```

Переносит панель (серверы, клиенты, ключи, nginx, compose, `.env`, Caddyfile),
сертификат Caddy, блок-лист по флагу — и приводит новую машину в то же состояние:
BBR, nftables, fail2ban, CrowdSec, агент панели, модуль ядра.
Старая машина не останавливается: откат мгновенный.

Подробно, включая переключение DNS и риск «endpoint = IP»: [docs/MIGRATION.md](docs/MIGRATION.md).

## Быстрый старт

```bash
git clone git@github.com:LAPAPITUN/awg-host-hardening.git
cd awg-host-hardening
sudo ./install.sh install --dry-run                 # посмотреть, что будет сделано
sudo ./install.sh install --owner-ips 95.27.216.249 # применить
sudo ./install.sh status                            # что включено и сколько забанено
```

Полезные флаги:

| Флаг | Смысл |
|---|---|
| `--dry-run` | только показать команды, ничего не менять |
| `--owner-ips 1.2.3.4,5.6.7.8` | твои адреса: не банятся, добавлены в `ignoreip` |
| `--panel-log PATH` | лог nginx панели на хосте (по умолчанию `/opt/my-wg-panel/logs/access.log`) |
| `--no-crowdsec` / `--no-fail2ban` / `--no-bbr` / `--no-caddy` | отключить отдельный слой |
| `--with-kernel-module` | сразу собрать модуль ядра AmneziaWG под текущее ядро |
| `--panel-dir PATH` | каталог, смонтированный в панель как `/var/lib/awgsec` |

## Что делает каждый слой

### 1. nftables (`inet awgsec`)

Свой набор `blocked_ipv4` с таймаутами и цепочка **prerouting priority -150** — drop
срабатывает **до DNAT и до Docker**. Пакет от забаненного IP умирает в ядре: ни nginx,
ни панель, ни Flask его не видят, в логи он не попадает.

```bash
awgsec-block add 1.2.3.4 86400   # забанить на сутки
awgsec-block add 1.2.3.0/24      # подсеть
awgsec-block del 1.2.3.4
awgsec-block list                # активные блокировки
```

Почему не `input`: опубликованные порты Docker (`ports:`) проходят через DNAT и
уходят в `FORWARD`, а не в `INPUT`. Правило в `input` такие пакеты не ловит —
частая ошибка в гайдах.

### 2. BBR

`/etc/sysctl.d/99-awgsec-bbr.conf`: `bbr` + `fq`, буферы 32 МБ, `tcp_fastopen=3`,
`tcp_mtu_probing=1`, `ip_forward=1`. После применения скрипт **проверяет**
`net.ipv4.tcp_congestion_control = bbr` и падает с ошибкой, если не применилось.

BBR ускоряет TCP (панель, прокси, отдача файлов). На UDP WireGuard/AmneziaWG он не
влияет — там своя логика.

### 3. fail2ban

Три джейла, все банят через `awgsec-block` (единый набор, единый файл состояния):

- `sshd` — 5 попыток за 10 минут → 24 часа;
- `awg-panel-auth` — 5 ответов 401/403 от basic-auth за 10 минут → 24 часа;
- `awg-panel-scan` — 20 попаданий в сканерские пути (`.env`, `.git`, `.aws`, `.ssh`,
  `phpinfo`, `wp-*`, `docker-compose.yml`, `env-config.js`, `cpanel`, `actuator`,
  `vendor/`, `_profiler`, `xmlrpc.php`) → 24 часа.

Ключевая деталь: реальный IP берётся из **последнего поля** лога
(`$http_x_forwarded_for`), потому что панель стоит за Caddy и в `$remote_addr`
приходит адрес контейнера Caddy. Фильтр работает и до, и после починки `real_ip` в nginx.

### 4. CrowdSec

Локальный движок сценариев + **бесплатная community blocklist** (CAPI): IP, которые
уже атакуют чужие инсталляции CrowdSec по всему миру. Это и есть ответ на «инструмент,
который знает всех активных сканеров».

- коллекции: `crowdsecurity/nginx`, `http-cve`, `base-http-scenarios`, `sshd`, `linux`;
- `crowdsec-firewall-bouncer` в режиме `nftables` (своя таблица, с нашим набором не конфликтует);
- acquisition: лог панели (`type: nginx`) + системные логи;
- регистрация в CAPI автоматическая (`cscli capi register`).

Полезное:

```bash
cscli decisions list              # что забанено и за что
cscli alerts list                 # на какие атаки сработало
cscli metrics                     # сколько строк прочитано, какие сценарии сработали
cscli hub list                    # коллекции/парсеры
cscli capi status                 # статус community blocklist
```

CrowdSec Console (веб-панель, опционально) — `cscli console enroll <key>`, бесплатный тариф.

### 5. Caddy (второй слой)

Таймер раз в минуту собирает IP из `awgsec-block list` + решений CrowdSec и пишет
`/etc/caddy/blocklist/blocklist.caddy`. В Caddyfile нужна одна строка внутри site-блока:

```
newserv.1121440.ru {
    import /etc/caddy/blocklist/blocklist.caddy
    reverse_proxy amnezia:80 { header_up Host {host} }
}
```

Смысл: если правило nft потеряется (руками почистили, обновили ядро), блокировка
останется на уровне HTTP. Если файл пуст — сниппет ничего не делает.

## Что ещё стоит поставить (и почему не в скрипте)

### Модуль ядра AmneziaWG — отдельный скрипт `kernel-module/`

Без модуля `awg-quick` падает в userspace-реализацию `amneziawg-go`: на 30–45 Мбит/с
трафика она держит 0.4–1.3 ядра и в `top` показывает **120–130%** (Go-датапас
многопоточный, `GOMAXPROCS=2` → потолок 200%). Модуль ядра убирает копирование
каждого пакета в userspace.

```bash
sudo ./kernel-module/install-amneziawg-kernel.sh   # сборка + DKMS, туннель не трогает
sudo docker restart amnezia                        # переключение на kernel-режим
```

Скрипт сам патчит `compat/compat.h` под переходное ядро 7.0.x: `setup_udp_tunnel_sock`
там уже принимает `struct sock *`, а `udp_tunnel_sock_release` ещё принимает
`struct socket *` — upstream-гард `< 7.1.5` этого не учитывает и сборка падает.

Замер на живом хосте (36 пиров, ~30 Мбит/с):

| | userspace | модуль ядра |
|---|---|---|
| load average (1m) | 4.2–4.9 | **0.43** |
| CPU steal | 54–81% | **0%** |
| amneziawg-go | 0.4–1.3 ядра | процесса нет |
| idle | 0–8% | 72% |

Откат: `rmmod amneziawg && docker restart amnezia`.

| Инструмент | Зачем | Почему отдельно |
|---|---|---|
| `unattended-upgrades` | авто-обновления безопасности | на хосте с Docker лучше контролировать вручную, иначе внезапный reboot |
| `vnstat` | учёт трафика по интерфейсу, независимо от панели | не защита, а наблюдаемость |
| `tc`/`htb` (или `wondershaper`) | шейпинг тяжёлым клиентам | влияет на клиентов, решение продуктовое |
| `auditd` + `lynis` | аудит конфигурации хоста | `lynis` — разовый аудит, не сервис |
| `restic`/`borg` | бэкапы `/opt/my-wg-panel/amnezia` | бэкапы — отдельная тема |
| Cloudflare (прокси) | скрывает origin, режет ботов на edge | только если домен можно вести через CF |
| `ufw` | простой фаервол | **не ставить вместе с nftables-правилами**: ufw перезаписывает правила и ломает Docker |

## Порядок применения на живой панели

1. Логи панели должны быть на хосте (bind-mount в compose):
   `./logs:/var/log/nginx` — иначе fail2ban и CrowdSec нечего читать.
2. `./install.sh install --dry-run` — прочитать, что будет сделано.
3. `./install.sh install --owner-ips <свой_ip>`.
4. Проверить: `./install.sh status`, затем открыть панель и убедиться, что 401/403
   приходят с реальных IP, а не с `172.18.0.2`.
5. Проверить, что SSH жив: `ssh root@host` из второй сессии, **до** того как закрыть первую.

## Откат

```bash
sudo ./install.sh uninstall
```

Снимает nft-таблицу, таймеры, джейлы fail2ban и sysctl-файл. CrowdSec удаляется
отдельно (`apt purge crowdsec crowdsec-firewall-bouncer`).

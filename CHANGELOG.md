# Changelog

Формат: Keep a Changelog. Версии семантические.

## [2.0.0] — 2026-08-31

Полный цикл идей сисадмина (см. [IDEAS.md](IDEAS.md)): 19/20 реализовано,
одна идея (Wi-Fi-клиенты) оставлена в бэклоге как требующая оборудования.

### Added — сеть и инвентарь
- `netpulse/l2map.py`: L2-карта по SNMP — Bridge-MIB (`dot1dTpFdbTable`)
  «MAC → порт коммутатора», LLDP-соседи (`lldpRemTable`), таблица `l2_ports`;
  фоновый цикл `np-l2map` (после автоскана ЛС)
- PTR-резолв имён для устройств без hostname (`L2Map.resolve_ptrs()`)
- API: `GET /api/l2map`, `GET /api/ptrs`, `POST /api/l2scan`

### Added — мониторинг и алерты
- Пороговые профили по группам устройств: `quality.profiles`
  (server/router/pc), алерт `PROFILE_LIMIT` в `scan_infra`
- Эскалация не-принятых алертов: `_escalate_loop()`, конфиг `escalate`
  (повтор в Telegram через `unack_min`)
- Прогноз ОЗУ: `ram_forecast()` (наименьшие квадраты по `mem_pct`,
  горизонт до 95%), API `GET /api/ramforecast`
- MTR-«веер» по расписанию: `MTREngine.save_snapshot()` (таблица
  `mtr_history`), `schedule_loop()` — ротация по `mtr.targets`,
  API `GET /api/mtrhistory`

### Added — безопасность
- `netpulse/geo.py`: локальный резолвер IP → страна (без внешних API)
- Гео-карта атак: `geo_attack_map()` по IDS/security-алертам,
  API `GET /api/geomap`
- Авто-diff SNMP-конфигов: `auto_diff()` по `infra_snaps`,
  алерт `CONFIG_CHANGED`
- Whitelist MAC: `lan.trusted_macs` не поднимают `LAN_NEW_DEVICE`
- RBAC: роли `admin`/`viewer` из `web_users`, POST-действия viewer
  блокируются (403, кроме подтверждения алертов/алиасов), `whoami`
  отдаёт роль
- `netpulse/cve.py`: NVD API v2 (без ключа, кэш `sw_cve`, rate-limit
  1.2 c/запрос), API `GET /api/cvestatus`, `POST /api/cvescan`

### Added — удобство и отчётность
- `netpulse/proxmox.py`: интеграция PVE (статус нод/ВМ, таблица
  `proxmox_status`), API `GET /api/proxmox`, `POST /api/proxmoxpoll`
- Конфиг через переменные окружения `NETPULSE_*` и `.env` (поверх
  `config.json`, секреты без правки файла)
- Еженедельный авто-отчёт: `_weekly_report_loop()` — email/Telegram/
  webhook, конфиг `report.weekly`; API `GET /api/reportpdf`
- SLA-доступность узлов: `sla_period(days)` по событиям OFFLINE/ONLINE,
  API `GET /api/sla`
- UI: вкладка «Сисадмин» (SLA, прогноз ОЗУ, L2-порты, гео-карта,
  Proxmox, MTR-история, CVE, лента изменений `/api/audit`)
- Печать топологии на A4 (светлая страница из текущей SVG) — кнопка
  в «Инфраструктуре»

### Changed
- `whoami` возвращает `role`; `_identity()` — кортеж `(имя, роль)`
- `sw.js` → `netpulse-v2`: network-first для статики (старый PWA-кэш
  отдавал устаревший `app.js`)

### Fixed
- `ram_forecast` падал 500 при пустой истории (чтение из кортежей
  `self.history`) — теперь буфер `_ram_hist` в `_tick_loop`
- Таблица `mtr_history` гарантированно создаётся до чтения

## [1.9.0] — 2026-08-25

### Added
- Пользовательские проверки: python-файлы в `custom_checks/*.py`
  (контракт `run() -> {ok, text}`), запуск в цикле сторожа, вкладка результатов
- Grafana-дашборд `grafana/netpulse-dashboard.json` (8 панелей на `/metrics`)
- Per-host метрика `np_host_karma` в Prometheus
- SVG-топология сети во вкладке «Инфраструктура» (шлюз, главный узел, устройства)
- Self-Healing: правила «событие → runbook» с rate-limit и аудитом
- SMART-мониторинг дисков через WMI (CRITICAL при PredictFailure)
- SNMP-снэпшоты + diff конфигурации устройств (`/api/infradiff`)
- Email-алерты (SMTP, stdlib)
- OpenAPI 3.0: `/api/swagger`
- Валидация config.json при загрузке (некорректные значения → default)
- PWA: manifest + service worker (установка на телефон, офлайн-статика)

### Fixed
- Дубль узла «шлюз/роутер» на топологии; наезд подписей на плашку NetPulse
- Свой хост получает LAN IP вместо 127.0.0.1

## [1.7.0] — 2026-08-25

### Added
- Аудит всех мутаций API: append-only `audit_log` (пользователь, IP, действие,
  статус, детали; секреты маскируются), эндпоинт `/api/audit`
- Бэкап config.json перед каждым изменением (`backups/config/`, хранятся 10)
- Ротируемое логирование `logs/netpulse.log` вместо print
- Webhook-канал алертов (Slack/Discord/Mattermost/Teams) — поля в настройках
- `ROADMAP.md` — отложенные предложения с вердиктами
- Идентификация админов `web_admins`, `/api/whoami`, бессрочная сессия
- Брутфорс-защита токена, security-заголовки, анти-CSRF
- Отчёты `/journal.txt`, `/journal.csv`, `/report.txt` под авторизацией

### Changed
- `apply_settings` отказоустойчив: сбой подсистемы не ломает сохранение

## [1.6.0] — 2026-08-24

### Added
- Модуль «Инфраструктура»: роутеры, коммутаторы, серверы; вкладка с типами устройств
- SNMP v2c-клиент на чистом stdlib (sysName, sysDescr, sysUpTime, sysContact, sysLocation, ifNumber)
- Автоклассификация устройств (шлюз → router; SNMP → switch/router/infra; ручной тип приоритетен)
- IDS whitelist (правила process/ports/path) + кнопка «+WL» на находках сканера
- Автоскан подсети по расписанию (`lan.auto_scan_min`)
- Свой MAC в скане ЛС; подсеть и главный узел в статусе вкладки

### Fixed
- MTR: промежуточные хопы больше не показывают 100% потерь (TTL-ответ = ответ)
- Сторож: ping-fallback — живая машина без WinRM не помечается офлайном
- Шлюз по умолчанию определяется по минимальной метрике (Radmin VPN не мешает)
- Сторож заполняет IP хоста при создании

### Security
- Анти-CSRF: POST только `application/json` + `X-Auth`
- Rate-limit: 5 неудачных авторизаций → блок IP на 10 минут + алерт
- Security-заголовки (XFO, nosniff, CSP, Referrer-Policy)
- Отчёты `/journal.txt`, `/journal.csv`, `/report.txt` под авторизацией

## [1.5.0] — 2026-08-24

### Added
- HTTPS (самоподписанный сертификат, `tools/make_cert.ps1`)
- Секреты config.json шифруются Windows DPAPI (`dpapi:...`)
- `web_host` — привязка интерфейса (доступ коллегам из сети)
- Бессрочная сессия администратора (`POST /api/login`, cookie 10 лет)
- `web_admins` — идентификация админов, `/api/whoami`
- Поле «Доступ из сети» в настройках

### Security
- Брутфорс-защита токена, security-заголовки, `compare_digest`

## [1.4.0] — 2026-08-24

### Added
- Карточка машины: RDP-файл, Wake-on-LAN, ping из карточки
- Спарклайн кармы; история health-score (снапшоты раз в 6 ч)
- Виджет дашборда «Парк и журнал»
- Экспорт отчёта TXT (UTF-8 BOM) и CSV для Excel
- Плановые работы с контролем просрочки
- GPO-инвентарь ПО (`/api/gposcript`, `/api/invreport`, поиск «Софт в парке»)
- `/api/selftest` и `/api/meta` (самодиагностика и карта ресурсов)

### Fixed
- Дубль `const fc` ломал весь app.js
- Статика отдаётся с `Cache-Control: no-cache`

## [1.3.0] — 2026-08-24

### Added
- Платформа ИТ-отдела: журнал работ, парк ПК с кармой, сторож ПК (WinRM/WMI),
  runbooks, сторож бэкапов, софт-инвентарь
- Миграция БД v3 (hosts, events, journal, runbook_log, backup_status)
- Вкладки «Журнал» и «Парк ПК», Prometheus-метрики платформы
- Wake-on-LAN с ARP-фолбэком; редактируемые алиасы устройств ЛС

### Fixed
- ARP-парсинг на Windows (MAC через дефис) — устройства теперь сохраняются
- Таблица ЛС показывает базу при открытии, а не только живой скан

## [1.0.0] — 2026-08-24

- Первый публичный релиз: мониторинг трафика, качество связи, диагностика
  (ping/traceroute/MTR/DNS/speedtest), сканер ЛС, IDS, захват пакетов,
  security-сканер, AI-аномалии, web-дашборд (SSE), REST API, Prometheus
- Исправления аудита: NameError в offline-детекте, утечка секретов в git,
  сломанный `admin_ok`, `hmac.compare_digest`, защита `settings` от отключения auth

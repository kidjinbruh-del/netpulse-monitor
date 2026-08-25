# Changelog

Формат: Keep a Changelog. Версии семантические.

## [1.7.0] — 2026-08-25

### Added
- Аудит всех мутаций API: append-only `audit_log` (пользователь, IP, действие,
  статус, детали; секреты маскируются), эндпоинт `/api/audit`
- Бэкап config.json перед каждым изменением (`backups/config/`, хранятся 10)
- Ротируемое логирование `logs/netpulse.log` вместо print
- Webhook-канал алертов (Slack/Discord/Mattermost/Teams) — поля в настройках
- `ROADMAP.md` — отложенные предложения с вердиктами

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
- `/api/selftest` и `/api/meta` (самодиагностика и карта для ИИ)
- `AGENTS.md` — документ для ИИ-ассистентов

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

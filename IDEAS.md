# NetPulse Architecture Knowledge Base

> Живой документ. Обновляется при каждом архитектурном решении.
> Последнее обновление: 2026-09-14 — миграция на FastAPI v3 начата.

## 1. Project Overview

- **Назначение:** сетевой мониторинг + P2P mesh + платформа отдела ИТ (журнал, парк, runbooks).
- **Стек v3:** Python 3.11+, FastAPI, uvicorn, Pydantic v2, SQLite, Jinja2 (планируется), sse-starlette.
- **Веб-UI:** статика `netpulse/web/` (index.html + app.js + style.css), отдаётся FastAPI + SPA fallback.

## 2. Architecture Decisions (ADR)

| ID | Решение | Дата | Статус |
|----|---------|------|--------|
| ADR-001 | FastAPI вместо stdlib HTTPServer (lifespan, DI, OpenAPI из коробки) | 2026-09-14 | ✅ принято, core/auth/special перенесены |
| ADR-002 | `AppContext` — контекстный менеджер жизненного цикла (`startup`/`shutdown`) | 2026-09-14 | ✅ реализовано |
| ADR-003 | Один глобальный контекст, сервисы регистрируются в `ServiceRegistry`; **никаких колбэков между сервисами** — только `ctx.get_service(name)` | 2026-09-14 | ✅ реализовано |
| ADR-004 | Структурированное JSON-логирование (файл) + human-readable (консоль) + audit_log в БД | 2026-09-14 | ✅ реализовано |
| ADR-005 | Конфиг загружается **первым** (`ConfigLoader` → Pydantic `Config`), валидируется, передаётся в `AppContext` и `create_app` | 2026-09-14 | ✅ реализовано |
| ADR-006 | Legacy `netpulse/services.py` → `netpulse/svc_legacy.py` (освобождение имени для пакета `services/`); legacy-бэкенды подключаются defensive (try/except → degraded) | 2026-09-14 | ✅ выполнено |
| ADR-007 | Безопасность: token auth (X-Auth/cookie), rate limit, brute-force block, RBAC admin/viewer, CORS allowlist, security headers, audit middleware | 2026-09-14 | ✅ middleware готовы |
| ADR-008 | `to_legacy_dict()` (config/legacy_export.py): v3 Config → legacy flat-dict; `legacy_raw` в модели сохраняет все неизвестные секции (lan/quality/email/webhook). Бэкенды получают 100% ключей | 2026-09-15 | ✅ monitor/inventory/journal/mesh attached |
| ADR-009 | `FirewallCtl`+`BackupManager` извлечены из legacy server.py → `netpulse/sysutils.py` (логика 1:1); legacy server.py импортирует обратно | 2026-09-15 | ✅ выполнено |
| ADR-010 | Единая БД: v3 `Database.path` = `network_stats.db` (как legacy DatabaseManager). v3-роуты видят legacy-таблицы (speedtest_log и т.д.) | 2026-09-15 | ✅ speedlog отдаёт живую историю |
| ADR-011 | Все 13 wrapper-сервисов (watchdog/planner/runbooks/backupwatch/softwareinv/wol/infra/healing/customchecks/l2map/cve/proxmox/ai + sla/geo/ram_forecast/mtr_history) делегируют инстансам внутри monitor backend — один корень, никаких дублирующих конструкций | 2026-09-15 | ✅ 23/23 attached (proxmox disabled по конфигу) |
| ADR-012 | `server/jobs.py` (JobManager): замена legacy JOBS+ThreadPool+polling. Background-задачи (securityscan) — asyncio task + to_thread, результат по job_id | 2026-09-15 | ✅ quick-скан done с реальными результатами |
| ADR-013 | Auth middleware: пустой POST без тела пропускает проверку Content-Type (иначе aitrain/mtrstop ломались с 415) | 2026-09-15 | ✅ исправлено |
| ADR-014 | Legacy `netpulse/config.py` → `netpulse/config_legacy.py` (то же затенение пакетом, что было с services.py). `svc_legacy.apply_settings` и старый server.py переведены на `config_legacy` | 2026-09-15 | ✅ выполнено |
| ADR-015 | POST `/api/settings`: применение через legacy `apply_settings` (merge + save config.json с DPAPI/bэкапом + live pinger/ai), затем перезагрузка v3 Config в `app.state` | 2026-09-15 | ✅ готово |
| ADR-016 | MeshService: `nodes_info`/`services_info`/`metrics_snapshot` (async, история CPU/RAM в памяти сервиса). P2P-мост реально соединился (netpulsehub ↔ node0/node1) | 2026-09-15 | ✅ p2pmetrics с живыми данными |
| ADR-017 | Legacy-зачистка: `_legacy/*` (4 файла) + старый `netpulse/server.py` (2363 строки) → `_archive/legacy_2024_09/`; `__pycache__` вычищены. Рабочий legacy (svc_legacy/mesh/inventory/journal/config_legacy/sysutils) остаётся как бэкенды | 2026-09-15 | ✅ выполнено |
| ADR-018 | `config.example.json` генерируется из v3-модели (`Config().model_dump`); загрузчик принимает пример как есть — канонический вложенный формат документирует структуру | 2026-09-15 | ✅ готово |
| ADR-019 | pytest-suite: `tests/unit` (config/registry/brute-force — 15 тестов) + `tests/integration` (lifespan с fake-сервисами, auth, audit — 2 теста). Изоляция через tmp_db/tmp_log и monkeypatch `_register_services` | 2026-09-15 | ✅ 17 passed |
| ADR-020 | Jinja2-гибрид: серверный first paint (`base.html` + partials `stat_card/session_table/park_table/forecast_bar` + фильтры `fmtnum/pct/status_dot/mbps`) на `/`, live-обновление inline SSE/fetch-скриптом по `data-srv`. Старый SPA untouched на `/index.html` | 2026-09-15 | ✅ smoke6 зелёный |
| ADR-021 | DPAPI: v3-лоадер расшифровывает `dpapi:`-значения в память через legacy `decrypt_config` (в файл — только шифр). Без этого вход по plaintext-токену давал 401 | 2026-09-15 | ✅ логин проверен на живом хабе |
| ADR-022 | Swagger blank: виноват был наш CSP (`script-src 'self'` резал CDN). Расширен под jsdelivr/fonts; `/api/openapi.json` и CDN всегда были доступны | 2026-09-15 | ✅ CSP проверен в заголовках |
| ADR-023 | Одна настоящая нода: `start_all.ps1` переведён на single-node (только mesh\node0:9000), `config.json` p2p.targets=[node0]. Стейл-процессы (от 14.09, elevated) блокируют бинд — их снос только через elevated `start_all` | 2026-09-15 | ✅ запуск 15.09 ~03:56: свежая нода (9000) и хаб (8771), мост connected→node0; стейл-хаб 8770 (PID 15176) пережил — снести вручную |
| ADR-024 | Тотальный рерайт legacy без поломок: config_legacy→config/store, sysutils, 16 малых модулей, mesh, core×7, ai×4, svc_legacy(69КБ)→netpulse/monitor/* (7 модулей, файл удалён). Правило: тот же контракт + типы + тесты; проверки: pytest 129, live smoke, рестарт хаба | 2026-09-15 | ✅ хаб на новом коде, все проверки зелёные |
| ADR-025 | p2p_core (84 файла, 16K строк, отдельный репозиторий P2P_Core) — вендор-граница: не переписывается, только mesh_auth используется мостом; ноды работают штатно | 2026-09-15 | ✅ зафиксировано |
| ADR-026 | Отчёт 500: `monitor.live_alerts` — deque, слайс `[:15]` кидал TypeError. Исправлено через `list(...)`, добавлен регресс-тест `test_report.py` | 2026-09-15 | ✅ проверено in-process (все отчёты 200) |

## 3. Component Map

```
__main__.py
  └─ load_config() → Config (Pydantic)
  └─ AppContext(config)
       ├─ setup_logging()
       ├─ Database.connect() + migrate()
       ├─ ServiceRegistry: 22 сервиса (топологическая сортировка по dependencies)
       └─ create_app(config, ctx) → FastAPI
            ├─ lifespan → ctx.startup()/shutdown()
            ├─ middleware: RequestID → SecurityHeaders → CORS → RateLimit → Auth → Audit
            ├─ routes: /api/* (волны миграции)
            └─ static: /static + SPA fallback /
```

## 4. Service Registry

| Service | Dependencies | Backend |
|---------|--------------|---------|
| monitor | — | legacy svc_legacy (to_legacy_dict) — attached 2026-09-15 |
| inventory | monitor | legacy-объект монитора — attached 2026-09-15 |
| journal | monitor | legacy-объект монитора — attached 2026-09-15 |
| mesh | monitor | legacy netpulse.mesh (legacy_p2p_client_cfg) |
| backup | — | netpulse.sysutils.BackupManager |
| firewall | — | netpulse.sysutils.FirewallCtl (новый сервис, 23-й) |
| watchdog | monitor, inventory | legacy netpulse.watchdog |
| planner | — | legacy netpulse.planner |
| runbooks | — | legacy netpulse.runbooks |
| backupwatch | — | legacy netpulse.backupwatch |
| softwareinv | inventory | legacy netpulse.softwareinv |
| wol | — | legacy netpulse.wol |
| infra | inventory | legacy netpulse.infra |
| healing | inventory | legacy netpulse.healing |
| customchecks | — | legacy netpulse.customchecks |
| sla | inventory | pending migration |
| geo | — | legacy netpulse.geo |
| ram_forecast | monitor | pending migration |
| l2map | inventory | legacy netpulse.l2map |
| mtr_history | monitor | pending migration |
| cve | softwareinv | legacy netpulse.cve |
| proxmox | — | legacy netpulse.proxmox (disabled по умолчанию) |
| ai | monitor | pending migration (legacy требует отсутствующий модуль `ai`) |

Shutdown — строго в обратном порядке startup. Ошибка остановки одного сервиса не блокирует остальные.

## 5. API Endpoints — статус миграции

| 1 | Роуты | core (`state/history/dbhistory/interfaces/connections/topprocesses`), auth (`whoami/meta/login/audit/selftest/health`), special (`stream/metrics/rdp/gposcript/journal.txt/journal.csv/report.txt`) | ✅ готово |
| 2 | Роуты | apps (`apps/appnewconn/appexe/firewallrules/fwblockip/fwblockapp/fwunblock`), diagnostics (`ping/trace/traceall/dnsbest/dnsresolve/speedtest/uploadtest/speedlog/mtrstats/mtrstart/mtrstop`), lan (`landevices/lanscan/lanalias/portscan`) | ✅ готово, smoke2 зелёный на живых данных |
| 3 | Роуты | security (`idsfeed/securityscan/securityresult/idswl`), capture (`capturestart/capturestop/capturestate`), alerts (`alerts/alertsack`), ai (`ai/aitrain`) | ✅ готово, smoke3 зелёный |
| 4 | Роуты | settings (`settings/backuplist/backuprun`), journal (`journal/journaladd/journaldel/journalreport`), inventory (`hosts/hostdetail/events/softsearch/invreport/healthrecompute/wol/diskforecast`), runbooks (`runbooks/runbookexec`), planner (`planner/plannerdone/watchdogpoll`), backupwatch (`backupstatus/backupcheck`) | ✅ готово, smoke4 зелёный |
| 5 | Роуты | infra (`infra/infrascan/infradtype/infradiff`), p2p (`p2pstatus/p2pnodes/p2pservices/p2pmetrics/p2pcall`), map (`map/healing/customchecks/customchecksrun`), new_ideas (`sla/geomap/ramforecast/l2map/ptrs/l2scan/mtrhistory/mtrfan/cvestatus/cvescan/proxmox/proxmoxpoll/reportpdf`) | ✅ готово, smoke5 зелёный — МИГРАЦИЯ ЗАВЕРШЕНА (~100 эндпоинтов) |

Всего в legacy `ROUTES_GET` + `ROUTES_POST` ~100 эндпоинтов (см. `netpulse/server.py`).

## 6. Security Model

- Публичные: `/api/whoami`, `/api/meta`, `/api/login`, `/api/docs`, `/api/redoc`, `/api/openapi.json`. Остальное `/api/*` + `/metrics` — требуют токен.
- Токен: `X-Auth` header или `np_session`/`np_token` cookie (HttpOnly, SameSite=Strict). Query-токены запрещены.
- Brute force: 5 fails → блок 10 мин (настраивается `security_*`).
- Rate limit: 100 req/60s на IP (настраивается).
- RBAC: viewer — только чтение + `alertsack`/`lanalias`.
- CORS: только собственный origin + `web_cors_origins`.
- Аудит: все POST `/api/*` → таблица `audit_log` (токены маскируются).

## 7. Logging

- Файл `logs/netpulse.log` — JSON, ротация 2MB × 5. Консоль — human-readable.
- Уровни через `logging_level`. Шумные логгеры (uvicorn.access, httpx) приглушены.
- `GET /api/audit` — чтение audit_log. `GET /api/health` — здоровье сервисов.

## 8. Configuration

- Источник: `config.json` + `DEFAULTS_DICT` merge + Pydantic-валидация. Env-переопределения `NP_*`.
- Protected: `web_auth_enabled` — только правкой JSON (метод `ConfigLoader.update(protect=True)`).
- Пример: `config.example.json` (создать). `config.json` — не в git.

## 9. Legacy Cleanup

- ✅ `_legacy/*` (4 файла) → `_archive/` → удалены полностью
- ✅ Старый `netpulse/server.py` (2363 строки) → `_archive/` → удалён полностью
- ✅ Топ-`main.py` (CustomTkinter-вход) → удалён (v3 вход — `netpulse/__main__.py`)
- ✅ Старый сьют `tests/test_*.py` (4 файла), `tests/__init__.py` вычищен (остались `unit`/`integration`, 17 passed)
- ✅ `netpulse/services.py` → `netpulse/svc_legacy.py` (бэкенд монитора, жив)
- ✅ `netpulse/config.py` → `netpulse/config_legacy.py` (merge/save/DPAPI, жив)
- ✅ `FirewallCtl`+`BackupManager` → `netpulse/sysutils.py` (жив)
- ✅ `__pycache__` вычищены
- ⏳ Живое ядро и инфраструктура — таблица ниже, ждёт решения

## 10. Open Questions

- [x] ~~`config.example.json` создать из DEFAULTS~~ — готово (генерируется из модели)
- [x] ~~Тесты~~ — 17 passed (`pytest tests/unit tests/integration`)
- [x] ~~Jinja2-шаблонизация веб-UI~~ — гибрид готов (base + 4 partials + фильтры + live-скрипт), smoke6 зелёный
- [ ] `start_all.ps1` проверен под v3 (hub = `python -m netpulse`, добавлен whoami-probe); mesh-узлы без изменений
- [x] ~~DPAPI-секреты~~ — лоадер расшифровывает в память (ADR-021)
- [ ] Quota-семантика: legacy `daily_mb/monthly_gb` vs v3 `daily_limit_mb/monthly_limit_mb` — сверить с QuotaManager

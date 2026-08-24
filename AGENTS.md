# AGENTS.md — карта проекта для ИИ-ассистентов

NetPulse — локальный центр сетевого мониторинга + платформа отдела ИТ
(журнал работ, парк ПК, сторожа, runbooks). Python 3.12+, веб на stdlib,
зависимости: psutil (web) + scikit-learn/pandas/numpy (desktop AI).

## Точки входа

- `python -m netpulse` — веб-сервер (основной), дашборд на 8770
- `python main.py` — десктоп-версия (CustomTkinter, легаси)
- `python -m tests.test_netpulse` / `test_core` — тесты без pytest

## Структура

```
netpulse/server.py      HTTP-сервер: Api-класс, ROUTES_GET/ROUTES_POST,
                        Handler, FirewallCtl, BackupManager, platform_report_text
netpulse/services.py    MonitorService — живое состояние, фоновые потоки,
                        ProcessMonitor/IDS, MTR, LAN-сканер, квоты
netpulse/journal.py     Журнал работ (записи + отчёты за период)
netpulse/inventory.py   Парк: hosts, events с дедупом, карма (health-score)
netpulse/watchdog.py    Сторож ПК: PowerShell/WinRM опрос, правила, прогноз дисков
netpulse/runbooks.py    Кнопки операций (JSON в netpulse/runbooks/), аудит
netpulse/backupwatch.py Свежесть бэкапов + напоминание об учениях
netpulse/planner.py     Плановые работы (повторяющиеся задачи)
netpulse/softwareinv.py Софт-инвентарь (отчёты GPO-скрипта)
netpulse/wol.py         Wake-on-LAN (+ARP-фолбэк)
netpulse/config.py      config.json, глубокое слияние с DEFAULTS
core/database.py        DatabaseManager: пул, WAL, миграции SCHEMA_VERSION
netpulse/web/           Дашборд: index.html + app.js (SPA, SSE) + style.css
```

## Как добавить фичу (паттерн)

1. Модуль: класс `X(self_service)`, свои таблицы создаёт сам в `__init__`
   (CREATE TABLE IF NOT EXISTS), фоновый цикл — `start()/stop()` через
   `service._stop_event`-совместимый Event.
2. Сервис: в `MonitorService.__init__` → `self.x = X(self)`;
   потоки — в `start()`, остановка — в `stop()`.
3. API: метод в `Api` + запись в `ROUTES_GET`/`ROUTES_POST`.
   Тела POST читаются `self._read_body()`.
4. UI: кнопка `data-view` + `<section id="view-*">` в index.html,
   метод в объекте `UI` в app.js, хук в `switchView`, заголовок в `VIEW_TITLES`.
5. Тест: `tests/test_*.py` (раннер свой, без pytest).

## Инварианты и грабли

- Timestamps в БД — localtime (datetime.now()), в SQL-фильтрах
  `datetime('now','localtime',...)`. Не смешивать с UTC.
- `db.execute(fetch=True)` возвращает list[dict]; INSERT+lastrowid —
  только через `with db.connection()` (пул соединений!).
- Секреты: web_token/telegram.token маскировать в любых ответах API.
- `PROTECTED_SETTINGS = {"web_auth_enabled"}` — нельзя менять через API.
- Статику правишь — учти кэш браузера (no-cache уже выставлен).
- В app.js не дублировать имена const в одной функции (уже ловили).
- Не коммитить: *.db*, logs/, __pycache__, config.json (см. .gitignore).

## Деплой на машине Петра

Задача планировщика `NetPulse` (RunLevel Highest) запускает
`start_netpulse.ps1` (убивает прошлый процесс на 8770, стартует сервер).
Перезапуск после деплоя: `schtasks /End /TN NetPulse; schtasks /Run /TN NetPulse`
(из не-админа /End может не убить python-ребёнка — тогда elevated).

## Диагностика

- `/api/selftest` — здоровье БД/модулей/диска
- `/api/meta` — карта эндпоинтов, таблиц, модулей (для ИИ)
- `node --check netpulse/web/app.js` — синтаксис фронтенда
- Playwright-скрипт для скриншотов/консоли — по запросу

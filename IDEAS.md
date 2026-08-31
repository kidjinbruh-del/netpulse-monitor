# IDEAS.md — бэклог идей сисадмина (NetPulse)

Сводка предложений от сисадмина для развития NetPulse.
Статусы: `[новая]` — не начата, `[бэклог]` — может требовать интеграции, `[закрыта]` — вердикт, `[сделано]` — реализовано в коде.
Решение по каждой идее принимает владелец; реализованные фичи попадают в [CHANGELOG](CHANGELOG.md).

## Сеть и инвентарь

1. **[сделано] MAC → порт коммутатора.** По SNMP (Bridge MIB dot1dTpFdbTable) показывать, на каком порту какого свитча сидит устройство. Модуль `netpulse/l2map.py`, таблица `l2_ports`, раздел «Сисадмин» → «L2-порты».
2. **[сделано] Соседи по LLDP/CDP.** LLDP-MIB (`lldpRemTable`) + локальная база `l2_ports.lldp_json`. Физическая топология доступна API `/api/l2map`.
3. **[сделано] ARP/DNS-резолв имён.** `L2Map.resolve_ptrs()` — массовые PTR-запросы по устройствам без hostname (API `/api/ptrs`, кнопка «Опрос»).
4. **[новая] Wi-Fi-клиенты.** Требует доступа к AP/контроллеру (крайне редко встречаются в среде) — оставлена в бэклоге.

## Мониторинг и алерты

5. **[сделано] Пороговые профили по группам устройств.** `quality.profiles` в config; `profile_thresholds(dtype)` + алерт `PROFILE_LIMIT` в `scan_infra` (профили: server/router/pc).
6. **[сделано] REST-хуки + эскалации в Telegram.** `_escalate_loop()`: не-подтверждённые алерты повторяются через `escalate.unack_min` и уходят в Telegram по `escalate.hook_url`.
7. **[сделано] Диапазон + PDF-отчёт.** `_weekly_report_text()` + отдельная печатная страница топологии (кнопка «Печать») и API `/api/reportpdf`; экспорт SVG/PNG/JSON карты существовал.
8. **[сделано] Прогноз заполнения RAM и дисков шлюза.** `ram_forecast()` по `history` (наименьшие квадраты, горизонт до 95%) — API `/api/ramforecast`, блок в «Сисадмин». Диски уже были `disk_history`/`diskfc`.

## Безопасность

9. **[сделано] Карта атак по источникам.** `netpulse/geo.py` (локальная таблица префиксов → страна, без внешних API) + `geo_attack_map()` по алертам SUSPICIOUS_CONN/PORT_SCAN/SECURITY_SCAN и `procmon.ids_events`. API `/api/geomap`.
10. **[сделано] Авто-diff SNMP-конфигов.** `save_snapshot()` пишет `infra_snaps`; `auto_diff()` сравнивает соседние слепки и алертит `CONFIG_CHANGED` по diff.
11. **[сделано] Whitelist MAC.** `lan.trusted_macs` в config; `scan()` не поднимает `LAN_NEW_DEVICE` для доверенных MAC.
12. **[сделано] Связь инвентаря ПО с CVE-базами.** `netpulse/cve.py`: NVD API v2 (без ключа, кэш `sw_cve`, rate-limit 1.2 c/запрос); API `/api/cvestatus`, `/api/cvescan`, кнопка «Проверить» в «Сисадмин».

## Удобство сисадмина

13. **[сделано] Dark theme + полноэкранная печатная топология.** Тёмная тема уже была; добавлена кнопка «Печать» (светлая страница A4 из текущей топологии), плюс экспорт SVG/PNG/JSON.
14. **[сделано] RBAC / API-токены.** `_identity()` возвращает `(имя, роль)`; `web_users` в config; POST-действия отклоняются для `viewer` (403), кроме подтверждения алертов и алиасов. `whoami` отдаёт роль.
15. **[сделано] Интеграция с Proxmox.** `netpulse/proxmox.py` (PVE API /api2/json, токен, таблица `proxmox_status`).
16. **[сделано] Конфиг через env/.env.** `_env_overrides()` − `NETPULSE_*` поверх `config.json` + `.env` (секреты без правки файла).

## Отчётность

17. **[сделано] Еженедельный авто-отчёт.** Email/Telegram/webhook: `_weekly_report_loop()` + `_weekly_report_text()` (аптайм, карма, топ алертов).
18. **[сделано] SLA-доступность узлов за месяц.** `sla_period(days)` по `hosts` и событиям OFFLINE/ONLINE — API `/api/sla`, блок в «Сисадмин».
19. **[сделано] Лента изменений из audit.** Вкладка «Сисадмин» → «Лента изменений» из таблицы `audit_log` (кто/что/когда менял).

## Мониторинг сети (L3)

20. **[сделано] MTR «пакетами веером» по расписанию.** `MTREngine.save_snapshot()` (таблица `mtr_history`) + `schedule_loop()` ротация по `mtr.targets`; API `/api/mtrhistory`, блок «MTR-история».
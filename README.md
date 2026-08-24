# NetPulse

Локальный центр сетевого мониторинга на Python. Весь трафик, пинги, сканы и данные остаются на вашей машине — никакого облака.

## Возможности

- Живая скорость по интерфейсам (down/up), топ процессов по соединениям
- Оценка качества связи (пинг / джиттер / потери → score 0–100)
- Диагностика: ping-probe, traceroute, живой MTR, подбор лучшего DNS, speedtest
- Карта LAN-устройств с алертами о новых подключениях, TCP-сканер портов
- IDS: детект сканов портов и подозрительных соединений
- Захват пакетов (raw socket, нужны права администратора)
- Аномалии трафика через IsolationForest (scikit-learn)
- Web-дашборд (SSE, обновление раз в секунду) + Prometheus `/metrics`
- Управление Windows Firewall из дашборда (блок IP/приложения)
- Алерты с дедупликацией, опциональные Telegram-уведомления, автобэкапы

## Две версии

| | Web (`netpulse`) | Desktop (`main.py`) |
|---|---|---|
| Запуск | `python -m netpulse` | `python main.py` |
| Интерфейс | браузер `http://127.0.0.1:8770` | окно CustomTkinter |
| Зависимости | только `psutil` | `requirements.txt` |

Web-версия — основная и активно развиваемая; десктопная сохранена как альтернативный UI.

## Быстрый старт

```bash
pip install psutil            # web-версия
python -m netpulse --port 8770
```

```bash
pip install -r requirements.txt   # desktop-версия
python main.py
```

Захват пакетов и блокировка через firewall требуют запуска от администратора.

## Аутентификация веб-дашборда

В `config.json`:

```json
"web_auth_enabled": true,
"web_token": "длинная-случайная-строка"
```

Токен передаётся заголовком `X-Auth` либо параметром `?token=` (для EventSource/SSE). Без включённого auth API доступен только с localhost.

## Конфигурация

При первом запуске создаётся/используется `config.json`. Основные секции: `quality` (пороги оценки качества), `quota` (лимиты трафика), `security.suspicious_ports`, `ids`, `diagnostics` (цели trace/DNS), `speedtest`, `telegram`, `backup`.

Файл не хранится в репозитории — может содержать токены (например, Telegram).

## Тесты

```bash
python -m tests.test_netpulse
python -m tests.test_core
```

## Структура

```
netpulse/     web-версия: HTTP-сервер, сервисы, дашборд (web/)
core/         общее: БД, пингер, сниффер, traceroute, security-сканер
ai/           агенты аномалий и прогнозов (desktop-версия)
ui/           desktop-интерфейс на CustomTkinter
tests/        тесты без внешних зависимостей
_legacy/      архив первой монолитной версии
```

## Лицензия

MIT — см. [LICENSE](LICENSE).

# MikroTik и внешние системы мониторинга

NetPulse 2.4 опрашивает MikroTik в фоне и отдаёт кэш через `/api/mikrotik` и `/metrics`. Открытие дашборда или scrape Prometheus не запускает запросы к роутеру. В интерфейсе: «Инфраструктура» → MikroTik → обновление состояния или внеочередной опрос.

## Поддержка RouterOS

| Устройство | Транспорт | Вход |
|---|---|---|
| RouterOS 7 с REST | HTTPS REST (www-ssl) | Имя и пароль по TLS |
| RouterOS 6.43+ и 7 | API-SSL, обычно 8729 | Современный API login |
| RouterOS 6 до 6.43 | API-SSL с `legacy_login: true` | Challenge/response внутри TLS |

Это совместимость протоколов, а не обещание работы с каждым выпуском прошивки. Нужны действующий сертификат, доверенная CA и поддерживаемая Python версия TLS. Старую прошивку без современного TLS обновите. Отключения проверки сертификата, HTTP и открытого API на 8728 нет. На физических устройствах проверка ещё не проводилась; автотесты используют локальные HTTPS/API-SSL имитаторы, включая legacy login.

Создайте отдельную учётную запись MikroTik с `read` и `rest-api` для REST либо `read` и `api` для API-SSL. Не выдавайте `write`, `policy`, `sensitive` и административный доступ. Разрешите доступ к службе только с IP сервера NetPulse. Сертификат должен соответствовать имени/IP в URL. Службу и правила доступа настраивает администратор: NetPulse не меняет конфигурацию роутера.

## Локальная конфигурация

Добавьте в `config.json` (остальные настройки сохраните):

```json
{
  "mikrotik": {
    "enabled": true,
    "poll_interval_sec": 30,
    "devices": [
      {
        "id": "office",
        "name": "Офис",
        "transport": "rest",
        "url": "https://router.example.internal",
        "username": "netpulse",
        "password_env": "NP_ROUTER_OFFICE_PASSWORD",
        "ca_file": "C:/NetPulse/certs/router-ca.pem",
        "timeout_sec": 5
      }
    ]
  },
  "metrics": {"token_env": "NP_METRICS_TOKEN"}
}
```

Для API-SSL замените транспорт на `api_ssl`, URL на `https://router.example.internal:8729`; для старого login добавьте `legacy_login: true`. `ca_file` можно опустить для сертификата публичной CA. Пароли задайте переменными окружения процесса NetPulse, а не в JSON или браузере. Например PowerShell: `$env:NP_ROUTER_OFFICE_PASSWORD = Read-Host 'Router password' -MaskInput`. Сервису задайте переменные через менеджер запуска; секреты в Git не добавляйте.

Перезапустите NetPulse после изменения локального файла. `python -m netpulse --check` проверяет формат, наличие пароля и CA без подключения к сети. Опрос ограничен 16 устройствами, 256 интерфейсами на устройство, четырьмя параллельными задачами, 2 MiB на ответ и тайм-аутом 1–10 секунд на операцию. Интервал ограничен 15–3600 секундами. При отказе подключения остаётся время последнего успеха; CPU/счётчики не подменяются нулями и устаревшими значениями.

## Prometheus + Grafana: основной вариант

Готовые файлы: `deploy/observability/`. Prometheus хранит историю и вычисляет скорость из счётчиков, Grafana показывает готовый дашборд. NetPulse экспортирует CPU, память, uptime, состояния интерфейсов, байты, ошибки и потери пакетов, а также качество сети самого сервера.

1. Установите Docker Compose. Создайте `deploy/observability/secrets/`.
2. Создайте случайный длинный токен в `netpulse_metrics_token.txt`, без кавычек; такое же значение задайте в `NP_METRICS_TOKEN` процесса NetPulse. В `grafana_admin_password.txt` положите отдельный случайный пароль администратора Grafana. Для Alertmanager создайте третий отдельный токен в `netpulse_alertmanager_token.txt` и задайте то же значение процессу NetPulse в `NP_ALERTMANAGER_TOKEN`. Каталог исключён из Git.
3. В NetPulse включите `web_auth_enabled`, задайте отдельный административный токен. Bearer-токен метрик разрешает только `/metrics`, доступа к настройкам и операциям он не даёт.
4. Проверьте target в `prometheus/prometheus.yml`. По умолчанию контейнер обращается к `host.docker.internal:8770` по HTTP. Это пример для доверенной локальной сети Docker на одном компьютере. NetPulse с bind `127.0.0.1` из контейнера обычно недоступен: настройте доступный контейнеру адрес и ограничьте вход firewall подсетью Docker. Автоматически NetPulse сетевые настройки не меняет.
5. Для обращения через LAN используйте HTTPS NetPulse, `scheme: https`, правильный hostname и `tls_config.ca_file` с примонтированной CA. Проверку TLS не отключайте.
6. Из каталога `deploy/observability` выполните `docker compose config`, затем `docker compose up -d`. Prometheus: http://localhost:9090/targets, Grafana: http://localhost:3000 (admin и пароль из файла). Дашборд — папка NetPulse.

Включены правила недоступности экспортера, ошибки опроса роутера, остановки коллектора, высокой CPU и недостатка памяти. Порог устаревания учитывает интервал опроса. Alertmanager включён в Compose; для доставки событий в NetPulse настройте его отдельный токен, а для внешних уведомлений — включённый канал NetPulse. Подробности: [операционный центр](OPERATIONS.md). Смена пароля в файле Grafana после первого запуска не меняет существующую учётную запись в её БД.

На этой рабочей машине Docker отсутствует: запуск всего стека не проверялся. CI проверяет конфигурацию Prometheus и правила через официальный `promtool`; структура Compose, dashboard и provisioning проверяется автотестами.

## Zabbix как альтернативный потребитель

`deploy/zabbix/netpulse-7.0.yaml` — шаблон для Zabbix 7.0: HTTP agent получает `/metrics`, dependent items извлекают доступность экспортера, качество сети и непрочитанные предупреждения. Импортируйте шаблон, привяжите к хосту, задайте макросы `{$NETPULSE.URL}` и секретный `{$NETPULSE.TOKEN}`. Для частной CA настройте доверие на Zabbix server/proxy. Шаблон не содержит discovery интерфейсов MikroTik; для их готовых графиков используйте Grafana. Импорт на живой Zabbix ещё не проверялся.

## Источники протоколов

- [MikroTik REST API](https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST+API)
- [MikroTik API](https://help.mikrotik.com/docs/spaces/ROS/pages/47579160/API)
- [Prometheus configuration](https://prometheus.io/docs/prometheus/latest/configuration/configuration/)
- [Grafana provisioning](https://grafana.com/docs/grafana/latest/administration/provisioning/)

- [Zabbix 7.0 template export](https://www.zabbix.com/documentation/7.0/en/manual/xml_export_import/templates)

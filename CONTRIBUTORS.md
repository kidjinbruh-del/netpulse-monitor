# Контрибьюторы

Репозиторий ведётся совместно. Проект **NetPulse** объединяет два кодовых
направления: центральный мониторинг (NetPulse Hub) и распределённую
mesh-сеть узлов (**P2P_Core**).

## Совместная работа: P2P_Core

Пакет `netpulse/p2p_core/` (mesh-сеть узлов: networking, internal_modules,
services, node_runner) разрабатывается совместно с автором проекта
[P2P_Core](https://github.com/olegs32/P2P_Core):

| Участник | Профиль | Роль |
|---|---|---|
| **kidjinbruh-del** | https://github.com/kidjinbruh-del | Меш-аутентификация (HMAC), интеграция P2P_Core в NetPulse, node_runner, Hub-клиент |
| **olegs32** | https://github.com/olegs32 | Сетевое ядро P2P_Core: протокол v2.0 (msgpack), роутер, транспорт, сессии, сервисы |

P2P_Core — самостоятельный проект (собственный git-репозиторий); в NetPulse
он представлен как часть единого кода меша. Изменения синхронизируются в обе
стороны между [netpulse-monitor](https://github.com/kidjinbruh-del/netpulse-monitor)
и [P2P_Core](https://github.com/olegs32/P2P_Core).

## Участники

<!-- Список участников проекта. Правки — по согласованию. -->
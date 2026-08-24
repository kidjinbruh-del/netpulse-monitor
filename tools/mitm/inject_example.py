"""
mitmproxy-аддон для инъекций в трафик программы (шаблон Олега).

Запуск:
    mitmdump -s inject_example.py -p 8080
    (или mitmweb для веб-интерфейса)

Направить программу сюда:
  1) Программа умеет системный прокси -> просто укажите 127.0.0.1:8080
     в настройках Windows (Параметры -> Сеть -> Прокси).
  2) Программа игнорирует прокси -> Proxifier: правило "имя.exe -> 127.0.0.1:8080"
     (в Proxifier тип прокси HTTPS).
  3) HTTPS: открыть http://mitm.it через браузер с этим прокси,
     установить сертификат mitmproxy в "Доверенные корневые ЦС".
     Если программа пинит сертификат -> только Frida (unpinning), это отдельно.

Полезные CLI-режимы без скрипта:
    mitmdump -p 8080 --modify-headers '~u api ~req X-Debug 1'
    mitmdump -p 8080 --modify-body '~u /api/check ~s "old" "new"'
    mitmdump -p 8080 --map-local '~u site.com/config.json C:\\patch\\config.json'
    mitmdump -p 8080 --client-replay flowfile   # переиграть захваченный запрос
"""

import json
from mitmproxy import http

# Что перехватываем: подставьте хост/порт вашей программы
TARGET_HOST = "api.example.com"


class Injector:
    # ---------- инъекция В ЗАПРОС ----------
    def request(self, flow):
        if TARGET_HOST not in flow.request.host:
            return

        # пример 1: дописать/подменить заголовок
        flow.request.headers["X-Debug"] = "1"

        # пример 2: подменить параметр в JSON-теле
        if flow.request.method == "POST" and flow.request.content:
            try:
                body = json.loads(flow.request.get_text())
                if isinstance(body, dict) and "license" in body:
                    body["license"] = "TEST-KEY-123"
                    flow.request.set_text(json.dumps(body))
            except (ValueError, TypeError):
                pass

        # пример 3: редирект запроса на свой стенд
        # flow.request.host = "127.0.0.1"
        # flow.request.port = 9000

    # ---------- инъекция В ОТВЕТ ----------
    def response(self, flow):
        if TARGET_HOST not in flow.request.host:
            return

        # пример 4: подправить поле в ответе сервера
        if flow.response and flow.response.content:
            try:
                data = json.loads(flow.response.get_text())
                if isinstance(data, dict) and "version" in data:
                    data["version"] = "9.9.9-debug"
                    flow.response.set_text(json.dumps(data))
            except (ValueError, TypeError):
                pass

        # пример 5: полностью фейковый ответ (сервер даже не спрашивается)
        # if flow.request.path == "/api/v1/license/check":
        #     flow.response = http.Response.make(
        #         200,
        #         json.dumps({"status": "ok", "until": "2030-01-01"}),
        #         {"Content-Type": "application/json"})


addons = [Injector()]

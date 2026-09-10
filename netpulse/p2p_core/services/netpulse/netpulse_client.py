# services/netpulse/netpulse_client.py — HTTP-клиент к API NetPulse (сервер мониторинга)
# Сервис обращается к локальному центральному NetPulse через REST API.

import logging

logger = logging.getLogger("netpulse.api_client")


class NetPulseClient:
    """Тонкий HTTP-клиент к NetPulse REST API."""

    def __init__(self, base_url="http://127.0.0.1:8770", timeout=5.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    # ------------------------------------------------------------------ #
    #  Низкоуровневый GET к /api/<endpoint>
    # ------------------------------------------------------------------ #
    def get(self, endpoint, params=None, timeout=None):
        """Вернуть JSON-ответ `data` (dict/list) эндпоинта netpulse.
        Возвращает None при ошибке/недоступности сервера."""
        import requests
        url = f"{self.base_url}/api/{endpoint}"
        try:
            r = requests.get(url, params=params, timeout=timeout or self.timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.debug("netpulse GET %s failed: %s", url, e)
            return None

    # ------------------------------------------------------------------ #
    #  Низкоуровневый POST к /api/<endpoint>
    # ------------------------------------------------------------------ #
    def post(self, endpoint, body=None, timeout=None):
        """POST JSON-тело на /api/<endpoint>.
        Возвращает JSON-ответ или None при ошибке."""
        import requests
        url = f"{self.base_url}/api/{endpoint}"
        try:
            r = requests.post(url, json=body or {}, timeout=timeout or self.timeout)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.debug("netpulse POST %s failed: %s", url, e)
            return None

    # ------------------------------------------------------------------ #
    #  Конкретные методы (для RPC-сервиса)
    # ------------------------------------------------------------------ #
    def alive(self):
        """Проверка доступности сервера мониторинга."""
        meta = self.get("meta")
        return meta is not None

    def collect(self):
        """Полный снимок состояния мониторинга (/api/state)."""
        return self.get("state")

    def alerts(self, limit=80):
        return self.get("alerts", {"limit": limit})

    def events(self, limit=80, host_id=None):
        params = {"limit": limit}
        if host_id:
            params["host_id"] = host_id
        return self.get("events", params)

    def hosts(self):
        return self.get("hosts")

    def host_detail(self, host_id):
        return self.get("hostdetail", {"id": host_id})

    def landevices(self):
        return self.get("landevices")

    def l2map(self):
        return self.get("l2map")

    def map(self):
        return self.get("map")

    def infra(self):
        return self.get("infra")

    def selftest(self):
        return self.get("selftest")

    def meta(self):
        return self.get("meta")

    def journal(self, limit=150):
        return self.get("journal", {"limit": limit})

    def history(self, minutes=30):
        return self.get("history", {"minutes": minutes})

    def proxy(self, endpoint, query_params=None):
        """Универсальный прокси к произвольному эндпоинту netpulse."""
        return self.get(endpoint, query_params)

    # ------------------------------------------------------------------ #
    #  Write-операции (POST) — агрегация событий/алертов на сетевом уровне
    # ------------------------------------------------------------------ #
    def alerts_ack(self, alert_id=None):
        """Подтвердить алерт (по id) или все неподтверждённые."""
        body = {"id": alert_id} if alert_id else {}
        return self.post("alertsack", body)

    def journal_add(self, text, source="ps2p", host=None, user=None,
                    minutes=0):
        """Добавить запись в журнал работ."""
        body = {"text": text, "source": source, "host": host,
                "user": user, "minutes": minutes}
        return self.post("journaladd", body)

    def journal_delete(self, entry_id):
        return self.post("journaldel", {"id": entry_id})

    def health_recompute(self):
        return self.post("healthrecompute")

    def lan_alias(self, mac, alias, timeout=10):
        return self.post("lanalias", {"mac": mac, "alias": alias}, timeout=timeout)

    def runbook_exec(self, name, params=None, actor="ps2p"):
        return self.post("runbookexec", {"name": name, "params": params or {},
                                         "actor": actor})

    def watchdog_poll(self):
        # обход watchdog может идти до 4 минут
        return self.post("watchdogpoll", timeout=250)

    def lan_scan(self):
        # LAN-скан может идти долго
        return self.post("lanscan", timeout=120)

# services/netpulse/service.py — интеграция NetPulse (мониторинг) в mesh.
# Проксирует состояние центрального NetPulse в P2P-сеть: любой узел сети
# может запросить мониторинг (состояние, алерты, события, парк, топологию)
# у узла, где запущен сервис, через обычный RPC-механизм P2P_Core.

from netpulse.p2p_core.internal_modules.base import ModuleGeneric
from netpulse.p2p_core.services.rpc import rpc

from netpulse.p2p_core.services.netpulse.netpulse_client import NetPulseClient


class NetPulse(ModuleGeneric):
    """Мост: NetPulse (REST API) <-> mesh RPC."""

    PROVIDES = ("netpulse", "monitoring")

    def __init__(self, name, context):
        super().__init__(name, context)
        self.client = NetPulseClient()

    # ------------------------------------------------------------------ #
    #  Базовые данные мониторинга
    # ------------------------------------------------------------------ #
    @rpc
    def status(self, data: dict):
        """Краткий статус: доступен ли мониторинг и что умеет."""
        meta = self.client.meta()
        if meta is None:
            return {"ok": False, "node": self.ctx.NODE, "monitoring": "offline"}
        return {
            "ok": True,
            "node": self.ctx.NODE,
            "monitoring": "online",
            "app": meta.get("app"),
            "endpoints": meta.get("endpoints_get", [])[:60],
        }

    @rpc
    def collect(self, data: dict):
        """Полный снимок состояния сети (/api/state)."""
        snap = self.client.collect()
        if snap is None:
            return {"ok": False, "error": "netpulse offline"}
        snap = dict(snap)
        snap["_node"] = self.ctx.NODE
        return snap

    @rpc
    def alerts(self, data: dict):
        """Алерты мониторинга. data: {'limit': N}."""
        limit = data.get("limit", 80) if isinstance(data, dict) else 80
        res = self.client.alerts(limit)
        if res is None:
            return {"ok": False, "error": "netpulse offline"}
        res["_node"] = self.ctx.NODE
        return res

    @rpc
    def events(self, data: dict):
        """События парка машин. data: {'limit': N, 'host_id': N}."""
        if not isinstance(data, dict):
            data = {}
        res = self.client.events(data.get("limit", 80), data.get("host_id"))
        if res is None:
            return {"ok": False, "error": "netpulse offline"}
        return res

    @rpc
    def hosts(self, data: dict):
        """Парк машин со статусом watchdog. data: {} (ignored)."""
        res = self.client.hosts()
        if res is None:
            return {"ok": False, "error": "netpulse offline"}
        return res

    @rpc
    def host_detail(self, data: dict):
        """Детали машины. data: {'host_id': N}."""
        hid = data.get("host_id") if isinstance(data, dict) else None
        res = self.client.host_detail(hid)
        if res is None:
            return {"ok": False, "error": "netpulse offline"}
        return res

    @rpc
    def journal(self, data: dict):
        """Журнал работ. data: {'limit': N}."""
        limit = data.get("limit", 150) if isinstance(data, dict) else 150
        res = self.client.journal(limit)
        if res is None:
            return {"ok": False, "error": "netpulse offline"}
        return res

    @rpc
    def selftest(self, data: dict):
        """Самодиагностика netpulse."""
        return self.client.selftest()

    @rpc
    def meta(self, data: dict):
        """Метаданные netpulse (эндпоинты, таблицы, модули)."""
        return self.client.meta()

    # ------------------------------------------------------------------ #
    #  Топология
    # ------------------------------------------------------------------ #
    @rpc
    def topology(self, data: dict):
        """Топология сети с точки зрения netpulse (/api/map)."""
        res = self.client.map()
        if res is None:
            return {"ok": False, "error": "netpulse offline"}
        return res

    @rpc
    def map(self, data: dict):
        """ЕДИНАЯ КАРТА: топология LAN (netpulse /api/map) + L2 + mesh-соседи."""
        topo = self.client.map()
        if topo is None:
            return {"ok": False, "error": "netpulse offline"}
        mesh_all = self.ctx.network.neighbor_table.all()
        mesh = [
            {"node_id": n.node_id, "host": n.host, "port": n.port,
             "via": n.via, "services": list(n.services)}
            for n in mesh_all
        ]
        return {
            "ok": True,
            "node": self.ctx.NODE,
            "self_ip": topo.get("self_ip"),
            "gateway": topo.get("gateway"),
            "lan_nodes": topo.get("nodes", []),
            "l2": self.client.l2map(),
            "mesh_nodes": mesh,
        }

    @rpc
    def l2map(self, data: dict):
        """L2-карта (MAC->порт). data: {'mac': '...'} (optional)."""
        params = {}
        if isinstance(data, dict) and data.get("mac"):
            params["mac"] = data["mac"]
        res = self.client.l2map()
        if res is None:
            return {"ok": False, "error": "netpulse offline"}
        return res

    @rpc
    def landevices(self, data: dict):
        """Устройства, обнаруженные в LAN."""
        res = self.client.landevices()
        if res is None:
            return {"ok": False, "error": "netpulse offline"}
        return res

    @rpc
    def infra(self, data: dict):
        """Устройства инфраструктуры (SNMP)."""
        res = self.client.infra()
        if res is None:
            return {"ok": False, "error": "netpulse offline"}
        return res

    # ------------------------------------------------------------------ #
    #  Универсальный доступ + обнаружение узлов
    # ------------------------------------------------------------------ #
    @rpc
    def proxy(self, data: dict):
        """Прокси к любому GET-эндпоинту netpulse.
        data: {'endpoint': 'state', 'params': {...}}"""
        if not isinstance(data, dict):
            return {"ok": False, "error": "data must be dict"}
        ep = data.get("endpoint")
        if not ep or not isinstance(ep, str):
            return {"ok": False, "error": "endpoint required"}
        res = self.client.proxy(ep, data.get("params"))
        if res is None:
            return {"ok": False, "error": "netpulse offline"}
        return res

    @rpc
    def find_nodes(self, data: dict):
        """Найти узлы mesh, где доступен мониторинг netpulse."""
        table = self.ctx.network.neighbor_table
        found = table.find_by_service(self.name)
        nodes = []
        for info in found:
            nodes.append({"node_id": info.node_id, "status": str(info.status),
                          "via": info.via})
        # свой узел, если мониторинг онлайн
        if self.client.alive():
            nodes.append({"node_id": self.ctx.NODE, "status": "CONNECTED", "via": "-"})
        return {"nodes": nodes, "count": len(nodes)}

    @rpc
    def peers(self, data: dict):
        """Сконфигурированные пиры + активные WS-подключения узла."""
        table = self.ctx.network.neighbor_table
        connected = [n.model_dump() for n in table.connected()]
        known = [n.model_dump() for n in table.known()]
        configured = []
        try:
            for p in self.ctx.config_manager.list_peers():
                configured.append({"node_id": p.node_id, "uri": p.uri})
        except Exception as e:
            configured = [{"error": str(e)}]
        return {
            "node": self.ctx.NODE,
            "configured_peers": configured,
            "connected": connected,
            "known": known,
            "hint": "Для работы через интернет укажите реальный IP/домен "
                    "в uri пиров и настройте проброс порта",
        }

    # ------------------------------------------------------------------ #
    #  Write-операции (POST) — управление мониторингом со всех узлов mesh
    # ------------------------------------------------------------------ #
    @rpc
    def ack(self, data: dict):
        """Подтвердить алерты. data: {'alert_id': N} — если нет, все."""
        if not isinstance(data, dict):
            data = {}
        res = self.client.alerts_ack(data.get("alert_id"))
        if res is None:
            return {"ok": False, "error": "netpulse offline"}
        return res

    @rpc
    def journal_add(self, data: dict):
        """Добавить запись в журнал работ. data: {'text':..., 'host':..., 'minutes':N}."""
        if not isinstance(data, dict) or not data.get("text"):
            return {"ok": False, "error": "text required"}
        res = self.client.journal_add(
            text=data.get("text"), source=data.get("source", "p2p"),
            host=data.get("host"), user=data.get("user"),
            minutes=data.get("minutes") or 0)
        if res is None:
            return {"ok": False, "error": "netpulse offline"}
        return res

    @rpc
    def journal_del(self, data: dict):
        """Удалить запись журнала. data: {'id': N}."""
        if not isinstance(data, dict) or not data.get("id"):
            return {"ok": False, "error": "id required"}
        res = self.client.journal_delete(data["id"])
        if res is None:
            return {"ok": False, "error": "netpulse offline"}
        return res

    @rpc
    def health_recompute(self, data: dict):
        """Пересчитать health-score парка."""
        res = self.client.health_recompute()
        if res is None:
            return {"ok": False, "error": "netpulse offline"}
        return res

    @rpc
    def set_alias(self, data: dict):
        """Задать алиас LAN-устройства по MAC. data: {'mac':..., 'alias':...}."""
        if not isinstance(data, dict) or not data.get("mac") or not data.get("alias"):
            return {"ok": False, "error": "mac and alias required"}
        res = self.client.lan_alias(data["mac"], data["alias"])
        if res is None:
            return {"ok": False, "error": "netpulse offline"}
        return res

    @rpc
    def runbook(self, data: dict):
        """Выполнить runbook. data: {'name':..., 'params':{}}."""
        if not isinstance(data, dict) or not data.get("name"):
            return {"ok": False, "error": "name required"}
        res = self.client.runbook_exec(data["name"], data.get("params"))
        if res is None:
            return {"ok": False, "error": "netpulse offline"}
        return res

    @rpc
    def watchdog_poll(self, data: dict):
        """Запустить цикл watchdog-опроса (может занять до 4 мин)."""
        res = self.client.watchdog_poll()
        if res is None:
            return {"ok": False, "error": "netpulse offline"}
        return res

    @rpc
    def post(self, data: dict):
        """Универсальный POST-прокси к любому эндпоинту netpulse.
        data: {'endpoint': 'watchdogpoll', 'body': {...}}"""
        if not isinstance(data, dict) or not data.get("endpoint"):
            return {"ok": False, "error": "endpoint required"}
        res = self.client.post(data["endpoint"], data.get("body") or {})
        if res is None:
            return {"ok": False, "error": "netpulse offline"}
        return res

    # ------------------------------------------------------------------ #
    #  Распределённая агрегация (мост между узлами mesh)
    # ------------------------------------------------------------------ #
    @rpc
    async def gather(self, data: dict):
        """РАСПРЕДЕЛЁННАЯ СВОДКА: собрать состояние мониторинга со всех
        mesh-узлов, где запущен сервис netpulse. data: {'section': 'status'|'collect'|'alerts'}.
        Вызов идёт поверх сети (может маршрутизироваться multi-hop)."""
        if not isinstance(data, dict):
            data = {}
        section = data.get("section", "status")

        seen = set()
        targets = []
        # свой узел
        if self.client.alive():
            seen.add(self.ctx.NODE)
            targets.append({"node_id": self.ctx.NODE, "local": True})
        # удалённые узлы с сервисом netpulse
        for info in self.ctx.network.neighbor_table.find_by_service(self.name):
            if info.node_id not in seen:
                seen.add(info.node_id)
                targets.append({"node_id": info.node_id, "local": False})

        results = []

        async def collect_one(t):
            try:
                if t["local"]:
                    if section == "status":
                        payload = self.status({})
                    elif section == "alerts":
                        payload = self.alerts({"limit": 40})
                    else:
                        payload = self.collect({})
                else:
                    payload = await self.ctx.network.call(
                        dst=t["node_id"], service=self.name,
                        method=section, data={} if section != "alerts" else {"limit": 40},
                        timeout=15,
                    )
                ok = not (isinstance(payload, dict) and payload.get("ok") is False)
                results.append({"node_id": t["node_id"], "ok": ok, "data": payload})
            except Exception as e:
                results.append({"node_id": t["node_id"], "ok": False,
                                "error": str(e)})

        import asyncio
        await asyncio.gather(*[collect_one(t) for t in targets])

        return {"section": section, "count": len(results),
                "nodes": results}


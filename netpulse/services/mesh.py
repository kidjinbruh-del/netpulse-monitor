from collections import deque
from threading import Lock
from typing import Dict, Any, Optional

from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger


logger = get_logger("services.mesh")


class MeshService(BaseService):
    name = "mesh"
    dependencies = ["monitor"]

    def __init__(self, config: Config):
        super().__init__(config)
        self._client = None
        self._hub = None
        self._metrics_hist: Dict[str, deque] = {}
        self._metrics_lock = Lock()

    def _on_start(self):
        from netpulse.config.legacy_export import legacy_p2p_client_cfg
        p2p_cfg = legacy_p2p_client_cfg(self.config)
        if not p2p_cfg.get("enabled"):
            logger.info("Mesh disabled in config")
            return
        try:
            if p2p_cfg.get("targets"):
                from netpulse.mesh import MeshHub
                self._hub = MeshHub(p2p_cfg)
                self._hub.start()
            else:
                from netpulse.mesh import MeshClient
                self._client = MeshClient(p2p_cfg)
                self._client.start()
            logger.info("Mesh service started")
        except Exception as e:
            logger.warning(f"Mesh unavailable, degraded mode: {e}")
            self._hub = None
            self._client = None

    def _on_stop(self):
        for m in (self._hub, self._client):
            if m is not None:
                try:
                    m.stop()
                except Exception:
                    pass
        self._hub = None
        self._client = None
        logger.info("Mesh service stopped")

    @property
    def _mesh(self):
        return self._hub or self._client

    def _health_details(self) -> Dict[str, Any]:
        mesh = self._mesh
        if mesh is None:
            return {"enabled": False}
        try:
            return {
                "enabled": True,
                "connected": bool(mesh.connected),
                "target": mesh.target,
                "last_error": mesh.last_error,
            }
        except Exception as e:
            return {"enabled": True, "error": str(e)}

    @property
    def connected(self) -> bool:
        mesh = self._mesh
        return bool(mesh and mesh.connected)

    @property
    def target(self) -> Optional[str]:
        mesh = self._mesh
        return mesh.target if mesh else None

    @property
    def last_error(self) -> Optional[str]:
        mesh = self._mesh
        return mesh.last_error if mesh else None

    @property
    def status_dict(self) -> Dict[str, Any]:
        mesh = self._mesh
        if mesh is None:
            return {"enabled": False}
        try:
            return dict(mesh.status)
        except Exception:
            return {"enabled": True}

    def call(self, service: str, method: str, data: Dict[str, Any],
             dst: str, timeout: int = 10) -> Any:
        mesh = self._mesh
        if mesh is None:
            raise RuntimeError("Mesh not initialized")
        return mesh.call(service, method, data, dst=dst, timeout=timeout)

    def _require_mesh(self):
        from fastapi import HTTPException
        mesh = self._mesh
        if mesh is None:
            raise HTTPException(503, "P2P-мост не создан")
        if not mesh.connected:
            raise HTTPException(
                503, f"нет связи с решёткой: {mesh.last_error or ''}")
        return mesh

    async def nodes_info(self) -> Dict[str, Any]:
        """Узлы решётки: neighbors + services (как legacy p2p_nodes)."""
        import asyncio
        from netpulse.mesh import MeshError
        mesh = self._require_mesh()
        try:
            nt = await asyncio.to_thread(
                mesh.call, "netinfo", "neighbors", {}, mesh.target)
        except MeshError as e:
            from fastapi import HTTPException
            raise HTTPException(502, str(e))
        connected = (nt or {}).get("connected") or []
        known = (nt or {}).get("known") or []
        try:
            services = await asyncio.to_thread(
                mesh.call, "netinfo", "services", {}, mesh.target) or []
        except MeshError:
            services = []
        return {
            "ok": True,
            "node_id": (nt or {}).get("own") or mesh.target,
            "connected": connected,
            "known": known,
            "all_services": services,
            "connected_count": len(connected),
            "known_count": len(known),
            "bridge": self.status_dict,
        }

    async def services_info(self, node: Optional[str] = None) -> Dict[str, Any]:
        """Сервисы узла + хосты каждого сервиса."""
        import asyncio
        from netpulse.mesh import MeshError
        mesh = self._require_mesh()
        node = node or mesh.target
        try:
            services = await asyncio.to_thread(
                mesh.call, "netinfo", "services", {}, node) or []
        except MeshError as e:
            from fastapi import HTTPException
            raise HTTPException(502, str(e))

        async def _find(svc: str):
            try:
                hosts = await asyncio.to_thread(
                    mesh.call, "netinfo", "find_service", {"service": svc}, node) or []
                return svc, [h.get("node_id") for h in hosts if h]
            except MeshError:
                return svc, []

        by_svc = dict(await asyncio.gather(*[_find(s) for s in services]))
        return {"ok": True, "node": node, "services": services,
                "ui_services": [], "hosts": by_svc}

    async def metrics_snapshot(self, web_port: int = 0) -> Dict[str, Any]:
        """Тёплая карта меша: CPU/RAM всех нод + история."""
        import asyncio
        import time
        import psutil
        from netpulse.mesh import MeshError
        mesh = self._require_mesh()
        try:
            nt = await asyncio.to_thread(
                mesh.call, "netinfo", "neighbors", {}, mesh.target) or {}
            own = nt.get("own") or mesh.target
            node_ids = [own] + [
                n.get("node_id") for n in (nt.get("connected") or [])
                if n.get("node_id") and n.get("node_id") != own]
        except MeshError:
            own = mesh.target
            node_ids = [own]

        def _probe(nid: str):
            if nid == own:
                vm = psutil.virtual_memory()
                return (nid, {
                    "node_id": nid, "host": "localhost", "port": web_port,
                    "cpu": psutil.cpu_percent(interval=0.2),
                    "cpu_count": psutil.cpu_count(),
                    "mem_pct": round(vm.percent, 1),
                    "mem_used_gb": round(vm.used / 1073741824, 2),
                    "mem_total_gb": round(vm.total / 1073741824, 2),
                    "uptime_sec": int(time.time() - psutil.boot_time()),
                    "ts": int(time.time()),
                })
            try:
                return (nid, mesh.call("netinfo", "metrics", {}, dst=nid, timeout=6))
            except MeshError as e:
                return (nid, {"error": str(e)})

        rows: Dict[str, Any] = {}
        errors: Dict[str, Any] = {}
        probed = await asyncio.gather(*[asyncio.to_thread(_probe, n) for n in node_ids])
        for nid, row in probed:
            if nid in (None, ""):
                continue
            if (row or {}).get("error"):
                errors[nid] = row["error"]
                continue
            rows[nid] = row

        now = int(time.time())
        with self._metrics_lock:
            for nid, r in rows.items():
                hist = self._metrics_hist.setdefault(nid, deque(maxlen=300))
                hist.append((now, r.get("cpu", 0), r.get("mem_pct", 0)))
            history = {
                nid: [{"t": t, "cpu": c, "mem": m} for t, c, m in deq]
                for nid, deq in self._metrics_hist.items()
            }
        return {"ok": True, "now": now, "nodes": rows,
                "errors": errors, "history": history}

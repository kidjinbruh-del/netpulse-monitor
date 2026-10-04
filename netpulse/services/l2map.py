"""L2Map service wrapper (backend: legacy netpulse.l2map)."""
from typing import Dict, Any
from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger

logger = get_logger("services.l2map")


class L2MapService(BaseService):
    name = "l2map"
    dependencies: list = ["monitor"]

    def __init__(self, config: Config):
        super().__init__(config)
        self._backend = None

    def _on_start(self):
        try:
            monitor = self.ctx.get_service("monitor")
            self._backend = monitor.l2map_svc if monitor else None
            if self._backend is None:
                raise RuntimeError("monitor backend has no l2map")
            logger.info("L2MapService attached to monitor backend")
        except Exception as e:
            logger.warning(f"L2MapService backend unavailable, degraded mode: {e}")
            self._backend = None

    def _on_stop(self):
        self._backend = None

    def _health_details(self) -> Dict[str, Any]:
        return {"backend": "attached" if self._backend else "degraded"}

    def status(self):
        if self._backend is None:
            return {"status": "degraded", "ports": [], "lldp": []}
        try:
            return self._backend.status()
        except Exception:
            return {"status": "degraded", "ports": [], "lldp": []}

    def ports_for(self, mac: str):
        if self._backend is None:
            return []
        return self._backend.ports_for(mac)

    @property
    def last_ports(self):
        if self._backend is None:
            return []
        try:
            return self._backend.last_ports or []
        except Exception:
            return []

    @property
    def last_lldp(self):
        if self._backend is None:
            return []
        try:
            return self._backend.last_lldp or []
        except Exception:
            return []

    def resolve_ptrs(self):
        if self._backend is None:
            return 0
        try:
            return self._backend.resolve_ptrs()
        except Exception:
            return 0

    def scan(self):
        if self._backend is None:
            return {"error": "backend unavailable"}
        return self._backend.scan()

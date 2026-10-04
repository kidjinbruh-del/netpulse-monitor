"""SoftwareInventory service wrapper (backend: legacy netpulse.softwareinv)."""
from typing import Dict, Any
from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger

logger = get_logger("services.softwareinv")


class SoftwareInvService(BaseService):
    name = "softwareinv"
    dependencies: list = ["monitor"]

    def __init__(self, config: Config):
        super().__init__(config)
        self._backend = None

    def _on_start(self):
        try:
            monitor = self.ctx.get_service("monitor")
            self._backend = monitor.softwareinv_svc if monitor else None
            if self._backend is None:
                raise RuntimeError("monitor backend has no softwareinv")
            logger.info("SoftwareInvService attached to monitor backend")
        except Exception as e:
            logger.warning(f"SoftwareInvService backend unavailable, degraded mode: {e}")
            self._backend = None

    def _on_stop(self):
        self._backend = None

    def _health_details(self) -> Dict[str, Any]:
        return {"backend": "attached" if self._backend else "degraded"}

    def search(self, term: str):
        if self._backend is None:
            return []
        return self._backend.search(term)

    def stats(self):
        if self._backend is None:
            return {}
        return self._backend.stats()

    def for_host(self, host_id: int, limit: int = 200):
        if self._backend is None:
            return []
        return self._backend.for_host(host_id, limit)

    def receive_report(self, body: dict):
        from fastapi import HTTPException
        if self._backend is None:
            raise HTTPException(503, "backend unavailable")
        res = self._backend.receive_report(body)
        # Legacy-контракт: (status, payload) при ошибке, dict при успехе.
        if isinstance(res, tuple):
            code, payload = res
            raise HTTPException(code, payload.get("error", "error"))
        return res

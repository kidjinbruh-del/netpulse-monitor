"""Runbooks service wrapper (backend: legacy netpulse.runbooks)."""
from typing import Dict, Any
from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger

logger = get_logger("services.runbooks")


class RunbooksService(BaseService):
    name = "runbooks"
    dependencies: list = ["monitor"]

    def __init__(self, config: Config):
        super().__init__(config)
        self._backend = None

    def _on_start(self):
        try:
            monitor = self.ctx.get_service("monitor")
            self._backend = monitor.runbooks_svc if monitor else None
            if self._backend is None:
                raise RuntimeError("monitor backend has no runbooks")
            logger.info("RunbooksService attached to monitor backend")
        except Exception as e:
            logger.warning(f"RunbooksService backend unavailable, degraded mode: {e}")
            self._backend = None

    def _on_stop(self):
        self._backend = None

    def _health_details(self) -> Dict[str, Any]:
        return {"backend": "attached" if self._backend else "degraded"}

    def list(self):
        if self._backend is None:
            return []
        return self._backend.list()

    def recent_log(self, limit: int = 20):
        if self._backend is None:
            return []
        return self._backend.recent_log(limit)

    def execute(self, name: str, params: dict, actor: str = "admin"):
        if self._backend is None:
            return {"ok": False, "error": "backend unavailable"}
        return self._backend.execute(name, params, actor)

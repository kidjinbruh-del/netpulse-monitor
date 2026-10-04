"""Healing service wrapper (backend: legacy netpulse.healing)."""
from typing import Dict, Any
from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger

logger = get_logger("services.healing")


class HealingService(BaseService):
    name = "healing"
    dependencies: list = ["monitor"]

    def __init__(self, config: Config):
        super().__init__(config)
        self._backend = None

    def _on_start(self):
        try:
            monitor = self.ctx.get_service("monitor")
            self._backend = monitor.healing_svc if monitor else None
            if self._backend is None:
                raise RuntimeError("monitor backend has no healing")
            logger.info("HealingService attached to monitor backend")
        except Exception as e:
            logger.warning(f"HealingService backend unavailable, degraded mode: {e}")
            self._backend = None

    def _on_stop(self):
        self._backend = None

    def _health_details(self) -> Dict[str, Any]:
        return {"backend": "attached" if self._backend else "degraded"}

    def status_list(self):
        if self._backend is None:
            return []
        try:
            return self._backend.status_list()
        except Exception:
            return []

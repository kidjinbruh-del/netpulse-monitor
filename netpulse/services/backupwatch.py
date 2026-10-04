"""BackupWatch service wrapper (backend: legacy netpulse.backupwatch)."""
from typing import Dict, Any
from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger

logger = get_logger("services.backupwatch")


class BackupWatchService(BaseService):
    name = "backupwatch"
    dependencies: list = ["monitor"]

    def __init__(self, config: Config):
        super().__init__(config)
        self._backend = None

    def _on_start(self):
        try:
            monitor = self.ctx.get_service("monitor")
            self._backend = monitor.backupwatch_svc if monitor else None
            if self._backend is None:
                raise RuntimeError("monitor backend has no backupwatch")
            logger.info("BackupWatchService attached to monitor backend")
        except Exception as e:
            logger.warning(f"BackupWatchService backend unavailable, degraded mode: {e}")
            self._backend = None

    def _on_stop(self):
        self._backend = None

    def _health_details(self) -> Dict[str, Any]:
        return {"backend": "attached" if self._backend else "degraded"}

    def status_list(self):
        if self._backend is None:
            return []
        return self._backend.status_list()

    def check_once(self):
        if self._backend is None:
            return {"error": "backend unavailable"}
        return self._backend.check_once()

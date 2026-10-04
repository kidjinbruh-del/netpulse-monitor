"""Backup service wrapper (backend: legacy BackupManager из netpulse.server)."""
from typing import Dict, Any
from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger

logger = get_logger("services.backup")


class BackupService(BaseService):
    name = "backup"
    dependencies: list = []

    def __init__(self, config: Config):
        super().__init__(config)
        self._backend = None

    def _on_start(self):
        try:
            from netpulse.config.legacy_export import to_legacy_dict
            from netpulse.sysutils import BackupManager
            self._backend = BackupManager(to_legacy_dict(self.config))
            if self.config.backup.enabled:
                self._backend.start()
            logger.info("BackupService backend attached")
        except Exception as e:
            logger.warning(f"BackupService backend unavailable, degraded mode: {e}")
            self._backend = None

    def _on_stop(self):
        if self._backend is not None:
            try:
                self._backend.stop()
            except Exception:
                pass
        self._backend = None

    def _health_details(self) -> Dict[str, Any]:
        return {"backend": "attached" if self._backend else "degraded"}

    def run_now(self) -> Dict[str, Any]:
        if self._backend is None:
            return {"ok": False, "error": "backend unavailable"}
        return self._backend.run_backup_now()

    def rotate(self, keep: int = 7) -> None:
        if self._backend is not None:
            self._backend.rotate(keep)

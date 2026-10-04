"""CVE service wrapper (backend: legacy netpulse.cve)."""
from typing import Dict, Any
from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger

logger = get_logger("services.cve")


class CveService(BaseService):
    name = "cve"
    dependencies: list = ["monitor"]

    def __init__(self, config: Config):
        super().__init__(config)
        self._backend = None

    def _on_start(self):
        try:
            monitor = self.ctx.get_service("monitor")
            self._backend = monitor.cve_svc if monitor else None
            if self._backend is None:
                raise RuntimeError("monitor backend has no cve")
            logger.info("CveService attached to monitor backend")
        except Exception as e:
            logger.warning(f"CveService backend unavailable, degraded mode: {e}")
            self._backend = None

    def _on_stop(self):
        self._backend = None

    def _health_details(self) -> Dict[str, Any]:
        return {"backend": "attached" if self._backend else "degraded"}

    def status(self):
        if self._backend is None:
            return {"enabled": False, "note": "backend degraded"}
        try:
            st = self._backend.status()
            st["enabled"] = bool(self.config.cve.enabled)
            return st
        except Exception as e:
            return {"enabled": False, "error": str(e)}

    def check_products(self, products):
        if self._backend is None:
            return []
        return self._backend.check_products(products)

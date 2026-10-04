"""Infra service wrapper (backend: legacy netpulse.infra)."""
from typing import Dict, Any
from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger

logger = get_logger("services.infra")


class InfraService(BaseService):
    name = "infra"
    dependencies: list = ["monitor"]

    def __init__(self, config: Config):
        super().__init__(config)
        self._backend = None

    def _on_start(self):
        try:
            monitor = self.ctx.get_service("monitor")
            self._backend = monitor.infra_svc if monitor else None
            if self._backend is None:
                raise RuntimeError("monitor backend has no infra")
            logger.info("InfraService attached to monitor backend")
        except Exception as e:
            logger.warning(f"InfraService backend unavailable, degraded mode: {e}")
            self._backend = None

    def _on_stop(self):
        self._backend = None

    def _health_details(self) -> Dict[str, Any]:
        return {"backend": "attached" if self._backend else "degraded"}

    def device_list(self):
        if self._backend is None:
            return []
        try:
            return self._backend.device_list()
        except Exception:
            return []

    def gateway_ip(self):
        if self._backend is None:
            return ""
        try:
            return self._backend.gateway_ip()
        except Exception:
            return ""

    def scan_infra(self, community=None):
        if self._backend is None:
            return {"error": "backend unavailable"}
        return self._backend.scan_infra(community)

    def set_dtype(self, host_id: int, dtype: str):
        if self._backend is None:
            return {"ok": False, "error": "backend unavailable"}
        return self._backend.set_dtype(host_id, dtype)

    def snap_diff(self, host_id: int):
        if self._backend is None:
            return {"error": "backend unavailable"}
        return self._backend.snap_diff(host_id)

    def whitelist_match_hidden(self, path: str) -> bool:
        if self._backend is None:
            return False
        try:
            return bool(self._backend.whitelist_match_hidden(path))
        except Exception:
            return False

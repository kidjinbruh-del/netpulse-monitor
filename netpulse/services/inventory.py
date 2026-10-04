from typing import Dict, Any, List, Optional

from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger


logger = get_logger("services.inventory")


class InventoryService(BaseService):
    name = "inventory"
    dependencies = ["monitor"]

    def __init__(self, config: Config):
        super().__init__(config)
        self._svc = None

    def _on_start(self):
        # Legacy Inventory живёт внутри MonitorService (ему нужен service-объект).
        try:
            monitor = self.ctx.get_service("monitor")
            self._svc = monitor.inventory_svc if monitor else None
            if self._svc is None:
                raise RuntimeError("monitor backend has no inventory")
            logger.info("Inventory service attached to monitor backend")
        except Exception as e:
            logger.warning(f"Legacy Inventory unavailable, degraded mode: {e}")
            self._svc = None
    
    def _on_stop(self):
        self._svc = None
    
    def _health_details(self) -> Dict[str, Any]:
        if not self._svc:
            return {"error": "not initialized"}
        try:
            hosts = self._svc.list_hosts()
            return {"hosts_count": len(hosts)}
        except Exception as e:
            return {"error": str(e)}
    
    def list_hosts(self) -> List[Dict[str, Any]]:
        if not self._svc:
            return []
        return self._svc.list_hosts()
    
    def worst_hosts(self, limit: int = 5) -> List[Dict[str, Any]]:
        if not self._svc:
            return []
        return self._svc.worst_hosts(limit)
    
    def host_detail(self, host_id: int) -> Dict[str, Any]:
        if not self._svc:
            return {"error": "not initialized"}
        return self._svc.host_detail(host_id)
    
    def karma_history(self, host_id: int) -> List[Dict[str, Any]]:
        if not self._svc:
            return []
        return self._svc.karma_history(host_id)
    
    def recompute_health(self) -> Dict[str, Any]:
        if not self._svc:
            return {"error": "not initialized"}
        return self._svc.recompute_health()
    
    def recent_events(self, limit: int = 80, host_id: Optional[int] = None) -> List[Dict[str, Any]]:
        if not self._svc:
            return []
        return self._svc.recent_events(limit, host_id)
    
    def upsert_host(self, name: str, ip: str = "", os_info: str = "") -> int:
        if not self._svc:
            return 0
        return self._svc.upsert_host(name, ip, os_info) or 0
    
    def mark_online(self, host_id: int, online: bool = True) -> None:
        if not self._svc:
            return
        self._svc.mark_online(host_id, online)
    
    def resolve_host_id(self, identifier: str) -> Optional[int]:
        if not self._svc:
            return None
        return self._svc.resolve_host_id(identifier)
    
    @property
    def watchdog(self):
        if not self._svc:
            return None
        return self._svc.watchdog
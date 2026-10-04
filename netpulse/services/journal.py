from typing import Dict, Any, List, Optional

from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger


logger = get_logger("services.journal")


class JournalService(BaseService):
    name = "journal"
    dependencies = ["monitor"]

    def __init__(self, config: Config):
        super().__init__(config)
        self._svc = None

    def _on_start(self):
        # Legacy WorkJournal живёт внутри MonitorService.
        try:
            monitor = self.ctx.get_service("monitor")
            self._svc = monitor.journal_svc if monitor else None
            if self._svc is None:
                raise RuntimeError("monitor backend has no journal")
            logger.info("Journal service attached to monitor backend")
        except Exception as e:
            logger.warning(f"Legacy Journal unavailable, degraded mode: {e}")
            self._svc = None
    
    def _on_stop(self):
        self._svc = None
    
    def list_entries(self, limit: int = 150, source: Optional[str] = None, text: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self._svc:
            return []
        return self._svc.list_entries(limit, source, text)
    
    def add(self, text: str, source: str = "manual", host: Optional[str] = None, 
            user_name: Optional[str] = None, minutes: int = 0) -> Dict[str, Any]:
        if not self._svc:
            return {"error": "not initialized"}
        return self._svc.add(text, source, host, user_name, minutes)
    
    def delete(self, entry_id: int) -> Dict[str, Any]:
        if not self._svc:
            return {"error": "not initialized"}
        return self._svc.delete(entry_id)
    
    def month_report(self, days: str = "30") -> Dict[str, Any]:
        if not self._svc:
            return {"error": "not initialized"}
        return self._svc.month_report(days)
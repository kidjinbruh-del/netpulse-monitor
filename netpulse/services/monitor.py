from typing import Dict, Any, List, Optional
import time

from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger


logger = get_logger("services.monitor")


class MonitorService(BaseService):
    name = "monitor"
    dependencies = []
    
    def __init__(self, config: Config):
        super().__init__(config)
        # Ленивая инициализация реального MonitorService
        self._svc = None
    
    def _on_start(self):
        # Ядро мониторинга v3 (бывший svc_legacy). Конфиг — legacy flat-dict.
        try:
            from netpulse.config.legacy_export import to_legacy_dict
            from netpulse.monitor import MonitorService as RealMonitorService
            self._svc = RealMonitorService(to_legacy_dict(self.config))
            self._svc.start()
        except Exception as e:
            logger.warning(f"MonitorService backend unavailable, degraded mode: {e}")
            self._svc = None
    
    def _on_stop(self):
        if self._svc:
            self._svc.stop()
            self._svc = None
    
    def _health_details(self) -> Dict[str, Any]:
        if not self._svc:
            return {"error": "not initialized"}
        try:
            snap = self._svc.get_snapshot()
            return {
                "quality_score": snap.get("quality", {}).get("score"),
                "down_kbps": snap.get("down_kbps"),
                "up_kbps": snap.get("up_kbps"),
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _status_details(self) -> Dict[str, Any]:
        return self._health_details()
    
    # Прокси методы к реальному сервису
    
    def get_snapshot(self) -> Dict[str, Any]:
        if not self._svc:
            return {}
        return self._svc.get_snapshot()
    
    def forecast_speed(self) -> Dict[str, Any]:
        if not self._svc:
            return {}
        return self._svc.forecast_speed()
    
    def quota_usage(self) -> Dict[str, Any]:
        if not self._svc:
            return {}
        return self._svc.quota.usage()
    
    def state_json_cached(self) -> str:
        if not self._svc:
            return "{}"
        return self._svc.state_json_cached()
    
    def get_history(self, seconds: int) -> List[tuple]:
        if not self._svc:
            return []
        return self._svc.get_history(seconds)
    
    def db_history(self, hours: int) -> List[Dict[str, Any]]:
        if not self._svc:
            return []
        return self._svc.db_history(hours)
    
    def interfaces_info(self) -> List[Dict[str, Any]]:
        if not self._svc:
            return []
        return self._svc.interfaces_info()
    
    def connections(self, limit: int = 150, include_listening: bool = False) -> List[Dict[str, Any]]:
        if not self._svc:
            return []
        return self._svc.connections(limit=limit, include_listening=include_listening)
    
    def top_processes_by_conns(self) -> List[Dict[str, Any]]:
        if not self._svc:
            return []
        return self._svc.top_processes_by_conns()
    
    def procmon_top_io(self, limit: int = 40) -> List[Dict[str, Any]]:
        if not self._svc:
            return []
        return self._svc.procmon.top_io(limit)
    
    def procmon_new_connections(self, limit: int = 80) -> List[Dict[str, Any]]:
        if not self._svc:
            return []
        return self._svc.procmon.new_connections(limit)
    
    def procmon_ids_feed(self, limit: int = 80) -> List[Dict[str, Any]]:
        if not self._svc:
            return []
        return self._svc.procmon.ids_feed(limit)
    
    def push_alert(self, alert_type: str, message: str, source: str, rate: int = 60) -> None:
        if not self._svc:
            return
        self._svc.push_alert(alert_type, message, source, rate=rate)
    
    def apply_settings(self, settings: Dict[str, Any]) -> None:
        if not self._svc:
            return
        self._svc.apply_settings(settings)
    
    @property
    def live_alerts(self):
        if not self._svc:
            return []
        return self._svc.live_alerts
    
    @property
    def snapshot(self):
        if not self._svc:
            return {}
        return self._svc.snapshot
    
    def _training_provider(self):
        if not self._svc:
            return []
        return self._svc._training_provider()

    # --- доступ к legacy-ядру и его подсистемам ---

    @property
    def legacy(self):
        """Сырой legacy MonitorService (или None в degraded-режиме)."""
        return self._svc

    def _sub(self, name: str):
        return getattr(self._svc, name, None) if self._svc else None

    @property
    def procmon(self):
        return self._sub("procmon")

    @property
    def mtr(self):
        return self._sub("mtr")

    @property
    def lan(self):
        return self._sub("lan")

    @property
    def capture(self):
        return self._sub("capture")

    @property
    def quota_mgr(self):
        return self._sub("quota")

    @property
    def journal_svc(self):
        return self._sub("journal")

    @property
    def inventory_svc(self):
        return self._sub("inventory")

    @property
    def ai_svc(self):
        return self._sub("ai")

    @property
    def legacy_db(self):
        return getattr(self._svc, "db", None) if self._svc else None

    @property
    def infra_svc(self):
        return self._sub("infra")

    @property
    def softwareinv_svc(self):
        return self._sub("softwareinv")

    @property
    def watchdog_svc(self):
        return self._sub("watchdog")

    @property
    def planner_svc(self):
        return self._sub("planner")

    @property
    def runbooks_svc(self):
        return self._sub("runbooks")

    @property
    def backupwatch_svc(self):
        return self._sub("backupwatch")

    @property
    def healing_svc(self):
        return self._sub("healing")

    @property
    def customchecks_svc(self):
        return self._sub("customchecks")

    @property
    def l2map_svc(self):
        return self._sub("l2map")

    @property
    def cve_svc(self):
        return self._sub("cve")

    @property
    def proxmox_svc(self):
        return self._sub("proxmox")

    # --- методы-аналитики legacy-ядра ---

    def sla_period(self, days: int = 30):
        if not self._svc:
            return {"devices": [], "days": days}
        try:
            return {"devices": self._svc.sla_period(days=days), "days": days}
        except Exception:
            return {"devices": [], "days": days}

    def ram_forecast(self):
        if not self._svc:
            return {}
        try:
            return self._svc.ram_forecast()
        except Exception as e:
            return {"error": str(e)}

    def mtr_history(self, hours: int = 24):
        if not self._svc:
            return {"entries": [], "hours": hours}
        try:
            return {"entries": self._svc.mtr_history(hours=hours), "hours": hours}
        except Exception:
            return {"entries": [], "hours": hours}

    def geo_attack_map(self, limit: int = 150):
        if not self._svc:
            return {"attacks": [], "limit": limit}
        try:
            return self._svc.geo_attack_map(limit=limit)
        except Exception as e:
            return {"attacks": [], "limit": limit, "error": str(e)}

    def weekly_report_text(self):
        if not self._svc:
            return {"error": "backend unavailable"}
        try:
            return self._svc.weekly_report_text_ep()
        except Exception as e:
            return {"error": str(e)}
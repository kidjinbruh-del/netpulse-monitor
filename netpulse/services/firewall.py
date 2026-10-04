"""Firewall service: управление Windows Firewall (бэкенд netpulse.sysutils)."""
from typing import Dict, Any

from netpulse.services.base import BaseService
from netpulse.config import Config
from netpulse.logging import get_logger
from netpulse.sysutils import FirewallCtl


logger = get_logger("services.firewall")


class FirewallService(BaseService):
    name = "firewall"
    dependencies: list = []

    def _health_details(self) -> Dict[str, Any]:
        return {"admin": FirewallCtl.admin_ok(), "prefix": FirewallCtl.RULE_PREFIX}

    def block_ip(self, ip: str, direction: str = "both") -> Dict[str, Any]:
        return FirewallCtl.block_ip(ip, direction)

    def block_app(self, path: str) -> Dict[str, Any]:
        return FirewallCtl.block_app(path)

    def unblock(self, rule_name: str) -> Dict[str, Any]:
        if not rule_name.startswith(FirewallCtl.RULE_PREFIX):
            return {"ok": False, "error": "можно удалять только правила NetPulse"}
        return FirewallCtl.unblock(rule_name)

    def list_rules(self) -> Dict[str, Any]:
        return FirewallCtl.list_rules()

    def admin_ok(self) -> bool:
        return FirewallCtl.admin_ok()

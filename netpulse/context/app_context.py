from __future__ import annotations
from typing import Optional, Dict, Any, List
from contextlib import contextmanager
import logging
import sys
import os

from netpulse.config import Config
from netpulse.context.registry import ServiceRegistry
from netpulse.context.types import BaseService, HealthStatus
from netpulse.logging.setup import setup_logging
from netpulse.db.connection import Database


class AppContext:
    """
    Контекстный менеджер жизненного цикла приложения.
    
    Использование:
        with AppContext(config) as ctx:
            app = create_app(config, ctx)
            uvicorn.run(app, ...)
    
    Или вручную:
        ctx = AppContext(config)
        ctx.startup()
        try:
            # работа приложения
        finally:
            ctx.shutdown()
    """
    
    def __init__(self, config: Config):
        self.config = config
        self.registry = ServiceRegistry()
        self.db: Optional[Database] = None
        self.logger: Optional[logging.Logger] = None
        self._started = False
        self._startup_errors: List[Exception] = []
    
    def __enter__(self) -> "AppContext":
        return self.startup()
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.shutdown()
        return False
    
    def startup(self) -> "AppContext":
        if self._started:
            self.logger.warning("Context already started")
            return self
        
        # 1. Инициализация логирования
        self.logger = setup_logging(self.config.logging)
        self.logger.info("Starting NetPulse", extra={"version": self.config.version})
        
        # 2. База данных
        self.db = Database(self.config.database)
        self.db.connect()
        self.db.migrate()
        self.logger.info("Database connected and migrated")
        
        # 3. Регистрация сервисов
        self._register_services()
        
        # 4. Запуск сервисов в порядке зависимостей
        for service in self.registry.startup_order():
            try:
                service.start(self)
            except Exception as e:
                self.logger.error(f"Failed to start service {service.name}: {e}", exc_info=True)
                self._startup_errors.append(e)
                # Продолжаем запуск остальных сервисов
        
        if self._startup_errors:
            self.logger.warning(f"Some services failed to start: {len(self._startup_errors)} errors")
        
        self._started = True
        self.logger.info("NetPulse startup complete", extra={
            "services_started": len(self.registry),
            "errors": len(self._startup_errors)
        })
        return self
    
    def shutdown(self) -> None:
        if not self._started:
            return
        
        self.logger.info("Shutting down NetPulse...")
        
        # Остановка в обратном порядке зависимостей
        shutdown_errors = []
        for service in self.registry.shutdown_order():
            try:
                service.stop(self)
            except Exception as e:
                self.logger.error(f"Error stopping service {service.name}: {e}", exc_info=True)
                shutdown_errors.append((service.name, e))
        
        # Закрытие БД
        try:
            if self.db:
                self.db.close()
                self.logger.info("Database closed")
        except Exception as e:
            self.logger.error(f"Error closing database: {e}", exc_info=True)
            shutdown_errors.append(("database", e))
        
        self._started = False
        
        if shutdown_errors:
            self.logger.warning(f"Shutdown completed with errors: {shutdown_errors}")
        else:
            self.logger.info("NetPulse shutdown complete")
    
    def _register_services(self) -> None:
        # Импорты внутри метода чтобы избежать циклических зависимостей
        from netpulse.services.monitor import MonitorService
        from netpulse.services.inventory import InventoryService
        from netpulse.services.journal import JournalService
        from netpulse.services.mesh import MeshService
        from netpulse.services.backup import BackupService
        from netpulse.services.firewall import FirewallService
        from netpulse.services.watchdog import WatchdogService
        from netpulse.services.planner import PlannerService
        from netpulse.services.runbooks import RunbooksService
        from netpulse.services.backupwatch import BackupWatchService
        from netpulse.services.softwareinv import SoftwareInvService
        from netpulse.services.wol import WolService
        from netpulse.services.infra import InfraService
        from netpulse.services.healing import HealingService
        from netpulse.services.customchecks import CustomChecksService
        from netpulse.services.sla import SlaService
        from netpulse.services.geo import GeoService
        from netpulse.services.ram_forecast import RamForecastService
        from netpulse.services.l2map import L2MapService
        from netpulse.services.mtr_history import MtrHistoryService
        from netpulse.services.cve import CveService
        from netpulse.services.proxmox import ProxmoxService
        from netpulse.services.ai import AIService
        
        # Core services (no dependencies)
        self.registry.register(MonitorService(self.config))
        self.registry.register(InventoryService(self.config))
        self.registry.register(JournalService(self.config))
        
        # Infrastructure services
        self.registry.register(MeshService(self.config))  # depends on monitor
        self.registry.register(BackupService(self.config))
        self.registry.register(FirewallService(self.config))
        self.registry.register(WatchdogService(self.config))  # depends on monitor, inventory
        self.registry.register(PlannerService(self.config))
        self.registry.register(RunbooksService(self.config))
        self.registry.register(BackupWatchService(self.config))
        self.registry.register(SoftwareInvService(self.config))
        self.registry.register(WolService(self.config))
        self.registry.register(InfraService(self.config))
        self.registry.register(HealingService(self.config))
        self.registry.register(CustomChecksService(self.config))
        self.registry.register(SlaService(self.config))
        self.registry.register(GeoService(self.config))
        self.registry.register(RamForecastService(self.config))
        self.registry.register(L2MapService(self.config))
        self.registry.register(MtrHistoryService(self.config))
        self.registry.register(CveService(self.config))
        self.registry.register(ProxmoxService(self.config))
        self.registry.register(AIService(self.config))
    
    def get_service(self, name: str) -> Optional[BaseService]:
        return self.registry.get(name)
    
    def health_check(self) -> Dict[str, Any]:
        results = {}
        for name, service in self.registry.get_all().items():
            try:
                health = service.health()
                results[name] = {
                    "healthy": health.healthy,
                    "details": health.details
                }
            except Exception as e:
                results[name] = {"healthy": False, "error": str(e)}
        return {
            "overall": all(r.get("healthy", False) for r in results.values()),
            "services": results
        }
    
    @property
    def started(self) -> bool:
        return self._started


# Глобальный контекст для удобства (опционально)
_global_context: Optional[AppContext] = None


def get_global_context() -> Optional[AppContext]:
    return _global_context


def set_global_context(ctx: AppContext) -> None:
    global _global_context
    _global_context = ctx
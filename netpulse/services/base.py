from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, TYPE_CHECKING

from netpulse.config import Config
from netpulse.context.types import HealthStatus
from netpulse.logging import get_logger

if TYPE_CHECKING:
    from netpulse.context import AppContext


logger = get_logger("services.base")


class BaseService(ABC):
    """Базовый класс для всех сервисов NetPulse."""
    
    name: str = "base"
    dependencies: List[str] = []
    
    def __init__(self, config: Config):
        self.config = config
        self._running = False
        self._ctx: Optional[AppContext] = None
        self.logger = get_logger(f"services.{self.name}")
    
    @property
    def ctx(self) -> AppContext:
        if self._ctx is None:
            raise RuntimeError(f"Service {self.name} not attached to context")
        return self._ctx
    
    def attach_context(self, ctx: AppContext) -> None:
        self._ctx = ctx
    
    def start(self, ctx: AppContext) -> None:
        """Запуск сервиса. Вызывается AppContext при старте."""
        self.attach_context(ctx)
        self._running = True
        self.logger.info(f"Service started: {self.name}")
        self._on_start()
    
    def stop(self, ctx: AppContext) -> None:
        """Остановка сервиса. Вызывается AppContext при shutdown."""
        self.logger.info(f"Service stopping: {self.name}")
        self._on_stop()
        self._running = False
        self.logger.info(f"Service stopped: {self.name}")
    
    def health(self) -> HealthStatus:
        """Проверка здоровья сервиса."""
        return HealthStatus(healthy=self._running, details=self._health_details())
    
    def status(self) -> Dict[str, Any]:
        """Статус сервиса для API."""
        return {
            "name": self.name,
            "running": self._running,
            **self._status_details()
        }
    
    # Методы для переопределения в подклассах
    
    def _on_start(self) -> None:
        """Вызывается после attach_context и установки _running=True."""
        pass
    
    def _on_stop(self) -> None:
        """Вызывается перед установкой _running=False."""
        pass
    
    def _health_details(self) -> Dict[str, Any]:
        """Дополнительные детали для health check."""
        return {}
    
    def _status_details(self) -> Dict[str, Any]:
        """Дополнительные детали для status()."""
        return {}
    
    # Удобные методы доступа к другим сервисам через контекст
    
    def get_service(self, name: str):
        return self.ctx.get_service(name)
    
    @property
    def db(self):
        return self.ctx.db
    
    @property
    def monitor(self):
        return self.get_service("monitor")
    
    @property
    def inventory(self):
        return self.get_service("inventory")
    
    @property
    def journal(self):
        return self.get_service("journal")
    
    @property
    def mesh(self):
        return self.get_service("mesh")
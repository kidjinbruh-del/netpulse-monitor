from typing import Protocol, Any, Dict, List, Optional, TYPE_CHECKING
from dataclasses import dataclass, field
from abc import ABC, abstractmethod

if TYPE_CHECKING:
    from .app_context import AppContext
    from netpulse.config import Config


@dataclass
class HealthStatus:
    healthy: bool
    details: Dict[str, Any] = field(default_factory=dict)


class Service(Protocol):
    name: str
    dependencies: List[str]
    
    def start(self, ctx: "AppContext") -> None: ...
    def stop(self, ctx: "AppContext") -> None: ...
    def health(self) -> HealthStatus: ...
    def status(self) -> Dict[str, Any]: ...


class BaseService(ABC):
    name: str = "base"
    dependencies: List[str] = []

    def __init__(self, config: "Config"):
        self.config = config
        self._running = False
        self._ctx: Optional["AppContext"] = None
    
    @property
    def ctx(self) -> "AppContext":
        if self._ctx is None:
            raise RuntimeError(f"Service {self.name} not attached to context")
        return self._ctx
    
    def attach_context(self, ctx: "AppContext") -> None:
        self._ctx = ctx
    
    def start(self, ctx: "AppContext") -> None:
        self.attach_context(ctx)
        self._running = True
        ctx.logger.info(f"Service started: {self.name}")
    
    def stop(self, ctx: "AppContext") -> None:
        self._running = False
        ctx.logger.info(f"Service stopped: {self.name}")
    
    def health(self) -> HealthStatus:
        return HealthStatus(healthy=self._running, details={})
    
    def status(self) -> Dict[str, Any]:
        return {"name": self.name, "running": self._running}


class HasStartStop(Protocol):
    def start(self, ctx: "AppContext") -> None: ...
    def stop(self, ctx: "AppContext") -> None: ...

    @property
    def name(self) -> str: ...
    @property
    def dependencies(self) -> List[str]: ...
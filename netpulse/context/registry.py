from typing import Dict, List, Optional, Set
from collections import deque

from .types import HasStartStop


class ServiceRegistry:
    def __init__(self):
        self._services: Dict[str, HasStartStop] = {}
        self._dependencies: Dict[str, List[str]] = {}
        self._startup_order: List[str] = []
    
    def register(self, service: HasStartStop) -> None:
        if service.name in self._services:
            raise ValueError(f"Service {service.name} already registered")
        self._services[service.name] = service
        self._dependencies[service.name] = list(service.dependencies)
        self._recompute_startup_order()
    
    def unregister(self, name: str) -> None:
        self._services.pop(name, None)
        self._dependencies.pop(name, None)
        self._recompute_startup_order()
    
    def get(self, name: str) -> Optional[HasStartStop]:
        return self._services.get(name)
    
    def get_all(self) -> Dict[str, HasStartStop]:
        return dict(self._services)
    
    def startup_order(self) -> List[HasStartStop]:
        return [self._services[name] for name in self._startup_order]
    
    def shutdown_order(self) -> List[HasStartStop]:
        return [self._services[name] for name in reversed(self._startup_order)]
    
    def _recompute_startup_order(self) -> None:
        # Топологическая сортировка (Kahn's algorithm)
        in_degree: Dict[str, int] = {name: 0 for name in self._services}
        adj: Dict[str, List[str]] = {name: [] for name in self._services}
        
        for name, deps in self._dependencies.items():
            for dep in deps:
                if dep in self._services:
                    adj[dep].append(name)
                    in_degree[name] += 1
        
        queue = deque([name for name, deg in in_degree.items() if deg == 0])
        order = []
        
        while queue:
            name = queue.popleft()
            order.append(name)
            for neighbor in adj[name]:
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)
        
        if len(order) != len(self._services):
            # Циклическая зависимость - fallback к алфавитному порядку
            order = sorted(self._services.keys())
        
        self._startup_order = order
    
    def __contains__(self, name: str) -> bool:
        return name in self._services
    
    def __len__(self) -> int:
        return len(self._services)
    
    def __iter__(self):
        return iter(self._services)
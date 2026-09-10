# GRID/services/manager.py

import logging
from typing import Callable, Any, Dict
from netpulse.p2p_core.internal_modules.base import ModuleGeneric
from netpulse.p2p_core.services.rpc import get_generators

_log = logging.getLogger('ServiceManager')


class ServiceManager:
    def __init__(self):
        self.services: Dict[str, Dict[str, Any]] = {}

    def register_service(self, service: ModuleGeneric):
        if service.name not in self.services:
            self.services[service.name] = {}
        self.services[service.name]['self'] = service

        # авторегистрация @generator методов
        for name, method in get_generators(service).items():
            self._set(service.name, f'__gen__{name}', method)
            _log.debug(f'Auto-registered generator: {service.name}.{name}')

    def get_service(self, service: str) -> Any | None:
        return self.services.get(service, {}).get('self')

    def remove_service(self, service: ModuleGeneric):
        self.services.pop(service.name, None)

    def replace_service(self, service: ModuleGeneric):
        """Полная перерегистрация (hot-reload): старые методы/генераторы
        сервиса затираются, регистрируются только актуальные."""
        self.services[service.name] = {}
        self.register_service(service)

    # ------------------------------------------------------------------ #
    #  RPC methods
    # ------------------------------------------------------------------ #

    def register_method(self, service: ModuleGeneric, method_name: str,
                        method: Callable):
        self._set(service.name, method_name, method)

    def get_method(self, service: str, method: str) -> Callable | None:
        return self._get(service, method)

    # ------------------------------------------------------------------ #
    #  Generators
    # ------------------------------------------------------------------ #

    def get_generator(self, service: str, name: str) -> Callable | None:
        return self._get(service, f'__gen__{name}')

    def list_generators(self, service: str) -> list[str]:
        """Список имён генераторов сервиса."""
        prefix = '__gen__'
        return [
            k[len(prefix):]
            for k in self.services.get(service, {})
            if k.startswith(prefix)
        ]

    # ------------------------------------------------------------------ #
    #  Internal
    # ------------------------------------------------------------------ #

    def _set(self, service_name: str, key: str, value: Any):
        if service_name not in self.services:
            self.services[service_name] = {}
        self.services[service_name][key] = value

    def _get(self, service_name: str, key: str) -> Any | None:
        return self.services.get(service_name, {}).get(key)
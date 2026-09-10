# GRID/services/loader.py

import asyncio
import importlib
import importlib.util
import inspect
import logging
import sys
import types
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from netpulse.p2p_core.internal_modules.base import ModuleGeneric
from netpulse.p2p_core.services.rpc import get_rpc_methods

log = logging.getLogger('ServiceLoader')


class ServiceLoader:
    def __init__(self, services_path: Path, context, services_manager):
        self.path     = Path(services_path)
        self.ctx  = context
        self.manager  = services_manager
        self._observer: Observer | None = None

    # ------------------------------------------------------------------ #
    #  Публичный API
    # ------------------------------------------------------------------ #

    def scan(self):
        """Сканировать все поддиректории services/ и зарегистрировать."""
        for service_dir in self.path.iterdir():
            if service_dir.is_dir() and not service_dir.name.startswith('_'):
                self._load_service_dir(service_dir)

    def watch(self):
        """Запустить watchdog — hot reload при изменении/добавлении файлов."""
        handler = _ReloadHandler(self)
        self._observer = Observer()
        self._observer.schedule(handler, str(self.path), recursive=True)
        self._observer.start()
        log.info(f'Watching {self.path}')

    def stop_watch(self):
        if self._observer:
            self._observer.stop()
            self._observer.join()

    # ------------------------------------------------------------------ #
    #  Загрузка
    # ------------------------------------------------------------------ #

    def _load_service_dir(self, service_dir: Path):
        """Загрузить все .py из директории сервиса."""
        for py_file in service_dir.glob('*.py'):
            if py_file.name.startswith('_'):
                continue
            self._load_file(py_file)

    def _load_file(self, path: Path):
        module_name = f'_services.{path.parent.name}.{path.stem}'
        try:
            module = self._import_fresh(module_name, path)
            self._register_from_module(module)
        except Exception as e:
            log.error(f'Failed to load {path}: {e}')

    def _import_fresh(self, module_name: str, path: Path) -> types.ModuleType:
        """Полный reimport в новый namespace — без кэша."""
        # убираем старый модуль из sys.modules если был
        sys.modules.pop(module_name, None)

        spec   = importlib.util.spec_from_file_location(module_name, path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module

    def _register_from_module(self, module: types.ModuleType):
        """Найти ModuleGeneric подклассы и зарегистрировать их @rpc методы."""
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if not issubclass(cls, ModuleGeneric) or cls is ModuleGeneric:
                continue

            service_name = cls.__name__.lower()

            # отменяем pending RPC если сервис уже был зарегистрирован
            self._cancel_pending(service_name)

            instance     = cls(name=service_name, context=self.ctx)
            rpc_methods  = get_rpc_methods(instance)

            if not rpc_methods:
                log.warning(f'{cls.__name__}: no @rpc methods found')
                continue

            old = self.manager.get_service(service_name)
            if old is not None and old is not instance:
                # D5: полноценный hot-reload — stop() старого, затем
                # регистрация и start() нового (в главном event loop)
                self._schedule_swap(old, instance, rpc_methods)
            else:
                self._activate(instance, rpc_methods)
                log.info(f'Registered {service_name} ({len(rpc_methods)} rpc methods)')

    def _activate(self, instance: ModuleGeneric, rpc_methods: dict):
        """Первичная регистрация сервиса (start() вызовет startup())."""
        self.manager.register_service(instance)
        for method_name, method in rpc_methods.items():
            self.manager.register_method(instance, method_name, method)
        # Регистрация в lifecycle для корректного start()/stop()
        self.ctx.register(instance)

    def _schedule_swap(self, old: ModuleGeneric, new: ModuleGeneric,
                       rpc_methods: dict):
        coro = self._swap_async(old, new, rpc_methods)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop is not None:
            # находимся в главном потоке с живым loop
            loop.create_task(coro)
        else:
            main_loop = getattr(self.ctx, 'loop', None)
            if main_loop is not None and main_loop.is_running():
                asyncio.run_coroutine_threadsafe(coro, main_loop)
                log.info(f'Service {new.name} reload scheduled on main loop')
            else:
                log.warning(
                    f'No running loop — {new.name} replaced without '
                    f'lifecycle swap (old instance kept in ctx._modules)'
                )
                self._activate(new, rpc_methods)

    async def _swap_async(self, old: ModuleGeneric, new: ModuleGeneric,
                          rpc_methods: dict):
        log.info(f'Reloading service {new.name}: stopping old instance...')
        try:
            await old.stop()
        except Exception:
            log.exception(f'{old.name}.stop() failed during reload')

        # заменить старый инстанс в lifecycle-списке
        modules = getattr(self.ctx, '_modules', [])
        for i, m in enumerate(modules):
            if m is old:
                modules[i] = new
                break

        # перерегистрация методов/генераторов (старые затираются)
        self.manager.replace_service(new)
        for method_name, method in rpc_methods.items():
            self.manager.register_method(new, method_name, method)

        try:
            await new.start()
            log.info(f'Service {new.name} reloaded: old stopped, new started')
        except Exception:
            log.exception(f'{new.name}.start() failed after reload')

    def _cancel_pending(self, service_name: str):
        """Отменить все pending futures для данного сервиса."""
        sessions = getattr(self.ctx, 'network', None)
        if not sessions:
            return
        router = getattr(sessions, 'router', None)
        if not router:
            return

        cancelled = router.sessions.cancel_by_service(service_name)
        if cancelled:
            log.warning(f'Cancelled {cancelled} pending RPC(s) for {service_name} (reload)')


class _ReloadHandler(FileSystemEventHandler):
    def __init__(self, loader: ServiceLoader):
        self.loader = loader

    def on_modified(self, event):
        if not event.is_directory and event.src_path.endswith('.py'):
            log.info(f'Reload: {event.src_path}')
            self.loader._load_file(Path(event.src_path))

    def on_created(self, event):
        if not event.is_directory and event.src_path.endswith('.py'):
            log.info(f'New service file: {event.src_path}')
            self.loader._load_file(Path(event.src_path))
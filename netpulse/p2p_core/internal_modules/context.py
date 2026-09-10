import asyncio
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from typing import TYPE_CHECKING

from netpulse.p2p_core.services.manager import ServiceManager
from netpulse.p2p_core.internal_modules.base import ModuleGeneric
from netpulse.p2p_core.internal_modules.certs_index import CertsIndex
from netpulse.p2p_core.internal_modules.config import Config

if TYPE_CHECKING:
    from memory import MemoryModule
    from netpulse.p2p_core.networking.network import NetworkModule
    from spawner import Spawner


class AppContext:
    def __init__(self, config: Config):
        self.config = config
        self.config_manager = None  # заполняется в main.py
        self.NODE = config.node
        self.peers = config.local.peers
        self._modules: list[ModuleGeneric] = []  # порядок важен

        # модули
        self.services = ServiceManager()
        self.certs_index = CertsIndex(own_node_id=config.node)

        self.network: NetworkModule | None = None
        self.memory: MemoryModule | None = None
        self.spawn: Spawner | None = None
        self.updater = None  # Updater — ядерный модуль (src/internal_modules/updater.py)

        # главный event loop (для планирования из потоков watchdog и т.п.)
        self.loop: asyncio.AbstractEventLoop | None = None

    def register(self, module: ModuleGeneric):
        """Регистрация в порядке вызова = порядок startup."""
        self._modules.append(module)
        return module  # чтобы можно было присваивать в одну строку

    async def startup(self):
        self.loop = asyncio.get_running_loop()
        for module in self._modules:
            module.log.info('Starting...')
            await module.start()

    async def shutdown(self):
        for module in reversed(self._modules):  # shutdown в обратном порядке
            module.log.info('Stopping...')
            await module.stop()


@asynccontextmanager
async def app_lifespan(ctx: AppContext) -> AsyncGenerator[AppContext, None]:
    await ctx.startup()
    try:
        yield ctx
    finally:
        await ctx.shutdown()

# GRID/services/test/service.py

from netpulse.p2p_core.internal_modules.base import ModuleGeneric
from netpulse.p2p_core.services.rpc import rpc
import asyncio


class Test(ModuleGeneric):
    def __init__(self, name: str, context):
        super().__init__(name, context)

    @rpc
    def echo(self, data):
        self.log.debug(f'echo: {data}')
        return data

    @rpc
    async def echo_stream(self, data: dict):
        count = data.get('count', 5) if isinstance(data, dict) else 5
        for i in range(count):
            await asyncio.sleep(0.3)
            yield f'chunk {i} of {count}'
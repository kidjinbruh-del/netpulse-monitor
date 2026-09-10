# GRID/services/generator/service.py

import uuid
from netpulse.p2p_core.internal_modules.base import ModuleGeneric
from netpulse.p2p_core.services.rpc import rpc
from netpulse.p2p_core.networking.protocol import MsgPack


class Generator(ModuleGeneric):
    def __init__(self, name, context):
        super().__init__(name, context)

    @rpc
    async def start_stream(self, data: dict):
        target     = data.get('target', 'DebugClient')
        count      = data.get('count', 10)
        multiplier = data.get('multiplier', 1)

        def compute_ranges():
            for i in range(count):
                self.log.debug(f'generating range {i}')
                yield [i * 100, (i + 1) * 100]

        pipe       = self.ctx.memory.create_pipe(buff=5)
        dispatcher = self.ctx.memory.create_dispatcher([pipe])

        template = MsgPack(
            source  = self.ctx.NODE,
            dst     = target,
            service = 'compute_full',
            method  = 'run_range',
            label   = str(uuid.uuid4()),
            data    = {'multiplier': multiplier},
        )

        # PipeTransport через Router (mesh-маршрутизация)
        self.ctx.memory.attach_transport(
            pipe, template, self.ctx.network.router
        )

        dispatcher.start(compute_ranges)
        self.log.info(f'stream started → {target}, label={template.label[:8]}')
        return {'status': 'started', 'label': template.label}
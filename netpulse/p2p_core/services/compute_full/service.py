# GRID/services/compute_full/service.py
# один сервис — и генератор и вычислитель

import uuid
import asyncio
from netpulse.p2p_core.internal_modules.base import ModuleGeneric
from netpulse.p2p_core.services.rpc import rpc, stream_wrapper, stream_consumer, generator
from netpulse.p2p_core.networking.protocol import MsgPack
from netpulse.p2p_core.internal_modules.memory import Pipe


class Compute(ModuleGeneric):
    def __init__(self, name, context):
        super().__init__(name, context)

    @generator
    def compute_ranges(self, data: dict):
        count = data.get('count', 20) if isinstance(data, dict) else 20
        for i in range(count):
            self.log.debug(f'generate #{i}')
            yield [i * 100, (i + 1) * 100]

    @generator
    def compute_squares(self, data: dict):
        count = data.get('count', 20) if isinstance(data, dict) else 20
        for i in range(count):
            yield i * i

    # ------------------------------------------------------------------ #
    #  Генератор — вызывается по RPC, стримит на target ноду
    # ------------------------------------------------------------------ #

    @rpc
    async def start_stream(self, data: dict):
        target     = data.get('target')
        count      = data.get('count', 20)
        multiplier = data.get('multiplier', 1)
        buff       = data.get('buff', 3)

        # B8: цель может быть и client-side соседом — Router умеет в оба направления
        if not self.ctx.network.router.get_transport_to(target):
            return {'error': f'node {target} not found'}

        generated = 0

        def compute_ranges():
            nonlocal generated
            for i in range(count):
                self.log.info(f'GENERATE #{i}')
                generated += 1
                yield [i * 100, (i + 1) * 100]
            self.log.info(f'Generator exhausted — total: {generated}')

        pipe       = self.ctx.memory.create_pipe(buff=buff)
        dispatcher = self.ctx.memory.create_dispatcher([pipe])

        template = MsgPack(
            source  = self.ctx.NODE,
            dst     = target,
            service = 'compute_full',
            method  = 'run_range',
            label   = str(uuid.uuid4()),
            data    = {'multiplier': multiplier, 'buff': buff},
        )

        # PipeTransport через Router (mesh-маршрутизация)
        self.ctx.memory.attach_transport(
            pipe, template, self.ctx.network.router
        )
        dispatcher.start(compute_ranges)

        self.log.info(f'Stream started → {target} count={count} buff={buff}')
        return {'status': 'started', 'label': template.label, 'count': count}

    # ------------------------------------------------------------------ #
    #  Потребитель — принимает стрим от генератора
    # ------------------------------------------------------------------ #

    @stream_wrapper('run_range')
    async def prepare_run(self, data: dict):
        multiplier = data.get('multiplier', 1) if isinstance(data, dict) else 1
        buff       = data.get('buff', 3) if isinstance(data, dict) else 3
        self.log.info(f'Prepare consumer: multiplier={multiplier} buff={buff}')
        return {
            'multiplier': multiplier,
            'buff':       buff,
            'results':    [],
            'index':      0,
        }

    @stream_consumer('run_range')
    async def consume_ranges(self, pipe: Pipe, ctx: dict):
        multiplier = ctx['multiplier']
        buff       = ctx['buff']
        results    = ctx['results']
        label      = ctx.get('label')
        router     = self.ctx.network.router

        # первый запрос порции
        if label:
            await router.send_stream_ack(label, buff)

        # Батчевый ACK: раз на buff потреблённых чанков (кумулятивно),
        # а не на каждый чанк — экономит пакет туда-обратно на чанк
        consumed_since_ack = 0

        async for chunk in pipe:
            ctx['index'] += 1
            index      = ctx['index']

            self.log.info(f'CONSUME #{index} data={chunk}')

            consumed_since_ack += 1
            if label and consumed_since_ack >= buff:
                await router.send_stream_ack(label, buff)
                consumed_since_ack = 0

            await asyncio.sleep(0.1)
            result = chunk[0] * multiplier
            results.append(result)
            self.log.info(f'RESULT  #{index} = {result}')

        self.log.info(f'Consumer done — total={len(results)} results={results}')

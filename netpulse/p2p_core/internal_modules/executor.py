# GRID/executor.py

import asyncio
import inspect
import logging
from typing import Callable, AsyncGenerator

from netpulse.p2p_core.internal_modules.exceptions import MethodNotFound
from netpulse.p2p_core.networking.protocol import MsgPack, PackType
from netpulse.p2p_core.internal_modules.memory import Pipe

log = logging.getLogger('Executor')
class LocalExecutor:
    def __init__(self, services, stream_registry, router_ref=None):
        self.services        = services
        self.stream_registry = stream_registry
        self._router_ref     = router_ref

    async def execute(self, pack: MsgPack) -> MsgPack | AsyncGenerator:
        """Обычный RPC вызов."""
        method: Callable | None = (
            self.services.get_method(pack.service, pack.method)
            if pack.method
            else self.services.get_service(pack.service)
        )
        if not method:
            raise MethodNotFound(pack.service, pack.method)

        log.debug(f'execute {pack.service}.{pack.method}')

        # метод может быть объявлен без параметра data — не подставлять лишний аргумент
        args = (pack.data,) if inspect.signature(method).parameters else ()

        if inspect.isasyncgenfunction(method):
            return method(*args)

        if asyncio.iscoroutinefunction(method):
            result = await method(*args)
        else:
            # D6 контракт: sync @rpc выполняется В ОТДЕЛЬНОМ ПОТОКЕ
            # (asyncio.to_thread), чтобы не блокировать event loop ноды.
            # Правила для авторов методов:
            #   - CPU-тяжёлый код → выносить в ProcessPoolExecutor вручную
            #     (to_thread не обходит GIL);
            #   - блокирующий I/O → разрешён в sync-методе благодаря to_thread;
            #   - async-методы: никаких time.sleep/блокирующих вызовов — только
            #     await-able API.
            result = await asyncio.to_thread(method, *args)

        return MsgPack(
            type=PackType.RESPONSE,
            source=pack.dst,
            dst=pack.source,
            service=pack.service,
            method=pack.method,
            label=pack.label,
            data=result,
        )

    # GRID/executor.py — open_stream передаёт ws и label в ctx

    async def open_stream(self, pack: MsgPack, buff_len: int = 10) -> MsgPack:
        service_obj = self.services.get_service(pack.service)
        if not service_obj:
            raise MethodNotFound(pack.service, pack.method)

        from netpulse.p2p_core.services.rpc import get_stream_handlers
        handlers = get_stream_handlers(service_obj)
        handler = handlers.get(pack.method)

        if not handler or 'consumer' not in handler:
            raise MethodNotFound(pack.service, f'stream:{pack.method}')

        wrapper = handler.get('wrapper')
        consumer = handler['consumer']

        pipe = Pipe(pipe_id=f'inbound_{pack.label[:8]}', buff_len=buff_len)
        inbound = self.stream_registry.register(pack.label, pipe)

        # label для ACK через Router.send_stream_ack()
        asyncio.create_task(
            self._run_consumer(wrapper, consumer, pipe, pack.data, inbound,
                               label=pack.label)
        )

        return MsgPack(
            type=PackType.STREAM_READY,
            source=pack.dst,
            dst=pack.source,
            label=pack.label,
            data='ready',
        )

    async def _run_consumer(self, wrapper, consumer, pipe, data, inbound,
                            label=None):
        ctx = None
        if wrapper:
            ctx = await wrapper(data) if asyncio.iscoroutinefunction(wrapper) else wrapper(data)

        # пробросить label в ctx для ACK через Router
        if isinstance(ctx, dict):
            ctx['label'] = label

        inbound.ready.set()
        try:
            await consumer(pipe, ctx)
        except Exception as e:
            log.error(f'consumer error: {e}')

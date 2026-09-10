# GRID/memory.py

import asyncio
import logging
from typing import Callable, Dict, Optional

from netpulse.p2p_core.internal_modules.base import ModuleGeneric
from netpulse.p2p_core.networking.protocol import MsgPack, PackType

log = logging.getLogger('Memory')
_SENTINEL = object()


class Pipe:
    def __init__(self, pipe_id: str, buff_len: int = 10):
        self.pipe_id = pipe_id
        self.buff_len = buff_len
        self.low_watermark = max(1, buff_len // 3)  # may be truncated
        self._queue = asyncio.Queue(maxsize=buff_len)
        self._closed = False
        self._error: Optional[BaseException] = None  # B4: причина аварийного конца

    async def put(self, item):
        await self._queue.put(item)

    def put_nowait(self, item):
        """Без блокировки: для остановки Dispatcher (pipe может быть полон)."""
        self._queue.put_nowait(item)

    def fail(self, error: BaseException):
        """Аварийное завершение (ошибка producer): консьюмер получит
        исключение вместо «успешного» StopAsyncIteration."""
        self._error = error
        try:
            self._queue.put_nowait(_SENTINEL)
        except asyncio.QueueFull:
            pass  # консьюмер досчитает реальные чанки и упрётся в close()
        self.close()

    @property
    def failed(self) -> bool:
        return self._error is not None

    @property
    def error(self) -> Optional[BaseException]:
        return self._error

    def _raise_if_failed(self):
        if self._error is not None:
            raise self._error

    async def get(self):
        return await self._queue.get()

    def is_full(self) -> bool:
        return self._queue.full()

    def empty(self) -> bool:
        return self._queue.empty()

    @property
    def size(self) -> int:
        return self._queue.qsize()

    def close(self):
        self._closed = True

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self._closed and self._queue.empty():
            self._raise_if_failed()
            raise StopAsyncIteration
        item = await self.get()
        if item is _SENTINEL:
            self._raise_if_failed()
            raise StopAsyncIteration
        return item


class PipeTransport:
    def __init__(self, pipe: Pipe, router, pack_template: MsgPack,
                 timeout: int = 30):
        self.pipe = pipe
        self.router = router
        self.template = pack_template
        self.timeout = timeout
        self.buff_size = pipe.buff_len
        self._task: Optional[asyncio.Task] = None

    def start(self) -> asyncio.Task:
        self._task = asyncio.create_task(self._handshake_and_pump())
        return self._task

    async def _handshake_and_pump(self):
        open_pack = MsgPack(
            type=PackType.STREAM_OPEN,
            source=self.template.source,
            dst=self.template.dst,
            service=self.template.service,
            method=self.template.method,
            label=self.template.label,
            data=self.template.data,
            path=[self.template.source],
            ttl=16,
        )
        future = self.router.sessions.register_single(
            self.template.label,
            self.template.service,
            self.template.method or '',
        )
        # Маршрутизация через mesh вместо прямого transport.send()
        await self.router._forward(open_pack)

        try:
            res = await asyncio.wait_for(future, timeout=self.timeout)
        except asyncio.TimeoutError:
            log.error(f'[pipe_transport] handshake timeout {self.template.label[:8]}')
            return
        if isinstance(res, Exception):
            # resolve() кладёт ERROR-пакет как ЗНАЧЕНИЕ, не как исключение:
            # без этой проверки «handshake ok» печатался даже при отказе,
            # и чанки уходили в никуда (ACK timeout через N секунд)
            log.error(f'[pipe_transport] handshake rejected '
                      f'{self.template.label[:8]}: {res}')
            return

        log.info(f'[pipe_transport] handshake ok, buff_size={self.buff_size}')
        await self._pump()

    async def _pump(self):
        sent_in_batch = 0
        ack_label = f'ack_{self.template.label}'

        # B2: future регистрируется ДО отправки батча — быстрый консьюмер
        # может ответить ACK на первый чанк раньше, чем раньше выполнялась
        # регистрация после батча; resolve() молча ронял такой ACK и _pump
        # замирал на полный timeout.
        ack_future = self.router.sessions.register_single(ack_label, '', '')

        try:
            async for chunk in self.pipe:
                chunk_pack = MsgPack(
                    type=PackType.STREAM_CHUNK,
                    source=self.template.source,
                    dst=self.template.dst,
                    label=self.template.label,
                    data=chunk,
                )
                await self.router._send_pack(chunk_pack)
                sent_in_batch += 1
                log.debug(f'[pipe_transport] sent #{sent_in_batch}/{self.buff_size}')

                if sent_in_batch >= self.buff_size:
                    log.debug(f'[pipe_transport] batch done ({self.buff_size} chunks) — waiting ACK')
                    try:
                        await asyncio.wait_for(ack_future, timeout=self.timeout)
                        log.debug(f'[pipe_transport] ACK received — next batch')
                    except asyncio.TimeoutError:
                        log.error(f'[pipe_transport] ACK timeout — stopping')
                        break
                    sent_in_batch = 0
                    # следующая партия уже может полить — сессия обязана существовать
                    ack_future = self.router.sessions.register_single(ack_label, '', '')
        except Exception as e:
            # B4: producer упал — Pipe.__anext__ бросил исходное исключение;
            # сетевые сбои (pipe не помечен упавшим) пробрасываем как раньше
            if not self.pipe.failed:
                raise
            log.debug(f'[pipe_transport] producer failed mid-stream: {e}')

        # снять незакрытую ack-сессию (EOF / выход после timeout):
        # иначе запись навсегда остаётся в SessionTable
        self.router.sessions.cancel(ack_label)

        if self.pipe.failed:
            # B4: producer упал — сообщить консьюмеру об ошибке,
            # а не «успешным» STREAM_EOF
            error_pack = MsgPack(
                type=PackType.ERROR,
                source=self.template.source,
                dst=self.template.dst,
                label=self.template.label,
                error=f'producer failed: {self.pipe.error}',
            )
            await self.router._send_pack(error_pack)
            log.error(f'[pipe_transport] producer failed — '
                      f'ERROR sent ({self.pipe.error})')
            return

        eof_pack = MsgPack(
            type=PackType.STREAM_EOF,
            source=self.template.source,
            dst=self.template.dst,
            label=self.template.label,
        )
        await self.router._send_pack(eof_pack)
        log.info(f'[pipe_transport] EOF sent')

    def stop(self):
        if self._task:
            self._task.cancel()


class Dispatcher:
    """
    Единая точка входа от генератора → распределяет по pipe'ам.
    Паузит генератор когда все pipe полные.

    Поток-продюсер кладёт элементы в потокобезопасную queue.Queue,
    async-сторона вычитывает её через run_in_executor (одна блокирующая
    вычитка «в полёте», без кросс-поточного планирования на каждый item —
    раньше run_coroutine_threadsafe(...).result() дёргался на каждый элемент).
    """

    def __init__(self, pipes: list[Pipe]):
        self.pipes: Dict[str, Pipe] = {p.pipe_id: p for p in pipes}
        self._running = False
        self._task: Optional[asyncio.Task] = None

    def _least_loaded(self) -> Optional[Pipe]:
        candidates = [p for p in self.pipes.values() if not p.is_full()]
        return min(candidates, key=lambda p: p.size) if candidates else None

    async def run(self, generator: Callable):
        import queue as _thread_queue

        self._running = True
        loop = asyncio.get_running_loop()

        total_buff = sum(p.buff_len for p in self.pipes.values())
        out_q: _thread_queue.Queue = _thread_queue.Queue(maxsize=max(1, total_buff))

        state = {'failed': False, 'error': None}

        def _put_out(item) -> bool:
            """Блокирующий put из потока с проверкой _running каждые 0.25с:
            потребитель умер/остановлен → выходим, не виснем навсегда."""
            while self._running:
                try:
                    out_q.put(item, timeout=0.25)
                    return True
                except _thread_queue.Full:
                    continue
            return False

        def _produce():
            try:
                for item in generator():
                    if not self._running or not _put_out(item):
                        break
            except Exception as e:
                log.error(f'[dispatcher] generator error: '
                          f'{type(e).__name__}: {e}')
                state['failed'] = True
                state['error'] = e
            finally:
                if self._running:
                    _put_out(_SENTINEL)

        producer_future = loop.run_in_executor(None, _produce)
        log.info(f'[dispatcher] started → {len(self.pipes)} pipes')

        while self._running:
            # блокирующая вычитка в executor-потоке с таймаутом: отзывчиво к stop()
            try:
                item = await loop.run_in_executor(
                    None, lambda: out_q.get(timeout=0.25))
            except _thread_queue.Empty:
                continue
            except asyncio.CancelledError:
                raise

            if item is _SENTINEL:
                break

            target = None
            while target is None and self._running:
                target = self._least_loaded()
                if target is None:
                    # все pipe полные — консьюмеры отстают; короткий сон вместо
                    # refill-callback'ов (спам set() на каждый get ниже watermark)
                    log.debug('[dispatcher] all pipes full — paused')
                    await asyncio.sleep(0.005)

            if target:
                await target.put(item)

        # producer-поток завершится сам: _produce проверяет self._running
        # и кладёт sentinel в finally

        # Ошибка producer — пометить pipes как упавшие (B4): консьюмер
        # получает ИСХОДНОЕ исключение, а не «успешный» конец потока
        if state['failed']:
            reason = state['error'] or RuntimeError('generator failed')
            for pipe in self.pipes.values():
                pipe.fail(reason)
            log.error('[dispatcher] aborted due to producer failure')
        else:
            # закрываем все pipes чтобы PipeTransport отправил EOF.
            # put_nowait вместо await put: при остановке pipe может быть полон
            # и некому читать — await висел бы вечно (второй дедлок).
            # close() сам гарантирует StopAsyncIteration после вычитки хвоста.
            for pipe in self.pipes.values():
                try:
                    pipe.put_nowait(_SENTINEL)
                except asyncio.QueueFull:
                    pass
                pipe.close()

        log.info('[dispatcher] finished')

    def start(self, generator: Callable) -> asyncio.Task:
        self._task = asyncio.create_task(self.run(generator))
        return self._task

    def stop(self):
        self._running = False


class MemoryModule(ModuleGeneric):
    def __init__(self, name: str, context):
        super().__init__(name, context)
        self.pipes: Dict[str, Pipe] = {}
        self.dispatchers: list[Dispatcher] = []
        self._transports: list[PipeTransport] = []
        self._counter = 0

    async def start(self):
        self.log.info(f'Started (node={self.name})')

    async def stop(self):
        for t in self._transports:
            t.stop()
        for d in self.dispatchers:
            d.stop()
        for pipe in self.pipes.values():
            pipe.close()
        self.log.info('Stopped')

    # ------------------------------------------------------------------ #
    #  Pipe management
    # ------------------------------------------------------------------ #

    def create_pipe(self, buff: int = 10) -> Pipe:
        self._counter += 1
        pipe_id = f'{self.name}_{self._counter}'
        pipe = Pipe(pipe_id, buff)
        self.pipes[pipe_id] = pipe
        log.debug(f'pipe created: {pipe_id}')
        return pipe

    def create_dispatcher(self, pipes: list[Pipe]) -> Dispatcher:
        d = Dispatcher(pipes)
        self.dispatchers.append(d)
        return d

    # ------------------------------------------------------------------ #
    #  Network pipe: outbound (локальный генератор → remote)
    # ------------------------------------------------------------------ #

    def attach_transport(self, pipe: Pipe, pack_template: MsgPack, router) -> PipeTransport:
        """
        Подключить сетевой транспорт к pipe.
        Чанки из pipe потекут как STREAM_CHUNK на remote через Router.
        """
        pt = PipeTransport(pipe, router, pack_template)
        self._transports.append(pt)
        pt.start()
        return pt


"""
Пример использования — outbound:
python# локальный генератор → 3 remote worker'а через mesh

def compute_ranges():
    for i in range(100):
        yield (i * 100, (i + 1) * 100)

pipes = [ctx.memory.create_pipe(buff=10) for _ in range(3)]
dispatcher = ctx.memory.create_dispatcher(pipes)

# каждый pipe → свой remote worker через Router
for i, pipe in enumerate(pipes):
    template = MsgPack(
        source  = ctx.NODE,
        dst     = f'Worker{i}',
        service = 'compute',
        method  = 'run_range',
        label   = str(uuid.uuid4()),
    )
    ctx.memory.attach_transport(pipe, template, ctx.network.router)

dispatcher.start(compute_ranges)


Пример использования — inbound:
python# получить стрим с remote через mesh

async for chunk in await ctx.network.stream(
    dst='Node1', service='data', method='stream_data', data={}
):
    print(chunk)
"""

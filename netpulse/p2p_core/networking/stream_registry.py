# GRID/stream_registry.py
# Реестр inbound стримов на принимающей стороне

import asyncio
import logging
from typing import Dict, Optional
from netpulse.p2p_core.internal_modules.memory import Pipe, _SENTINEL

log = logging.getLogger('StreamRegistry')


class InboundStream:
    """Запись об ожидаемом входящем стриме."""
    def __init__(self, label: str, pipe: Pipe):
        self.label = label
        self.pipe  = pipe
        self.ready = asyncio.Event()  # выставляется когда consumer запущен


class StreamRegistry:
    def __init__(self):
        self._streams: Dict[str, InboundStream] = {}

    def register(self, label: str, pipe: Pipe) -> InboundStream:
        stream = InboundStream(label, pipe)
        self._streams[label] = stream
        log.debug(f'inbound stream registered: {label[:8]}')
        return stream

    def get(self, label: str) -> Optional[InboundStream]:
        return self._streams.get(label)

    def remove(self, label: str):
        self._streams.pop(label, None)

    async def feed(self, label: str, chunk):
        stream = self._streams.get(label)
        if stream:
            await stream.pipe.put(chunk)
        else:
            log.warning(f'CHUNK for unknown stream {label[:8]} — dropped')

    async def close(self, label: str):
        stream = self._streams.get(label)
        if stream:
            await stream.pipe.put(_SENTINEL)
            stream.pipe.close()
            self.remove(label)
            log.debug(f'inbound stream closed: {label[:8]}')

    def fail(self, label: str, error: Exception):
        """B4: аварийное завершение стрима (ошибка producer на удалённом узле):
        консьюмер получит исключение вместо «успешного» конца потока."""
        stream = self._streams.get(label)
        if stream:
            stream.pipe.fail(error)
            self.remove(label)
            log.warning(f'inbound stream failed: {label[:8]} ({error})')
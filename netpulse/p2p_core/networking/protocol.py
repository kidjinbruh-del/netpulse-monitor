# GRID/protocol.py

import uuid
from enum import Enum
from typing import Any
import msgpack
from pydantic import BaseModel, Field

MAX_FRAME_SIZE = 32 * 1024 * 1024  # 32 МБ — лимит одного WS-кадра


class PackType(str, Enum):
    REQUEST      = "request"
    RESPONSE     = "response"
    FORWARDED    = "forwarded"
    STREAM_OPEN  = "stream_open"   # ← handshake: подготовить consumer
    STREAM_READY = "stream_ready"  # ← подтверждение: готов к приёму
    STREAM_CHUNK = "stream_chunk"
    STREAM_ACK   = "stream_ack"    # ← клиент → сервер: пришли ещё buff штук
    STREAM_EOF   = "stream_eof"
    ERROR        = "error"
    PING         = "ping"
    PONG         = "pong"
    HELLO        = "hello"  # представление при подключении
    HELLO_ACK    = "hello_ack"  # принято + таблица соседей + сервисы
    HELLO_REJECT = "hello_reject"  # отклонено + причина
    GOSSIP       = "gossip"  # периодическая рассылка топологии
    ANNOUNCE     = "announce"  # периодическая рассылка сервисов
    CERT_SYNC    = "cert_sync"  # рассылка digest сертификатов (thumbprint→метаданные)


class MsgPack(BaseModel):
    type:     PackType = PackType.REQUEST
    source:   str
    dst:      str | None = None
    service:  str | None = None
    method:   str | None = None  # имя stream для STREAM_OPEN
    data:     Any = None
    label:    str = Field(default_factory=lambda: str(uuid.uuid4()))
    error:    str | None = None
    path: list[str] = Field(default_factory=list)  # [Node0, Node1, ...]
    ttl: int = 16


# ------------------------------------------------------------------ #
#  Wire-формат: 1 binary WS frame = 1 msgpack dict MsgPack.model_dump()
# ------------------------------------------------------------------ #

_KNOWN_TYPES = {pt.value for pt in PackType}


class UnknownPackTypeError(Exception):
    """Валидный msgpack-кадр с неопознанным type (forward-compat)."""

    def __init__(self, type_value):
        self.type_value = type_value
        super().__init__(f'unknown pack type: {type_value!r}')


def encode_pack(pack: MsgPack) -> bytes:
    """MsgPack → байты binary-кадра. Только python-mode model_dump():
    mode='json' не представит bytes в data."""
    return msgpack.packb(pack.model_dump(), use_bin_type=True)


def decode_pack(raw: bytes) -> MsgPack:
    """Байты binary-кадра → MsgPack.

    raw=False обязателен: строки декодируются в str, bin-тип остаётся bytes.
    Не-dict кадр или битый msgpack → ValueError/упаковочные исключения
    (граница доверия: соединение закрывать).
    Неизвестный type → UnknownPackTypeError (пакет дропать, соединение жить).
    """
    d = msgpack.unpackb(raw, raw=False)
    if not isinstance(d, dict):
        raise ValueError(f'frame is not a msgpack dict: {type(d).__name__}')
    if d.get('type') not in _KNOWN_TYPES:
        raise UnknownPackTypeError(d.get('type'))
    return MsgPack(**d)


def hexdump_head(raw: bytes, n: int = 64) -> str:
    """Hexdump первых n байт кадра — для логов битых фреймов."""
    head = raw[:n]
    return head.hex(' ')
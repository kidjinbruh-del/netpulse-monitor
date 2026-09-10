# services/webpanel/rpc_client.py — синхронный RPC клиент для Streamlit
# Подключается к узлу по WebSocket, использует MsgPack протокол (HELLO → REQUEST/RESPONSE)
# Автоматический reconnect при разрыве соединения

import asyncio
import logging
import os
import threading
import uuid

import websockets

from netpulse.p2p_core.networking.protocol import (
    MAX_FRAME_SIZE,
    MsgPack,
    PackType,
    UnknownPackTypeError,
    decode_pack,
    encode_pack,
)
from netpulse.p2p_core.networking.neighbor_table import PROTOCOL_VERSION

log = logging.getLogger('NodeRPC')

_MAX_RECONNECT_ATTEMPTS = 10
_RECONNECT_BASE_DELAY = 2  # секунды (exponential backoff: base * 2^attempt)


class NodeRPC:
    """
    Синхронная обёртка над WS RPC для streamlit (sync-фреймворк).

    Внутри:
    - фоновый asyncio event loop в отдельном потоке
    - WebSocket клиент с HELLO handshake
    - receive loop для RESPONSE / ERROR / PING
    - threading.Event для блокировки call() до ответа
    - автоматический reconnect при разрыве

    Важно: _connected=False только когда reconnect полностью невозможен.
    Во время reconnect _reconnecting=True, а _connected остаётся True,
    чтобы Streamlit не пересоздавал экземпляр через get_rpc().
    """

    def __init__(self, host='localhost', port=9000,
                 node_id='webpanel', target_node=None):
        self.host = host
        self.port = port
        self.node_id = node_id
        self.target_node = target_node
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._ws = None
        self._pending: dict[str, threading.Event] = {}
        self._results: dict[str, object] = {}
        self._connected = False
        self._reconnecting = False
        self._recv_task: asyncio.Task | None = None
        self._lock = threading.Lock()

        self._start()

    # ------------------------------------------------------------------ #
    #  Lifecycle
    # ------------------------------------------------------------------ #

    def _start(self):
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()
        asyncio.run_coroutine_threadsafe(self._connect(), self._loop).result(timeout=10)

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    async def _connect(self):
        uri = f"ws://{self.host}:{self.port}/ws/{self.node_id}"
        self._ws = await websockets.connect(uri, max_size=MAX_FRAME_SIZE)

        dst = self.target_node or 'Node0'
        hello = MsgPack(
            type=PackType.HELLO,
            source=self.node_id,
            dst=dst,
            data={
                "node_id": self.node_id,
                "host": os.environ.get('P2P_PANEL_HOST', '127.0.0.1'),
                "port": int(os.environ.get('P2P_PANEL_PORT', '8501')),
                "version": PROTOCOL_VERSION,
                "session_id": str(uuid.uuid4()),
                "services": [],
                "role": "client",   # не mesh-узел: в карте сети рисуется серым, BFS не опрашивает
                "enc": "msgpack",
            },
        )
        await self._ws.send(encode_pack(hello))

        raw = await asyncio.wait_for(self._ws.recv(), timeout=5)
        pack = decode_pack(raw)

        if pack.type == PackType.HELLO_ACK:
            self.target_node = pack.source
            self._connected = True
            self._reconnecting = False
            log.info(f"Connected to {self.target_node} ({self.host}:{self.port})")
            self._recv_task = asyncio.create_task(self._receive_loop())
        elif pack.type == PackType.HELLO_REJECT:
            reason = (pack.data or {}).get('reason', 'unknown')
            raise ConnectionError(f"HELLO rejected: {reason}")
        else:
            raise ConnectionError(f"Unexpected handshake response: {pack.type}")

    async def _reconnect(self):
        """Автоматический reconnect с exponential backoff.

        _connected остаётся True на время попыток, чтобы Streamlit
        не пересоздал экземпляр NodeRPC. _reconnecting=True сигнализирует
        о временной недоступности.
        """
        if self._reconnecting:
            return  # уже идёт reconnect — не запускать параллельно
        self._reconnecting = True
        self._connected = False

        # Отменить старый receive loop
        if self._recv_task and not self._recv_task.done():
            self._recv_task.cancel()

        for attempt in range(_MAX_RECONNECT_ATTEMPTS):
            delay = min(_RECONNECT_BASE_DELAY * (2 ** attempt), 60)
            log.info(f"Reconnect attempt {attempt + 1}/{_MAX_RECONNECT_ATTEMPTS} in {delay}s...")
            await asyncio.sleep(delay)

            try:
                if self._ws:
                    await self._ws.close()
            except Exception:
                pass

            try:
                await self._connect()
                log.info(f"Reconnected to {self.target_node}")
                return
            except Exception as e:
                log.warning(f"Reconnect attempt {attempt + 1} failed: {e}")

        self._reconnecting = False
        log.error(f"Reconnect failed after {_MAX_RECONNECT_ATTEMPTS} attempts")

    async def _receive_loop(self):
        try:
            async for raw in self._ws:
                try:
                    pack = decode_pack(raw)
                except UnknownPackTypeError as e:
                    log.warning(f"Unknown pack type {e.type_value!r} — dropped")
                    continue

                if pack.type == PackType.RESPONSE:
                    self._resolve(pack.label, pack.data)

                elif pack.type == PackType.ERROR:
                    self._resolve(pack.label, {"__error__": pack.error})

                elif pack.type == PackType.PING:
                    pong = MsgPack(
                        type=PackType.PONG,
                        source=self.node_id,
                        dst=pack.source,
                        label=pack.label,
                    )
                    await self._ws.send(encode_pack(pong))

        except asyncio.CancelledError:
            pass  # отменён при reconnect — не запускать новый
        except websockets.exceptions.ConnectionClosed:
            log.warning("Connection closed, attempting reconnect...")
            await self._reconnect()
        except Exception as e:
            log.error(f"Receive loop error: {e}")
            await self._reconnect()

    def _resolve(self, label: str, data):
        with self._lock:
            event = self._pending.get(label)
            if event:
                self._results[label] = data
                event.set()

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def call(self, service: str, method: str, data=None,
             dst: str | None = None, timeout: int = 10):
        """
        Синхронный RPC вызов — блокируется до RESPONSE или timeout.

        Args:
            dst: целевой узел. Если None — локальный (target_node).
                 Удалённый узел маршрутизируется через mesh.
        """
        if not self._connected and not self._reconnecting:
            raise ConnectionError("Not connected to node")

        if self._reconnecting:
            raise ConnectionError("Reconnecting to node...")

        target = dst or self.target_node

        label = str(uuid.uuid4())
        event = threading.Event()

        with self._lock:
            self._pending[label] = event

        pack = MsgPack(
            type=PackType.REQUEST,
            source=self.node_id,
            dst=target,
            service=service,
            method=method,
            data=data,
            label=label,
        )

        asyncio.run_coroutine_threadsafe(
            self._ws.send(encode_pack(pack)),
            self._loop,
        ).result(timeout=5)

        if not event.wait(timeout=timeout):
            with self._lock:
                self._pending.pop(label, None)
            raise TimeoutError(f"RPC timeout: {service}.{method}")

        with self._lock:
            self._pending.pop(label, None)
            result = self._results.pop(label, None)

        if isinstance(result, dict) and "__error__" in result:
            raise RuntimeError(result["__error__"])

        return result

    @property
    def connected(self) -> bool:
        return self._connected or self._reconnecting

    @property
    def reconnecting(self) -> bool:
        return self._reconnecting

    @property
    def node(self) -> str:
        return self.target_node or ''

    def close(self):
        self._connected = False
        self._reconnecting = False
        if self._recv_task and not self._recv_task.done():
            self._recv_task.cancel()
        if self._ws:
            try:
                asyncio.run_coroutine_threadsafe(
                    self._ws.close(), self._loop
                ).result(timeout=5)
            except Exception:
                pass
        if self._loop:
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread:
            self._thread.join(timeout=5)

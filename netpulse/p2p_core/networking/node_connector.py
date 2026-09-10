# GRID/node_connector.py

import asyncio
import logging
import time
import uuid

import websockets

from netpulse.p2p_core.internal_modules.base import ModuleGeneric
from netpulse.p2p_core.networking.mesh_auth import SIG_FIELD, sign_hello
from netpulse.p2p_core.networking.neighbor_table import PROTOCOL_VERSION, ROLE_NODE
from netpulse.p2p_core.networking.protocol import (
    MAX_FRAME_SIZE,
    MsgPack,
    PackType,
    UnknownPackTypeError,
    decode_pack,
    encode_pack,
)
from netpulse.p2p_core.networking.transport import WebSocketTransport
log = logging.getLogger('NodeConnector')

KEEPALIVE_INTERVAL = 20   # сек между проверками
KEEPALIVE_TIMEOUT  = 60   # сек без трафика → ping
DEAD_TIMEOUT       = 90   # сек без трафика → unreachable


class NodeConnector(ModuleGeneric):
    """Исходящее подключение к другой ноде."""

    def __init__(self, name: str, context, peer_node_id: str,
                 target_uri: str):
        super().__init__(name, context)
        self.peer_node_id = peer_node_id
        self.target_uri   = target_uri   # ws://host:port/ws/{own_node_id}
        self._ws          = None
        self._connect_task   = None
        self._keepalive_task = None
        self._last_lex_reject = False

    # ------------------------------------------------------------------ #
    #  Lifecycle
    # ------------------------------------------------------------------ #

    async def start(self):
        # Reverse-HELLO: HELLO уходит всегда независимо от lex (проверка
        # перенесена на сервер — NetworkModule.websocket_endpoint отвечает
        # HELLO_REJECT+reverse dial если больший узел получил HELLO от
        # меньшего). Это позволяет инициировать связь с меньшего узла.
        if not self._already_connected():
            self._connect_task = asyncio.create_task(self._connect_loop())
        else:
            self.log.info(
                f'Already connected to {self.peer_node_id} — dial deferred'
            )
        self._keepalive_task = asyncio.create_task(self._keepalive_loop())
        self.log.info(f'Connector started → {self.target_uri}')

    async def stop(self):
        if self._connect_task:
            self._connect_task.cancel()
        if self._keepalive_task:
            self._keepalive_task.cancel()
        if self._ws:
            await self._ws.close()
        self.log.info(f'Connector stopped ({self.peer_node_id})')

    # ------------------------------------------------------------------ #
    #  Правило подключения
    # ------------------------------------------------------------------ #

    def _already_connected(self) -> bool:
        """Узел уже подключен — клиентским или серверным каналом.

        Проверяем и статус таблицы, и фактический транспорт в Router:
        запись может быть CONNECTED при уже отвалившемся сокете и наоборот.
        """
        info = self.ctx.network.neighbor_table.get(self.peer_node_id)
        if info and info.status.value == 'connected':
            return True
        return self.ctx.network.router.get_transport_to(self.peer_node_id) is not None

    # ------------------------------------------------------------------ #
    #  Подключение
    # ------------------------------------------------------------------ #

    async def _connect_loop(self):
        backoff = 5  # R8: экспоненциальный отступ при повторных отказах handshake
        while True:
            if self._already_connected():
                await asyncio.sleep(5)
                continue
            try:
                # max_size обязателен: дефолт websockets (1 МБ) уронит
                # соединение на больших чанках
                async with websockets.connect(
                    self.target_uri, max_size=MAX_FRAME_SIZE
                ) as ws:
                    self._ws = ws
                    # Регистрируем client-side WS в Router для ACK и маршрутизации
                    self.ctx.network.router.register_client_ws(self.peer_node_id, ws)

                    # handshake
                    accepted = await self._handshake(ws)
                    if not accepted:
                        # lex-отказ — сервер сейчас dial'ит обратно, не
                        # наращиваем backoff, ждём inbound
                        if getattr(self, '_last_lex_reject', False):
                            self._last_lex_reject = False
                            backoff = 5
                            self.log.info(
                                f'Lex reject from {self.peer_node_id} — '
                                f'waiting reverse dial 5s'
                            )
                            await asyncio.sleep(5)
                            continue
                        # R8: перманентный отказ не должен долбить каждые ~15с
                        backoff = min(backoff * 2, 300)
                        self.log.warning(
                            f'Handshake rejected by {self.peer_node_id} '
                            f'(retry in {backoff}s)'
                        )
                        await asyncio.sleep(backoff)
                        continue

                    self.log.info(f'Connected to {self.peer_node_id}')
                    backoff = 5

                    async for raw in ws:
                        try:
                            pack = decode_pack(raw)
                        except UnknownPackTypeError as e:
                            self.log.warning(
                                f'Unknown pack type {e.type_value!r} '
                                f'from {self.peer_node_id} — dropped'
                            )
                            continue

                        # D4: touch делается в router.handle() для всех типов
                        # пакетов — дубли здесь давали тройное обновление last_ts

                        transport = WebSocketTransport(ws)
                        # B3: сбой обработки пакета не рвёт соединение
                        try:
                            await self.ctx.network.router.handle(pack, transport)
                        except Exception:
                            self.log.exception(
                                f'handle() failed for {pack.type.value} '
                                f'from {self.peer_node_id} label={pack.label[:8]}'
                            )

            except websockets.exceptions.ConnectionClosedError as e:
                self.log.warning(f'Connection to {self.peer_node_id} closed: {e}')
            except Exception as e:
                if isinstance(e, OSError) and getattr(e, 'winerror', None) == 1225:
                    pass
                else:
                    self.log.error(f'Connector error ({self.peer_node_id}): {e}')
            finally:
                self._ws = None
                self.ctx.network.router.unregister_client_ws(self.peer_node_id)
                # пир может оставаться подключенным входящим каналом
                if not self.ctx.network.router.get_transport_to(self.peer_node_id):
                    self.ctx.network.neighbor_table.mark_unreachable(self.peer_node_id)
                await asyncio.sleep(5)

    async def _handshake(self, ws) -> bool:
        """Отправить HELLO, дождаться HELLO_ACK или HELLO_REJECT."""
        cfg  = self.ctx.config
        session_id = str(uuid.uuid4())
        hello = MsgPack(
            type   = PackType.HELLO,
            source = self.ctx.NODE,
            dst    = self.peer_node_id,
            data   = {
                'node_id':    self.ctx.NODE,
                'host':       self.ctx.network.local_ip(),
                'port':       cfg.network.port,
                'version':    PROTOCOL_VERSION,
                'session_id': session_id,
                'services':   list(self.ctx.services.services.keys()),
                'enc':        'msgpack',  # информационное поле
                SIG_FIELD:    sign_hello(self.ctx.NODE, session_id,
                                         cfg.local.secret) or '',
            }
        )
        await ws.send(encode_pack(hello))

        try:
            raw  = await asyncio.wait_for(ws.recv(), timeout=10)
            pack = decode_pack(raw)

            if pack.type == PackType.HELLO_ACK:
                await self._on_hello_ack(pack)
                return True
            elif pack.type == PackType.HELLO_REJECT:
                data = pack.data or {}
                is_lex = bool(data.get('lex_rule'))
                self._last_lex_reject = is_lex
                self.log.warning(
                    f'HELLO_REJECT from {self.peer_node_id}: '
                    f'{data.get("reason")}'
                    + (' [lex_reverse expected]' if is_lex else '')
                )
                # lex-отказ — не перманентная ошибка: сервер сейчас dial'ит
                # обратно по host/port из нашего HELLO, ждём inbound
                if is_lex:
                    self.log.info(
                        f'Lex reverse: {self.peer_node_id} should dial back '
                        f'(waiting inbound)'
                    )
                return False
        except asyncio.TimeoutError:
            self.log.error(f'Handshake timeout with {self.peer_node_id}')
        return False

    async def _on_hello_ack(self, pack: MsgPack):
        """Обработать HELLO_ACK — смержить соседей и сервисы."""
        data = pack.data or {}

        # зарегистрировать ноду как connected
        self.ctx.network.neighbor_table.register_connected(
            node_id    = self.peer_node_id,
            host       = data.get('host', ''),
            port       = data.get('port', 9000),
            session_id = data.get('session_id', ''),
            version    = data.get('version', PROTOCOL_VERSION),
            services   = data.get('services', []),
            role       = data.get('role', ROLE_NODE),
        )

        # смержить таблицу соседей
        neighbors = data.get('neighbors', [])
        self.ctx.network.neighbor_table.merge_gossip(
            neighbors, from_node=self.peer_node_id
        )
        self.log.info(
            f'HELLO_ACK from {self.peer_node_id}: '
            f'+{len(neighbors)} neighbors'
        )

    # ------------------------------------------------------------------ #
    #  Keepalive
    # ------------------------------------------------------------------ #

    async def _close_local_ws(self):
        """R7: закрыть полумёртвый client-side сокет — иначе connect_loop
        висит в приёме, а reconnect идёт параллельно со старым соединением."""
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass

    async def _keepalive_loop(self):
        while True:
            await asyncio.sleep(KEEPALIVE_INTERVAL)
            info = self.ctx.network.neighbor_table.get(self.peer_node_id)
            if not info:
                continue

            elapsed = time.time() - info.last_ts
            if elapsed <= KEEPALIVE_TIMEOUT:
                continue

            # соединение с пиром может обслуживаться его входящим каналом
            # (WS-сервер), а не этим коннектором — проверяем оба пути через
            # Router, иначе можно похоронить живого соседа
            transport = self.ctx.network.router.get_transport_to(self.peer_node_id)

            if not transport:
                if elapsed > DEAD_TIMEOUT:
                    self.log.warning(
                        f'{self.peer_node_id} no traffic {elapsed:.0f}s → unreachable'
                    )
                    self.ctx.network.neighbor_table.mark_unreachable(self.peer_node_id)
                    await self._close_local_ws()
                continue

            self.log.debug(f'Ping {self.peer_node_id} (no traffic {elapsed:.0f}s)')
            try:
                await transport.send(MsgPack(
                    type   = PackType.PING,
                    source = self.ctx.NODE,
                    dst    = self.peer_node_id,
                ))
            except Exception as e:
                self.log.error(f'Keepalive ping failed: {e}')
                if elapsed > DEAD_TIMEOUT:
                    self.ctx.network.neighbor_table.mark_unreachable(self.peer_node_id)
                    await self._close_local_ws()
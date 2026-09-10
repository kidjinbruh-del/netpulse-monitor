# GRID/network.py

import asyncio
import logging
import time
import uuid

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from typing import Dict

from netpulse.p2p_core.internal_modules.base import ModuleGeneric
from netpulse.p2p_core.internal_modules.local_ip import LocalIPResolver
from netpulse.p2p_core.networking.neighbor_table import PROTOCOL_VERSION, NeighborTable
from netpulse.p2p_core.networking.protocol import (
    MAX_FRAME_SIZE,
    MsgPack,
    PackType,
    UnknownPackTypeError,
    decode_pack,
    hexdump_head,
)
from netpulse.p2p_core.networking.mesh_auth import SIG_FIELD, verify_sig
from netpulse.p2p_core.networking.router import Router
from netpulse.p2p_core.networking.transport import WebSocketTransport

log = logging.getLogger('Network')

WS_CLOSE_PROTOCOL_ERROR = 1002


def _canon(s: str) -> str:
    return s.strip().lower() if isinstance(s, str) else s


class FrameDecodeError(Exception):
    """Кадр нарушает протокол (text вместо binary / битый msgpack) —
    граница доверия: соединение закрывается."""


async def _safe_close(websocket, code: int = 1000, reason: str = ''):
    """Закрыть WS, не падая на двойном close: при остановке узла uvicorn
    мог уже отправить close сам (RuntimeError в ASGI-имплементации)."""
    try:
        await websocket.close(code=code, reason=reason)
    except RuntimeError:
        pass


class Node:
    def __init__(self, node_id: str, ws: WebSocket):
        self.node_id = node_id
        self.ws = ws


class NodesManager:
    def __init__(self):
        self.nodes: Dict[str, Node] = {}

    def register(self, node_id: str, websocket: WebSocket) -> Node:
        node_id = _canon(node_id)
        node = Node(node_id=node_id, ws=websocket)
        self.nodes[node_id] = node
        log.info(f'Node {node_id} registered')
        return node

    def remove(self, node_id: str):
        node_id = _canon(node_id)
        self.nodes.pop(node_id, None)
        log.info(f'Node {node_id} removed')

    def get(self, node_id: str) -> Node | None:
        node_id = _canon(node_id)
        return self.nodes.get(node_id)


class NetworkModule(ModuleGeneric):
    def __init__(self, name: str, context, host: str = "0.0.0.0", port: int = 9000):
        super().__init__(name, context)
        self.host = host
        self.port = port
        self.app = FastAPI()
        self.nodes_manager: NodesManager = NodesManager()
        self.neighbor_table = NeighborTable(own_node_id=context.NODE)
        self.router = Router(self.nodes_manager, context)
        self.ip_resolver = LocalIPResolver(context)
        self._server        = None
        self._task          = None
        self._gossip_task   = None
        self._announce_task = None
        self._register_routes()

    def _register_routes(self):
        app = self.app

        @app.websocket("/ws/{node_id}")
        async def websocket_endpoint(websocket: WebSocket, node_id: str):
            await websocket.accept()
            transport = WebSocketTransport(websocket)

            try:
                # ждём HELLO первым кадром — строго binary msgpack
                first = await asyncio.wait_for(websocket.receive(), timeout=10)

                if first.get('type') == 'websocket.disconnect':
                    raise WebSocketDisconnect(first.get('code', 1000))

                if first.get('bytes') is None:
                    # text-кадр = легаси JSON-клиент; протокол теперь msgpack-only
                    reason = (
                        'upgrade required: this node speaks msgpack '
                        f'binary frames (protocol {PROTOCOL_VERSION})'
                    )
                    self.log.info(
                        f'Handshake rejected from {node_id}: '
                        f'text frame (legacy JSON client)'
                    )
                    await transport.send(MsgPack(
                        type   = PackType.HELLO_REJECT,
                        source = self.ctx.NODE,
                        dst    = node_id,
                        data   = {'reason': reason},
                    ))
                    await _safe_close(websocket, reason='upgrade required')
                    return

                try:
                    pack = decode_pack(first['bytes'])
                except Exception as e:
                    self.log.warning(
                        f'Malformed HELLO frame from {node_id}: {e} '
                        f'head={hexdump_head(first["bytes"])}'
                    )
                    await _safe_close(websocket, code=WS_CLOSE_PROTOCOL_ERROR)
                    return

                if pack.type != PackType.HELLO:
                    reason = f'expected HELLO, got {pack.type.value}'
                    self.log.info(f'Handshake rejected from {node_id}: {reason}')
                    await transport.send(MsgPack(
                        type   = PackType.HELLO_REJECT,
                        source = self.ctx.NODE,
                        dst    = node_id,
                        data   = {'reason': reason},
                    ))
                    await _safe_close(websocket, reason='handshake rejected')
                    return

                if _canon(pack.dst) != _canon(self.ctx.NODE) and _canon(pack.dst) != _canon(self.ctx.config.local.alias):
                    reason = (
                        f'HELLO addressed to {pack.dst!r}, '
                        f'this node is {self.ctx.NODE!r} | {self.ctx.config.local.alias!r}  — check peer URI/node_id'
                    )
                    self.log.info(f'Handshake rejected from {node_id}: {reason}')
                    await transport.send(MsgPack(
                        type=PackType.HELLO_REJECT,
                        source=self.ctx.NODE,
                        dst=node_id,
                        data={
                            'reason':   reason,
                            'expected': self.ctx.NODE,
                            'got':      pack.dst,
                        },
                    ))
                    await _safe_close(websocket, reason='handshake rejected')
                    return

                # проверить подпись HELLO (mesh_auth) если задан local.secret
                hello_data = pack.data or {}
                if not verify_sig(
                    node_id,
                    str(hello_data.get('session_id', '')),
                    self.ctx.config.local.secret,
                    hello_data.get(SIG_FIELD),
                ):
                    self.log.warning(
                        f'Handshake rejected from {node_id}: '
                        f'invalid HELLO signature (local.secret enabled)'
                    )
                    await transport.send(MsgPack(
                        type   = PackType.HELLO_REJECT,
                        source = self.ctx.NODE,
                        dst    = node_id,
                        data   = {'reason': 'invalid HELLO signature'},
                    ))
                    await _safe_close(websocket,
                                      reason='invalid HELLO signature')
                    return

                # проверить дубликат — заменить старое подключение на новое (reconnect)
                old_node = self.nodes_manager.get(node_id)
                if old_node:
                    # Сначала регистрируем новое WS, чтобы избежать окна,
                    # когда узел отсутствует в nodes_manager и ответы теряются
                    self.nodes_manager.register(node_id, websocket)
                    self.log.info(f'Reconnect: replacing connection for {node_id}')
                    try:
                        await old_node.ws.close()
                    except Exception:
                        pass
                else:
                    self.nodes_manager.register(node_id, websocket)
                # сокет сменился (новое подключение/reconnect) — кэш транспортов
                # для этого node_id невалиден
                self.router.invalidate_transport(node_id)

                # принять
                hello_data = pack.data or {}
                session_id = str(uuid.uuid4())

                self.neighbor_table.register_connected(
                    node_id    = node_id,
                    host       = hello_data.get('host', ''),
                    port       = hello_data.get('port', 9000),
                    session_id = session_id,
                    version    = hello_data.get('version', PROTOCOL_VERSION),
                    services   = hello_data.get('services', []),
                    role       = hello_data.get('role', 'node'),
                )

                # ответить HELLO_ACK с текущей таблицей соседей и сервисами
                await transport.send(MsgPack(
                    type   = PackType.HELLO_ACK,
                    source = self.ctx.NODE,
                    dst    = node_id,
                    data   = {
                        'host':       self.local_ip(),
                        'port':       self.port,
                        'version':    PROTOCOL_VERSION,
                        'session_id': session_id,
                        'services':   list(self.ctx.services.services.keys()),
                        'role':       hello_data.get('role', 'node'),
                        'neighbors':  self.neighbor_table.to_gossip(),
                    }
                ))
                self.log.info(
                    f'Node {node_id} accepted (session={session_id[:8]}, '
                    f'enc={hello_data.get("enc", "?")})'
                )

                # Lex reverse: больший узел должен dial'ить меньший, но
                # inbound держим параллельно. Если reverse достучится —
                # закроем inbound и оставим lex-правильный outbound,
                # иначе сохраним inbound. NAT: mesh может быть в серой сети,
                # проверка по факту попыткой (маршрутизация).
                # A2: канонизация lower — регистр alias зло
                if _canon(self.ctx.NODE) > _canon(node_id) and not self.router.has_client_ws(node_id):
                    _peer_host = hello_data.get('host', '')
                    _peer_port = hello_data.get('port', 9000)
                    _inbound_ws = websocket  # для закрытия после успеха reverse

                    async def _lex_reverse_keep_inbound():
                        await asyncio.sleep(0.5)
                        if self.router.has_client_ws(node_id):
                            return
                        if not _peer_host:
                            return
                        try:
                            await self.connect_to(
                                node_id,
                                f'ws://{_peer_host}:{_peer_port}/ws/{self.ctx.NODE}',
                            )
                        except Exception as e:
                            self.log.warning(f'Lex reverse dial to {node_id} failed: {e} — keep inbound')
                            return
                        # ждать появления outbound транспорта
                        for _ in range(10):
                            await asyncio.sleep(0.5)
                            if self.router.has_client_ws(node_id):
                                break
                        if self.router.has_client_ws(node_id):
                            # outbound успешен — сохранить в конфиг даже против lex
                            try:
                                cfg_uri = f'ws://{_peer_host}:{_peer_port}/ws/'
                                # add_peer идемпотентен
                                self.ctx.config_manager.add_peer(node_id, cfg_uri)
                            except Exception:
                                pass
                            # закрыть inbound, оставить lex-правильный outbound
                            cur = self.nodes_manager.get(node_id)
                            if cur and cur.ws is _inbound_ws:
                                try:
                                    await _inbound_ws.close()
                                except Exception:
                                    pass
                                self.log.info(f'Lex reverse ok {node_id} — inbound closed, keep outbound')
                        else:
                            self.log.warning(
                                f'Lex reverse dial to {node_id} no transport after retry '
                                f'(host={_peer_host} NAT?) — keep inbound'
                            )
                            # сохранить inbound как peer для будущих попыток
                            try:
                                cfg_uri = f'ws://{_peer_host}:{_peer_port}/ws/'
                                if not any(_canon(p.node_id) == _canon(node_id) for p in self.ctx.config_manager.list_peers()):
                                    self.ctx.config_manager.add_peer(node_id, cfg_uri)
                            except Exception:
                                pass

                    asyncio.create_task(_lex_reverse_keep_inbound())

                # Запросить CERT_SYNC у нового узла (если у него есть certstool)
                hello_services = hello_data.get('services', [])
                if 'certstool' in hello_services:
                    asyncio.create_task(self._request_cert_sync(node_id))

                # основной цикл — только binary msgpack-кадры
                while True:
                    try:
                        pack = await self._recv_pack(websocket)
                    except UnknownPackTypeError as e:
                        # forward-compat: будущие PackType не рвут соединение
                        self.log.warning(
                            f'Unknown pack type {e.type_value!r} '
                            f'from {node_id} — dropped'
                        )
                        continue
                    except FrameDecodeError as e:
                        self.log.warning(f'{e} — closing connection')
                        await _safe_close(websocket, code=WS_CLOSE_PROTOCOL_ERROR)
                        break

                    # D4: touch делается в router.handle() — здесь был дубль

                    # Дедлок updater.check: внешний REQUEST await executor
                    # блокировал receive loop того же WS, поэтому вложенный
                    # network.call на тот же узел (dst==self через alias/host)
                    # не получал RESPONSE до timeout. REQUEST/FORWARDED
                    # выносим в background task, остальные (RESPONSE/ERROR/PONG)
                    # должны резолвить future синхронно.
                    if pack.type in (PackType.REQUEST, PackType.FORWARDED,
                                     PackType.STREAM_OPEN):
                        async def _bg(_p=pack, _t=transport, _nid=node_id):
                            try:
                                await self.router.handle(_p, _t)
                            except Exception:
                                self.log.exception(
                                    f'handle() failed for {_p.type.value} '
                                    f'from {_nid} label={_p.label[:8]}'
                                )
                        asyncio.create_task(_bg())
                    else:
                        # B3: сбой обработки одного пакета не должен убивать соединение
                        try:
                            await self.router.handle(pack, transport)
                        except Exception:
                            self.log.exception(
                                f'handle() failed for {pack.type.value} '
                                f'from {node_id} label={pack.label[:8]}'
                            )

            except asyncio.TimeoutError:
                self.log.warning(f'HELLO timeout from {node_id}')
            except WebSocketDisconnect:
                pass
            finally:
                # Удалить только если это текущее (активное) WS для node_id,
                # а не уже заменённое при reconnect
                current = self.nodes_manager.get(node_id)
                was_active = bool(current and current.ws is websocket)
                if was_active:
                    self.nodes_manager.remove(node_id)
                    self.neighbor_table.mark_unreachable(node_id)
                    self.router.invalidate_transport(node_id)
                # Очистить pending-ответы для этого WS в любом случае
                self.router.cleanup_ws_pending(websocket)
                if was_active:
                    self.log.info(f'Node {node_id} disconnected')

    async def _recv_pack(self, websocket: WebSocket) -> MsgPack:
        """Принять один пакет: binary-кадр → decode_pack."""
        msg = await websocket.receive()
        # голый receive() возвращает disconnect КАК ЕСТЬ (не исключение):
        # {'type': 'websocket.disconnect', ...} без bytes/text. Раньше это
        # классифицировалось как «text frame 'None'» и ломало остановку узла
        if msg.get('type') == 'websocket.disconnect':
            raise WebSocketDisconnect(msg.get('code', 1000))
        raw = msg.get('bytes')
        if raw is None:
            text = msg.get('text')
            head = text[:80] if isinstance(text, str) else repr(text)
            raise FrameDecodeError(
                f'text frame in msgpack-only mode from peer: {head!r}'
            )
        try:
            return decode_pack(raw)
        except UnknownPackTypeError:
            raise
        except Exception as e:
            raise FrameDecodeError(
                f'malformed frame: {e} head={hexdump_head(raw)}'
            ) from e

    # ------------------------------------------------------------------ #
    #  Lifecycle
    # ------------------------------------------------------------------ #

    async def start(self):
        config = uvicorn.Config(
            self.app, host=self.host, port=self.port, log_level="warning",
            ws_max_size=MAX_FRAME_SIZE,
        )
        self._server = uvicorn.Server(config)
        self._task   = asyncio.create_task(self._server.serve())

        # fail-fast: при занятом порте uvicorn гасит serve-таск изнутри
        # (sys.exit(1) в startup) — без проверки узел продолжал бы жить
        # зомби без сети. Ждём до ~3с фактического бинда.
        for _ in range(30):
            await asyncio.sleep(0.1)
            if self._server.started or self._server.should_exit:
                break
        if not self._server.started:
            raise RuntimeError(
                f'WS-сервер не поднялся на {self.host}:{self.port} '
                f'(порт занят или ошибка bind) — узел завершается')

        self._gossip_task   = asyncio.create_task(self._gossip_loop())
        self._announce_task = asyncio.create_task(self._announce_loop())
        self.log.info(f'Started on {self.host}:{self.port}')

    async def stop(self):
        for task in (self._gossip_task, self._announce_task):
            if task:
                task.cancel()
        if self._server:
            self._server.should_exit = True
        if self._task:
            await self._task
        self.log.info('Stopped')

    # ------------------------------------------------------------------ #
    #  Периодические рассылки
    # ------------------------------------------------------------------ #

    async def _gossip_loop(self):
        """Каждые 30с рассылать таблицу соседей всем connected нодам."""
        while True:
            await asyncio.sleep(30)
            # R3: TTL-чистка ws_pending заодно с циклом
            self.router.sweep_ws_pending()
            # TTL-чистка KNOWN/UNREACHABLE (кто следит: Network — владелец таблицы, единый таймер)
            try:
                self.neighbor_table.sweep()
            except Exception as e:
                self.log.warning(f'Neighbor sweep failed: {e}')
            neighbors = self.neighbor_table.to_gossip()
            if not neighbors:
                continue
            pack = MsgPack(
                type   = PackType.GOSSIP,
                source = self.ctx.NODE,
                data   = {'neighbors': neighbors, 'from': self.ctx.NODE},
            )
            transports = [
                (node.node_id, self.router.get_transport_to(node.node_id))
                for node in self.neighbor_table.connected()
            ]
            await asyncio.gather(
                *[t.send(pack) for _, t in transports if t],
                return_exceptions=True,
            )

    async def _announce_loop(self):
        """Каждые 60с рассылать список сервисов всем connected нодам."""
        while True:
            await asyncio.sleep(60)
            services = list(self.ctx.services.services.keys())
            pack = MsgPack(
                type   = PackType.ANNOUNCE,
                source = self.ctx.NODE,
                data   = {'services': services, 'from': self.ctx.NODE},
            )
            transports = [
                self.router.get_transport_to(node.node_id)
                for node in self.neighbor_table.connected()
            ]
            await asyncio.gather(
                *[t.send(pack) for t in transports if t],
                return_exceptions=True,
            )

    # ------------------------------------------------------------------ #
    #  CERT_SYNC on-connect
    # ------------------------------------------------------------------ #

    async def _request_cert_sync(self, node_id: str):
        """Запросить CERT_SYNC digest у нового узла и отправить свой."""
        await asyncio.sleep(1)  # дать время на завершение handshake

        try:
            # 1. Запросить digest у нового узла
            result = await self.router.call(
                dst=node_id,
                service='certstool',
                method='get_cert_sync_digest',
                data={},
                timeout=10,
            )
            if result and isinstance(result, dict):
                certs = result.get('certs', [])
                sync_version = result.get('sync_version', 0)
                self.ctx.certs_index.merge_cert_sync(node_id, certs, sync_version)
                self.log.info(f'On-connect CERT_SYNC from {node_id}: {len(certs)} certs')
        except Exception as e:
            self.log.warning(f'On-connect CERT_SYNC request to {node_id} failed: {e}')

        # 2. Отправить свой digest новому узлу
        try:
            digest = self.ctx.certs_index.get_digest_for_sync()
            pack = MsgPack(
                type=PackType.CERT_SYNC,
                source=self.ctx.NODE,
                # D3: реальная версия, а не хардкод 0 — иначе merge по
                # строгому '>' игнорировал обновления метаданных
                data={'certs': digest,
                      'sync_version': self.ctx.certs_index.sync_version},
            )
            transport = self.router.get_transport_to(node_id)
            if transport:
                await transport.send(pack)
        except Exception as e:
            self.log.warning(f'On-connect CERT_SYNC send to {node_id} failed: {e}')

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #

    def local_ip(self) -> str:
        """Локальный IP интерфейса mesh (по запросу, с TTL-кэшем)."""
        return self.ip_resolver.get()

    def local_sessions(self) -> list[dict]:
        """Снапшот сессий этого узла с направлением каналов.

        Общий источник для system.sessions() (таблица в панели) и
        netinfo.topology() (карта сети): по каждой записи NeighborTable —
        нормализованный статус, direction
        (inbound / outbound / inbound+outbound / '' — живого WS нет),
        role и возраст активности.
        """
        nt = self.neighbor_table
        nm = self.nodes_manager

        now = time.time()
        rows = []
        for n in nt.all():
            d = n.model_dump()
            # локальный model_dump отдаёт NeighborStatus-enum — нормализуем
            status = d.get('status')
            d['status'] = getattr(status, 'value', status)
            outbound = self.router.has_client_ws(n.node_id)
            inbound = nm.get(n.node_id) is not None
            if outbound and inbound:
                d['direction'] = 'inbound+outbound'
            elif outbound:
                d['direction'] = 'outbound'
            elif inbound:
                d['direction'] = 'inbound'
            else:
                d['direction'] = ''
            last = d.get('last_ts')
            d['age_sec'] = round(now - last) if last else None
            rows.append(d)
        return rows

    async def connect_to(self, node_id: str, target_uri: str):
        """Динамически создать и запустить исходящее подключение к узлу.

        Проверяет, что узел ещё не подключен (по NeighborTable).
        """
        from netpulse.p2p_core.networking.node_connector import NodeConnector

        existing = self.neighbor_table.get(node_id)
        if existing and existing.status.value == 'connected':
            raise ValueError(f'Узел {node_id} уже подключен')

        connector = NodeConnector(
            name=f'Connector_{node_id}',
            context=self.ctx,
            peer_node_id=node_id,
            target_uri=target_uri,
        )
        self.ctx.register(connector)
        await connector.start()
        self.log.info(f'Dynamic connection initiated → {node_id} ({target_uri})')

    async def call(self, dst: str, service: str, method: str, data=None, timeout: int = 10):
        """Single RPC вызов."""
        return await self.router.call(dst, service, method, data, timeout)

    async def stream(self, dst: str, service: str, method: str,
                     data=None, timeout: int = 30):
        """Открыть mesh-стрим и вернуть async iterator по чанкам."""
        return await self.router.stream(dst, service, method, data, timeout)

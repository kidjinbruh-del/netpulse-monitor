# GRID/router.py — полная версия с mesh forwarding и mesh streaming

import asyncio
import inspect
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, AsyncGenerator

from netpulse.p2p_core.internal_modules.exceptions import RPCTimeout
from netpulse.p2p_core.internal_modules.executor import LocalExecutor, MethodNotFound
from netpulse.p2p_core.internal_modules.memory import Pipe, _SENTINEL
from netpulse.p2p_core.networking.protocol import MsgPack, PackType
from netpulse.p2p_core.networking.sessions import SessionTable
from netpulse.p2p_core.networking.stream_registry import StreamRegistry
from netpulse.p2p_core.networking.transport import WebSocketTransport

log = logging.getLogger('Router')

DEFAULT_TTL = 16


def _canon(s: str) -> str:
    return s.strip().lower() if isinstance(s, str) else s

# TTL кэша маршрута стрима (секунды)
_STREAM_ROUTE_TTL = 300


class NodeNotFound(Exception):
    def __init__(self, node): super().__init__(f'node={node}')


class NoRouteToHost(Exception):
    def __init__(self, node): super().__init__(f'no route to {node}')


# ------------------------------------------------------------------ #
#  StreamRoute — кэшированный маршрут стрима
# ------------------------------------------------------------------ #

@dataclass
class StreamRoute:
    label: str
    source: str                            # узел-генератор
    dst: str                               # узел-consumer
    forward_path: list[str] = field(default_factory=list)   # source → dst
    backward_path: list[str] = field(default_factory=list)  # dst → source
    established_at: float = field(default_factory=time.monotonic)

    @property
    def expired(self) -> bool:
        return (time.monotonic() - self.established_at) > _STREAM_ROUTE_TTL


# ------------------------------------------------------------------ #
#  Router
# ------------------------------------------------------------------ #

class Router:
    def __init__(self, nodes_manager, context):
        self.context         = context
        self._nodes_mgr      = nodes_manager
        self.sessions        = SessionTable()
        self.stream_registry = StreamRegistry()
        self.executor = LocalExecutor(context.services, self.stream_registry, router_ref=self)
        # WS transports для ответов удалённым WS-клиентам (webpanel и т.д.)
        # значение: (transport, created_ts) — ts для TTL-чистки (R3)
        self._ws_pending: dict[str, tuple[WebSocketTransport, float]] = {}
        # Client-side WS маппинг: node_id → websocket (от NodeConnector)
        self._client_ws: dict[str, Any] = {}
        # Кэш маршрутов стримов: label → StreamRoute
        self._stream_routes: dict[str, StreamRoute] = {}
        # Кэш транспортов: node_id → WebSocketTransport (создание объекта на
        # каждую отправку было расточительно); инвалидируется при смене сокета
        self._transport_cache: dict[str, WebSocketTransport] = {}

    def register_client_ws(self, node_id: str, ws):
        node_id = _canon(node_id)
        """Зарегистрировать client-side WS (от NodeConnector)."""
        self._client_ws[node_id] = ws
        # сокет сменился — кэшированный транспорт невалиден
        self.invalidate_transport(node_id)

    def unregister_client_ws(self, node_id: str):
        node_id = _canon(node_id)
        """Убрать client-side WS при disconnect."""
        self._client_ws.pop(node_id, None)
        self.invalidate_transport(node_id)

    def invalidate_transport(self, node_id: str):
        node_id = _canon(node_id)
        """Сбросить кэшированный транспорт узла (при reconnect/disconnect)."""
        if self._transport_cache.pop(node_id, None) is not None:
            log.debug(f'Transport cache invalidated for {node_id}')

    def has_client_ws(self, node_id: str) -> bool:
        node_id = _canon(node_id)
        """Есть ли активное исходящее (client-side, от NodeConnector) WS к узлу."""
        return self._client_ws.get(node_id) is not None

    def cleanup_ws_pending(self, websocket):
        """Удалить все _ws_pending записи, ссылающиеся на данный websocket.

        Вызывается при disconnect WS-клиента, чтобы RESPONSE/ERROR
        не пытались отправиться на уже закрытое соединение.
        """
        to_remove = [
            label for label, (transport, _) in self._ws_pending.items()
            if transport.ws is websocket
        ]
        for label in to_remove:
            self._ws_pending.pop(label, None)
        if to_remove:
            log.debug(f'Cleaned {len(to_remove)} pending entries for disconnected WS')

    def sweep_ws_pending(self, max_age: float = 180.0):
        """R3: TTL-чистка _ws_pending — записи по неотвеченным запросам
        WS-клиентов раньше оставались в таблице навсегда (утечка)."""
        now = time.monotonic()
        expired = [
            label for label, (_, created) in self._ws_pending.items()
            if now - created > max_age
        ]
        for label in expired:
            self._ws_pending.pop(label, None)
        if expired:
            log.warning(
                f'Swept {len(expired)} stale ws_pending entries '
                f'(no RESPONSE within {max_age:.0f}s)'
            )

    def get_transport_to(self, node_id: str) -> WebSocketTransport | None:
        node_id = _canon(node_id)
        """Получить транспорт к узлу (server-side или client-side).

        Транспорты кэшируются по node_id — инвалидируются при
        register/unregister_client_ws и при смене server-side сокета
        (websocket_endpoint вызывает invalidate_transport).
        """
        cached = self._transport_cache.get(_canon(node_id))
        if cached is not None:
            return cached

        node = self._nodes_mgr.get(node_id)
        if node:
            transport = WebSocketTransport(node.ws)
            self._transport_cache[node_id] = transport
            return transport

        client_ws = self._client_ws.get(node_id)
        if client_ws:
            transport = WebSocketTransport(client_ws)
            self._transport_cache[node_id] = transport
            return transport

        return None

    # ------------------------------------------------------------------ #
    #  Диспетчеризация пакетов
    # ------------------------------------------------------------------ #

    async def handle(self, pack: MsgPack, transport: WebSocketTransport):
        # обновить last_ts при любом трафике
        if pack.source:
            self.context.network.neighbor_table.touch(pack.source)

        match pack.type:
            case PackType.FORWARDED:
                await self._on_forwarded(pack)

            case PackType.REQUEST:
                if pack.dst and _canon(pack.dst) != _canon(self.context.NODE):
                    await self._on_remote_request(pack, transport)
                else:
                    await self._on_request(pack)

            case PackType.RESPONSE:
                if pack.label in self._ws_pending:
                    ws_transport, _ = self._ws_pending.pop(pack.label)
                    await ws_transport.send(pack)
                elif pack.path:
                    await self._route_back(pack)
                else:
                    self.sessions.resolve(pack.label, pack.data)

            # --- Stream packets: маршрутизация через mesh --- #

            case PackType.STREAM_OPEN:
                if pack.dst and _canon(pack.dst) != _canon(self.context.NODE):
                    await self._forward_stream_open(pack)
                else:
                    response = await self._on_stream_open(pack)
                    # кэшировать маршрут при получении STREAM_OPEN на dst
                    self._cache_stream_route_on_open(pack)
                    await self._send_back(response, pack)

            case PackType.STREAM_READY:
                # кэшировать маршрут на генераторе при получении READY
                self._cache_stream_route_on_ready(pack)
                if pack.path:
                    await self._route_back(pack)
                else:
                    self.sessions.resolve(pack.label, pack.data)

            case PackType.STREAM_CHUNK:
                if pack.dst and _canon(pack.dst) != _canon(self.context.NODE):
                    await self._forward_stream_data(pack)
                else:
                    await self.stream_registry.feed(pack.label, pack.data)

            case PackType.STREAM_ACK:
                if pack.dst and _canon(pack.dst) != _canon(self.context.NODE):
                    await self._route_back(pack)
                else:
                    self.sessions.resolve(f'ack_{pack.label}', 'ack')

            case PackType.STREAM_EOF:
                if pack.dst and _canon(pack.dst) != _canon(self.context.NODE):
                    await self._forward_stream_data(pack)
                else:
                    await self.stream_registry.close(pack.label)
                    self._stream_routes.pop(pack.label, None)

            # --- /Stream --- #

            case PackType.ERROR:
                # B4: ERROR для активного стрима = упал producer на удалённом
                # узле — роняем inbound pipe с исключением у консьюмера
                if self.stream_registry.get(pack.label) is not None:
                    self.stream_registry.fail(
                        pack.label, Exception(pack.error or 'producer failed'))
                elif pack.label in self._ws_pending:
                    ws_transport, _ = self._ws_pending.pop(pack.label)
                    await ws_transport.send(pack)
                elif pack.path:
                    await self._route_back(pack)
                else:
                    self.sessions.resolve(pack.label, Exception(pack.error))

            case PackType.GOSSIP:
                neighbors = (pack.data or {}).get('neighbors', [])
                from_node = (pack.data or {}).get('from', pack.source)
                self.context.network.neighbor_table.merge_gossip(
                    neighbors, from_node
                )

            case PackType.ANNOUNCE:
                services  = (pack.data or {}).get('services', [])
                from_node = (pack.data or {}).get('from', pack.source)
                self.context.network.neighbor_table.update_services(
                    from_node, services
                )

            case PackType.CERT_SYNC:
                certs_digest = (pack.data or {}).get('certs', [])
                from_node = pack.source
                sync_version = (pack.data or {}).get('sync_version', 0)
                self.context.certs_index.merge_cert_sync(
                    from_node, certs_digest, sync_version
                )

            case PackType.PING:
                response = MsgPack(
                    type   = PackType.PONG,
                    source = self.context.NODE,
                    dst    = pack.source,
                    label  = pack.label,
                    path   = list(pack.path),
                )
                await self._send_back(response, pack)

            case PackType.PONG:
                self.sessions.resolve(pack.label, 'pong')

    # ------------------------------------------------------------------ #
    #  Обработка FORWARDED
    # ------------------------------------------------------------------ #

    async def _on_forwarded(self, pack: MsgPack):
        """Промежуточная нода получила пакет в транзите."""
        if pack.ttl <= 0:
            log.warning(
                f'[mesh] TTL=0 reached at {self.context.NODE} '
                f'label={pack.label[:8]} dst={pack.dst} — packet dropped'
            )
            return

        if _canon(self.context.NODE) in [_canon(x) for x in pack.path]:
            log.warning(
                f'[mesh] Loop detected at {self.context.NODE} '
                f'label={pack.label[:8]} path={pack.path} — packet dropped'
            )
            return

        pack.path.append(self.context.NODE)

        if _canon(pack.dst) == _canon(self.context.NODE):
            pack.type = PackType.REQUEST
            await self._on_request(pack)
            return

        await self._forward(pack)

    # ------------------------------------------------------------------ #
    #  Локальная обработка REQUEST
    # ------------------------------------------------------------------ #

    async def _on_remote_request(self, pack: MsgPack, transport: WebSocketTransport):
        """Маршрутизация REQUEST от WS-клиента к удалённому узлу через mesh."""
        self._ws_pending[pack.label] = (transport, time.monotonic())
        try:
            pack.path.append(self.context.NODE)
            pack.ttl -= 1
            await self._forward(pack)
        except NoRouteToHost:
            self._ws_pending.pop(pack.label, None)
            err = MsgPack(
                type=PackType.ERROR,
                source=self.context.NODE,
                dst=pack.source,
                label=pack.label,
                error=f'No route to host: {pack.dst}',
            )
            await transport.send(err)

    async def _on_request(self, pack: MsgPack):
        try:
            result = await self.executor.execute(pack)

            if inspect.isasyncgen(result):
                async for chunk in result:
                    chunk_pack = MsgPack(
                        type    = PackType.STREAM_CHUNK,
                        source  = self.context.NODE,
                        dst     = pack.source,
                        label   = pack.label,
                        data    = chunk,
                        path    = list(pack.path),
                    )
                    await self._send_pack(chunk_pack)
                eof_pack = MsgPack(
                    type   = PackType.STREAM_EOF,
                    source = self.context.NODE,
                    dst    = pack.source,
                    label  = pack.label,
                    path   = list(pack.path),
                )
                await self._send_pack(eof_pack)
            else:
                result.path = list(pack.path)
                await self._send_pack(result)

        except MethodNotFound as e:
            err = MsgPack(
                type   = PackType.ERROR,
                source = self.context.NODE,
                dst    = pack.source,
                label  = pack.label,
                error  = str(e),
                path   = list(pack.path),
            )
            await self._send_pack(err)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            # B3: исключение сервиса не должно ронять WS-соединение —
            # возвращаем caller'у ERROR-пакет
            log.exception(f'request {pack.service}.{pack.method} failed '
                          f'label={pack.label[:8]}')
            err = MsgPack(
                type   = PackType.ERROR,
                source = self.context.NODE,
                dst    = pack.source,
                label  = pack.label,
                error  = f'{type(e).__name__}: {e}',
                path   = list(pack.path),
            )
            await self._send_pack(err)

    async def _on_stream_open(self, pack: MsgPack) -> MsgPack:
        # D7: buff из конфига вместо хардкода
        default_buff = self.context.config.memory.default_buff
        try:
            return await self.executor.open_stream(pack, buff_len=default_buff)
        except MethodNotFound as e:
            return MsgPack(
                type   = PackType.ERROR,
                source = self.context.NODE,
                dst    = pack.source,
                label  = pack.label,
                error  = str(e),
            )
        except asyncio.CancelledError:
            raise
        except Exception as e:
            log.exception(f'stream open {pack.service}.{pack.method} failed '
                          f'label={pack.label[:8]}')
            return MsgPack(
                type   = PackType.ERROR,
                source = self.context.NODE,
                dst    = pack.source,
                label  = pack.label,
                error  = f'{type(e).__name__}: {e}',
            )

    # ------------------------------------------------------------------ #
    #  Stream route caching
    # ------------------------------------------------------------------ #

    def _cache_stream_route_on_open(self, pack: MsgPack):
        """На generator-узле (dst STREAM_OPEN): кэшировать маршрут.

        pack.path = [consumer,…,генератор] →
        forward_path (source→dst)  = генератор→consumer,
        backward_path (dst→source) = consumer→генератор.
        """
        if not pack.path or not pack.source or not pack.dst:
            return
        route = StreamRoute(
            label=pack.label,
            source=_canon(pack.source),
            dst=_canon(pack.dst or self.context.NODE),
            forward_path=[_canon(x) for x in reversed(pack.path)],
            backward_path=[_canon(x) for x in pack.path],
        )
        self._stream_routes[pack.label] = route
        log.debug(
            f'[stream] route cached on consumer: {pack.label[:8]} '
            f'fwd={route.forward_path} bwd={route.backward_path}'
        )

    def _cache_stream_route_on_ready(self, pack: MsgPack):
        """На generator-узле: кэшировать маршрут из STREAM_READY."""
        if not pack.path or not pack.source or not pack.dst:
            return
        route = StreamRoute(
            label=pack.label,
            source=_canon(pack.dst),            # мы — генератор
            dst=_canon(pack.source),            # consumer
            forward_path=[_canon(x) for x in reversed(pack.path)],  # мы → consumer
            backward_path=[_canon(x) for x in pack.path],            # consumer → мы
        )
        self._stream_routes[pack.label] = route
        log.debug(
            f'[stream] route cached on generator: {pack.label[:8]} '
            f'fwd={route.forward_path} bwd={route.backward_path}'
        )

    def get_stream_route(self, label: str) -> StreamRoute | None:
        route = self._stream_routes.get(label)
        if route and route.expired:
            self._stream_routes.pop(label, None)
            return None
        if route:
            # скользящий TTL: пока по стриму идёт трафик, маршрут живёт
            # (иначе длинная передача > _STREAM_ROUTE_TTL теряла маршрут
            # посреди потока и умирала по ACK timeout)
            route.established_at = time.monotonic()
        return route

    # ------------------------------------------------------------------ #
    #  Mesh forwarding — stream packets
    # ------------------------------------------------------------------ #

    async def _forward_stream_open(self, pack: MsgPack):
        """Форвардинг STREAM_OPEN через mesh с кэшированием маршрута."""
        pack.path.append(self.context.NODE)
        pack.ttl -= 1
        # Кэшировать маршрут на промежуточном узле (для обратного ACK)
        if pack.source and pack.dst:
            existing = self._stream_routes.get(pack.label)
            if not existing:
                self._stream_routes[pack.label] = StreamRoute(
                    label=pack.label,
                    source=_canon(pack.source),
                    dst=_canon(pack.dst),
                    forward_path=[_canon(x) for x in pack.path],
                )
        await self._forward(pack)

    async def _forward_stream_data(self, pack: MsgPack):
        """Форвардинг STREAM_CHUNK / STREAM_EOF — предпочтительно через кэш маршрута."""
        route = self.get_stream_route(pack.label)
        if route and self.context.NODE in route.forward_path:
            idx = route.forward_path.index(self.context.NODE)
            if idx + 1 < len(route.forward_path):
                next_hop = route.forward_path[idx + 1]
                transport = self.get_transport_to(next_hop)
                if transport:
                    await transport.send(pack)
                    return
        # Fallback: обычная маршрутизация
        await self._forward(pack)

    # ------------------------------------------------------------------ #
    #  Mesh forwarding — general
    # ------------------------------------------------------------------ #

    async def _forward(self, pack: MsgPack):
        """Переслать пакет к следующему хопу на пути к dst."""
        dst = pack.dst

        # 1. server-side
        node = self._nodes_mgr.get(_canon(dst))
        if node:
            if not pack.path or (_canon(pack.path[-1]) != _canon(self.context.NODE) and _canon(pack.path[-1]) != _canon(self.context.config.local.alias)):
                pack.path.append(self.context.NODE)
            pack.ttl -= 1
            log.debug(
                f'[mesh] direct {self.context.NODE}→{dst} '
                f'label={pack.label[:8]} path={pack.path}'
            )
            transport = WebSocketTransport(node.ws)
            await transport.send(pack)
            return

        # 1b. client-side
        client_ws = self._client_ws.get(_canon(dst))
        if client_ws:
            if not pack.path or (_canon(pack.path[-1]) != _canon(self.context.NODE) and _canon(pack.path[-1]) != _canon(self.context.config.local.alias)):
                pack.path.append(self.context.NODE)
            pack.ttl -= 1
            log.debug(
                f'[mesh] client-direct {self.context.NODE}→{dst} '
                f'label={pack.label[:8]} path={pack.path}'
            )
            transport = WebSocketTransport(client_ws)
            await transport.send(pack)
            return

        # 2. через via из NeighborTable (по node_id)
        neighbor = self.context.network.neighbor_table.get(dst)
        if neighbor and neighbor.via:
            via_transport = self.get_transport_to(neighbor.via)
            if via_transport:
                if not pack.path or (_canon(pack.path[-1]) != _canon(self.context.NODE) and _canon(pack.path[-1]) != _canon(self.context.config.local.alias)):
                    pack.path.append(self.context.NODE)
                pack.ttl -= 1
                if pack.type == PackType.REQUEST:
                    pack.type = PackType.FORWARDED
                log.info(
                    f'[mesh] forward {self.context.NODE}→{neighbor.via}→{dst} '
                    f'label={pack.label[:8]} ttl={pack.ttl} path={pack.path}'
                )
                await via_transport.send(pack)
                return

        # 2b. разрешение по host/IP из NeighborTable
        resolved_id = self._resolve_by_host(dst)
        if resolved_id:
            neighbor = self.context.network.neighbor_table.get(resolved_id)
            if neighbor:
                if neighbor.via:
                    via_transport = self.get_transport_to(neighbor.via)
                    if via_transport:
                        if not pack.path or (_canon(pack.path[-1]) != _canon(self.context.NODE) and _canon(pack.path[-1]) != _canon(self.context.config.local.alias)):
                            pack.path.append(self.context.NODE)
                        pack.ttl -= 1
                        if pack.type == PackType.REQUEST:
                            pack.type = PackType.FORWARDED
                        log.info(
                            f'[mesh] forward {self.context.NODE}→{neighbor.via}→{resolved_id} '
                            f'label={pack.label[:8]} ttl={pack.ttl} path={pack.path}'
                        )
                        await via_transport.send(pack)
                        return
                else:
                    direct = self._nodes_mgr.get(_canon(resolved_id))
                    if direct:
                        if not pack.path or (_canon(pack.path[-1]) != _canon(self.context.NODE) and _canon(pack.path[-1]) != _canon(self.context.config.local.alias)):
                            pack.path.append(self.context.NODE)
                        pack.ttl -= 1
                        log.debug(
                            f'[mesh] direct-host {self.context.NODE}→{resolved_id} '
                            f'label={pack.label[:8]} path={pack.path}'
                        )
                        transport = WebSocketTransport(direct.ws)
                        await transport.send(pack)
                        return
                    client_ws = self._client_ws.get(_canon(resolved_id))
                    if client_ws:
                        if not pack.path or (_canon(pack.path[-1]) != _canon(self.context.NODE) and _canon(pack.path[-1]) != _canon(self.context.config.local.alias)):
                            pack.path.append(self.context.NODE)
                        pack.ttl -= 1
                        log.debug(
                            f'[mesh] client-host {self.context.NODE}→{resolved_id} '
                            f'label={pack.label[:8]} path={pack.path}'
                        )
                        transport = WebSocketTransport(client_ws)
                        await transport.send(pack)
                        return

        # 3. нет маршрута
        log.error(f'[mesh] no route to {dst} label={pack.label[:8]}')
        raise NoRouteToHost(dst)

    def _resolve_by_host(self, host: str) -> str | None:
        """Найти node_id в NeighborTable по host/IP."""
        for info in self.context.network.neighbor_table.all():
            if info.host == host:
                return info.node_id
        return None

    def _resolve_payload(self, pack: MsgPack):
        """Значение для sessions.resolve при локальном завершении обратного
        маршрута: ERROR доставляется как исключение (как в прямой ветке)."""
        if pack.type == PackType.ERROR:
            return Exception(pack.error or 'unknown error')
        return pack.data

    async def _route_back(self, pack: MsgPack):
        """Вернуть пакет по обратному маршруту из pack.path.

        Конвенция: path = [origin,…,текущий узел] — каждый хоп выталкивает
        себя с хвоста и шлёт новому хвосту. Ответные пакеты НЕ разворачиваются.
        """
        if not pack.path:
            self.sessions.resolve(pack.label, self._resolve_payload(pack))
            return

        path = pack.path
        if path and _canon(path[-1]) == _canon(self.context.NODE):
            path = path[:-1]

        if not path:
            self.sessions.resolve(pack.label, self._resolve_payload(pack))
            return

        next_hop = path[-1]
        transport = self.get_transport_to(next_hop)

        if not transport:
            log.error(
                f'[mesh] return path broken: '
                f'{next_hop} not reachable path={pack.path} '
                f'nodes={list(self._nodes_mgr.nodes.keys())} '
                f'client_ws={list(self._client_ws.keys())} '
                f'canon_next={_canon(next_hop)}'
            )
            return

        pack.path = path
        log.debug(
            f'[mesh] route_back →{next_hop} '
            f'label={pack.label[:8]} remaining_path={path}'
        )
        await transport.send(pack)

    async def _send_back(self, response: MsgPack, original: MsgPack):
        """Отправить ответ: по path если был форвардинг, иначе напрямую."""
        if original.path:
            # path уже [origin,…,мы] — каждый хоп выталкивает себя с хвоста
            response.path = list(original.path)
            await self._route_back(response)
        else:
            transport = self.get_transport_to(response.dst)
            if transport:
                await transport.send(response)
            else:
                log.error(f'[mesh] _send_back: no transport to {response.dst}')

    async def _send_pack(self, pack: MsgPack):
        """Отправить пакет — с учётом маршрутизации."""
        if pack.path:
            await self._route_back(pack)
        else:
            transport = self.get_transport_to(pack.dst)
            if transport:
                await transport.send(pack)

    # ------------------------------------------------------------------ #
    #  Stream ACK — отправка через mesh (Вариант A)
    # ------------------------------------------------------------------ #

    async def send_stream_ack(self, label: str, buff: int):
        """Отправить STREAM_ACK генератору — через mesh если нужно."""
        route = self.get_stream_route(label)
        dst = route.source if route else None
        ack_pack = MsgPack(
            type=PackType.STREAM_ACK,
            source=self.context.NODE,
            dst=dst,
            label=label,
            data=buff,
            path=list(route.backward_path) if route else [],
        )
        if route and route.backward_path:
            await self._route_back(ack_pack)
        elif dst:
            transport = self.get_transport_to(dst)
            if transport:
                await transport.send(ack_pack)
            else:
                log.warning(f'[stream] ACK: no route to {dst} label={label[:8]}')
        else:
            # Маршрут чистится на EOF раньше, чем приёмник дочитает хвост
            # буфера Pipe — поздние ACK штатны. Аномалия — только если стрим
            # ещё жив в реестре (маршрут потерян при живой передаче).
            if self.stream_registry.get(label) is None:
                log.debug(f'[stream] late ACK after EOF: label={label[:8]}')
            else:
                log.warning(f'[stream] ACK: no cached route for '
                            f'live stream label={label[:8]}')

    # ------------------------------------------------------------------ #
    #  Исходящие вызовы (публичный API)
    # ------------------------------------------------------------------ #

    async def call(self, dst: str, service: str, method: str,
                   data: Any = None, timeout: int = 10) -> Any:
        pack = MsgPack(
            type    = PackType.REQUEST,
            source  = self.context.NODE,
            dst     = dst,
            service = service,
            method  = method,
            data    = data,
            path    = [self.context.NODE],
            ttl     = DEFAULT_TTL,
        )

        # self-check с учётом alias (иначе локальный вызов через alias
        # уходит в mesh и дедлочит websocket loop внешнего RPC)
        if _canon(dst) == _canon(self.context.NODE) or _canon(dst) == _canon(self.context.config.local.alias):
            response = await self.executor.execute(pack)
            return response.data
        # host/IP -> node_id резолв для локального shortcut
        resolved_self = self._resolve_by_host(dst)
        if resolved_self == self.context.NODE:
            response = await self.executor.execute(pack)
            return response.data

        future = self.sessions.register_single(pack.label, service, method)

        try:
            await self._forward(pack)
        except NoRouteToHost:
            self.sessions.cancel(pack.label)
            raise

        try:
            result = await asyncio.wait_for(future, timeout=timeout)
            if isinstance(result, Exception):
                raise result
            return result
        except asyncio.TimeoutError:
            self.sessions.cancel(pack.label)
            raise RPCTimeout(pack.label, timeout)

    async def stream(self, dst: str, service: str, method: str,
                     data: Any = None, timeout: int = 30) -> AsyncGenerator:
        """Открыть mesh-стрим и вернуть async iterator."""
        label = str(uuid.uuid4())

        open_pack = MsgPack(
            type    = PackType.STREAM_OPEN,
            source  = self.context.NODE,
            dst     = dst,
            service = service,
            method  = method,
            data    = data,
            label   = label,
            path    = [self.context.NODE],
            ttl     = DEFAULT_TTL,
        )

        ready_future = self.sessions.register_single(label, service, method)

        # R2: pipe регистрируется ДО READY — ранние CHUNK больше не дропаются
        # в stream_registry.feed('unknown stream')
        # D7: buff из конфига вместо хардкода
        buff = self.context.config.memory.default_buff
        pipe = Pipe(pipe_id=f'mesh_{label[:8]}', buff_len=buff)
        self.stream_registry.register(label, pipe)

        try:
            await self._forward(open_pack)
        except NoRouteToHost:
            self.sessions.cancel(label)
            self.stream_registry.remove(label)
            raise

        try:
            await asyncio.wait_for(ready_future, timeout=timeout)
        except asyncio.TimeoutError:
            self.sessions.cancel(label)
            self.stream_registry.remove(label)
            self._stream_routes.pop(label, None)
            raise RPCTimeout(label, timeout)

        return _MeshStreamIterator(self, label, pipe)


# ------------------------------------------------------------------ #
#  MeshStreamIterator — async iterator для mesh-стримов
# ------------------------------------------------------------------ #

class _MeshStreamIterator:
    """Итератор по чанкам mesh-стрима с кумулятивным ACK.

    ACK отправляется раз на buff_len потреблённых чанков (окно совпадает
    с размером батча producer'а в PipeTransport._pump) — раньше ACK летел
    на КАЖДЫЙ чанк: по пакету туда-обратно на чанк без пользы.
    """

    def __init__(self, router: Router, label: str, pipe: Pipe):
        self.router = router
        self.label = label
        self._pipe = pipe
        self._since_ack = 0

    def __aiter__(self):
        return self

    async def __anext__(self):
        chunk = await self._pipe.get()
        if chunk is _SENTINEL:
            raise StopAsyncIteration
        self._since_ack += 1
        if self._since_ack >= self._pipe.buff_len:
            await self.router.send_stream_ack(self.label, self._pipe.buff_len)
            self._since_ack = 0
        return chunk

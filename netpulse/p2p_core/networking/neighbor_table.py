# GRID/neighbor_table.py

import logging
import time
from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field

log = logging.getLogger('NeighborTable')

PROTOCOL_VERSION = "2.0"


def _canon(s: str) -> str:
    return s.strip().lower() if isinstance(s, str) else s

# Роль участника: 'node' — полноценный узел mesh, 'client' — служебный
# WS-клиент (webpanel и т.п.): в карту сети попадает серым, BFS его не опрашивает
ROLE_NODE = 'node'
ROLE_CLIENT = 'client'


class NeighborStatus(str, Enum):
    CONNECTED   = "connected"    # прямое WS соединение
    KNOWN       = "known"        # известна из gossip, прямого нет
    UNREACHABLE = "unreachable"  # была connected/known, перестала отвечать


class NeighborInfo(BaseModel):
    node_id:    str
    host:       str
    port:       int
    status:     NeighborStatus  = NeighborStatus.KNOWN
    via:        Optional[str]   = None     # через кого слать если KNOWN
    hops:       int             = 1        # дистанция: 1=прямо, >1 через via
    last_ts:    float           = Field(default_factory=time.time)
    session_id: Optional[str]   = None
    version:    str             = PROTOCOL_VERSION
    services:   List[str]       = []       # сервисы на этой ноде
    role:       str             = ROLE_NODE

    # UNUSED: свойство uri не используется в проекте.
    # При необходимости: ws://{host}:{port}/ws/{node_id}
    # @property
    # def uri(self) -> str:
    #     return f"ws://{self.host}:{self.port}/ws/{self.node_id}"


class NeighborTable:
    def __init__(self, own_node_id: str):
        self.own_node_id = _canon(own_node_id)
        self._table: Dict[str, NeighborInfo] = {}

    # ------------------------------------------------------------------ #
    #  Регистрация
    # ------------------------------------------------------------------ #

    def register_connected(self, node_id: str, host: str, port: int,
                           session_id: str, version: str = PROTOCOL_VERSION,
                           services: List[str] = None,
                           role: str = ROLE_NODE) -> NeighborInfo:
        node_id = _canon(node_id)
        via = None
        info = NeighborInfo(
            node_id    = node_id,
            host       = host,
            port       = port,
            status     = NeighborStatus.CONNECTED,
            via        = via,        # прямое — via не нужен
            hops       = 1,
            last_ts    = time.time(),
            session_id = session_id,
            version    = version,
            services   = services or [],
            role       = role,
        )
        self._table[node_id] = info
        log.info(f'Registered connected: {node_id} ({host}:{port})')
        return info

    def register_known(self, node_id: str, host: str, port: int,
                       via: str, version: str = PROTOCOL_VERSION,
                       services: List[str] = None,
                       role: str = ROLE_NODE) -> NeighborInfo:
        node_id = _canon(node_id)
        via = _canon(via) if via else via
        # не перезаписывать connected более слабым known
        existing = self._table.get(node_id)
        if existing and existing.status == NeighborStatus.CONNECTED:
            return existing

        info = NeighborInfo(
            node_id  = node_id,
            host     = host,
            port     = port,
            status   = NeighborStatus.KNOWN,
            via      = via,
            hops     = 2,
            last_ts  = time.time(),
            version  = version,
            services = services or [],
            role     = role,
        )
        self._table[node_id] = info
        log.debug(f'Registered known: {node_id} via {via}')
        return info

    # ------------------------------------------------------------------ #
    #  Обновление
    # ------------------------------------------------------------------ #

    def touch(self, node_id: str):
        """Обновить last_ts при любом входящем трафике от ноды."""
        info = self._table.get(_canon(node_id))
        if info:
            info.last_ts = time.time()

    def mark_unreachable(self, node_id: str):
        info = self._table.get(_canon(node_id))
        if info:
            info.status = NeighborStatus.UNREACHABLE
            log.warning(f'Marked unreachable: {node_id}')

    def update_services(self, node_id: str, services: List[str]):
        info = self._table.get(_canon(node_id))
        if info:
            info.services = services
            log.debug(f'Services updated for {node_id}: {services}')

    # ------------------------------------------------------------------ #
    #  Запросы
    # ------------------------------------------------------------------ #

    def get(self, node_id: str) -> Optional[NeighborInfo]:
        return self._table.get(_canon(node_id))

    def connected(self) -> List[NeighborInfo]:
        return [n for n in self._table.values()
                if n.status == NeighborStatus.CONNECTED]

    def known(self) -> List[NeighborInfo]:
        return [n for n in self._table.values()
                if n.status == NeighborStatus.KNOWN]

    def all(self) -> List[NeighborInfo]:
        return list(self._table.values())

    def find_by_service(self, service: str) -> List[NeighborInfo]:
        """Найти ноды с нужным сервисом."""
        return [n for n in self._table.values() if service in n.services]

    # ------------------------------------------------------------------ #
    #  Gossip
    # ------------------------------------------------------------------ #

    def to_gossip(self) -> List[dict]:
        """Сериализовать для отправки — без UNREACHABLE."""
        return [
            n.model_dump()
            for n in self._table.values()
            if n.status != NeighborStatus.UNREACHABLE
               and n.node_id != self.own_node_id
        ]
    def merge_gossip(self, neighbors: List[dict], from_node: str):
        """Смержить входящую таблицу соседей.

        Новые узлы добавляются как KNOWN via=from_node. Уже известные
        non-CONNECTED записи обновляются из свежего gossip: via/host/port/
        services/version/role актуализируются, UNREACHABLE реанимируется
        в KNOWN. Свои CONNECTED-записи никогда не перезаписываются.
        Петля via==self отбрасывается, предпочтение — меньшим hops.
        При равных hops с другим via: failover только если существующий via
        UNREACHABLE (иначе — нет флаппинга); метаданные обновляются всегда.
        """
        from_node = _canon(from_node)
        added = 0
        updated = 0
        for entry in neighbors:
            node_id = _canon(entry.get('node_id'))
            if not node_id or node_id == _canon(self.own_node_id):
                continue

            # Loop guard: gossip где via == self -> путь через себя (sysadmin<-test via=sysadmin)
            # иначе sysadmin перезапишет правильный via=PyServ на via=test и закольцует (см. 2026-09-01 loop sysadmin<->test->DPost)
            if _canon(entry.get('via')) == _canon(self.own_node_id):
                log.debug(f'Gossip from {from_node}: skip {node_id} via self (loop)')
                continue
            # 2-hop петля: via узла указывает обратно на нас via==self.own via==self
            # напр. 43-img via sysadmin-pc, а sysadmin-pc via 43-img — оба через друг друга
            via_info = self._table.get(_canon(entry.get('via') or ''))
            if via_info and _canon(via_info.via) == _canon(self.own_node_id):
                log.debug(f'Gossip from {from_node}: skip {node_id} via {entry.get("via")} whose via is self (2-hop loop)')
                continue

            # hops дистанция: 1=прямо, >1 через via
            incoming_hops = int(entry.get('hops') or 1) + 1
            existing = self._table.get(node_id)
            if existing and existing.status == NeighborStatus.CONNECTED:
                continue  # своё прямое соединение не трогаем

            if existing is None:
                self._table[node_id] = NeighborInfo(
                    node_id=node_id,
                    host=entry.get('host', ''),
                    port=entry.get('port', 9000),
                    status=NeighborStatus.KNOWN,
                    via=from_node,
                    hops=incoming_hops,
                    version=entry.get('version', PROTOCOL_VERSION),
                    services=entry.get('services', []),
                    role=entry.get('role', ROLE_NODE),
                )
                added += 1
            else:
                if incoming_hops < existing.hops:
                    # более короткий путь — полное обновление
                    existing.host = entry.get('host', existing.host)
                    existing.port = entry.get('port', existing.port)
                    existing.via = from_node
                    existing.hops = incoming_hops
                    existing.version = entry.get('version', existing.version)
                    existing.services = entry.get('services', existing.services)
                    existing.role = entry.get('role', existing.role)
                    existing.last_ts = time.time()
                    if existing.status == NeighborStatus.UNREACHABLE:
                        existing.status = NeighborStatus.KNOWN
                    updated += 1
                elif incoming_hops == existing.hops and _canon(entry.get('via')) != _canon(existing.via):
                    # равные hops, via различается
                    if existing.status == NeighborStatus.UNREACHABLE:
                        # failover: текущий via мёртв — переключаемся на новый
                        existing.via = from_node
                        existing.host = entry.get('host', existing.host)
                        existing.port = entry.get('port', existing.port)
                        existing.hops = incoming_hops
                        existing.version = entry.get('version', existing.version)
                        existing.services = entry.get('services', existing.services)
                        existing.role = entry.get('role', existing.role)
                        existing.last_ts = time.time()
                        existing.status = NeighborStatus.KNOWN
                        updated += 1
                    else:
                        # via жив — не флэпать, но обновить метаданные из свежего gossip
                        existing.host = entry.get('host', existing.host)
                        existing.port = entry.get('port', existing.port)
                        existing.version = entry.get('version', existing.version)
                        existing.services = entry.get('services', existing.services)
                        existing.role = entry.get('role', existing.role)
                        existing.last_ts = time.time()
                        updated += 1
                else:
                    # более длинный путь или тот же via — обновить метаданные, via/hops не трогать
                    existing.host = entry.get('host', existing.host)
                    existing.port = entry.get('port', existing.port)
                    existing.version = entry.get('version', existing.version)
                    existing.services = entry.get('services', existing.services)
                    existing.role = entry.get('role', existing.role)
                    existing.last_ts = time.time()
                    if existing.status == NeighborStatus.UNREACHABLE and incoming_hops <= existing.hops + 2:
                        existing.status = NeighborStatus.KNOWN

        if added or updated:
            log.debug(f'Gossip from {from_node}: +{added} new, ~{updated} refreshed')

    def sweep(self, now: float | None = None, ttl_known: float = 90, ttl_unreach: float = 300):
        """TTL-чистка: KNOWN без обновления >ttl_known → UNREACHABLE, UNREACHABLE >ttl_unreach → удаление.

        Также каскад: если via стал UNREACHABLE, зависимые KNOWN тоже помечаются.
        Вызывается из Network._gossip_loop (30с) — единый владелец таблицы.
        """
        now = now if now is not None else time.time()
        to_remove = []
        for nid, info in list(self._table.items()):
            age = now - info.last_ts
            if info.status == NeighborStatus.KNOWN and age > ttl_known:
                via_info = self._table.get(info.via) if info.via else None
                # если via недоступен — сразу помечаем, иначе — stale
                if via_info and via_info.status == NeighborStatus.UNREACHABLE:
                    info.status = NeighborStatus.UNREACHABLE
                    log.warning(f'Sweep: {nid} via {info.via} unreachable -> mark unreachable')
                else:
                    info.status = NeighborStatus.UNREACHABLE
                    log.warning(f'Sweep: {nid} stale {age:.0f}s >{ttl_known:.0f}s -> unreachable')
            elif info.status == NeighborStatus.UNREACHABLE and age > ttl_unreach:
                to_remove.append(nid)
        for nid in to_remove:
            self._table.pop(nid, None)
            log.info(f'Sweep: removed {nid} (UNREACHABLE {ttl_unreach:.0f}s)')

        # каскад: KNOWN чей via стал UNREACHABLE — пометить
        for nid, info in list(self._table.items()):
            if info.status == NeighborStatus.KNOWN and info.via:
                via_info = self._table.get(info.via)
                if via_info and via_info.status == NeighborStatus.UNREACHABLE:
                    info.status = NeighborStatus.UNREACHABLE
                    log.warning(f'Sweep: {nid} via {info.via} unreachable -> cascade unreachable')
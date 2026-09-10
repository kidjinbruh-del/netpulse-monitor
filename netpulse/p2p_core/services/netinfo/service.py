# GRID/services/netinfo/service.py — диагностика сети: соседи, сервисы, карта топологии

import asyncio
import time

import psutil

from netpulse.p2p_core.internal_modules.base import ModuleGeneric
from netpulse.p2p_core.networking.neighbor_table import PROTOCOL_VERSION, ROLE_NODE
from netpulse.p2p_core.services.rpc import rpc

_TOPO_CACHE_TTL = 4.0    # сек жизни кэша полного снимка (панель опрашивает каждые 5с)
_TOPO_MAX_TTL = 6        # предохранитель глубины рекурсивного BFS
_TOPO_CALL_TIMEOUT = 6   # сек на ответ одного узла


class NetInfo(ModuleGeneric):
    def __init__(self, name, context):
        super().__init__(name, context)
        self._topo_cache = None   # (time.monotonic(), snapshot dict)

    @rpc
    def neighbors(self, data: dict):
        """Полная таблица соседей."""
        table = self.ctx.network.neighbor_table
        return {
            'own':       self.ctx.NODE,
            'connected': [n.model_dump() for n in table.connected()],
            'known':     [n.model_dump() for n in table.known()],
            'all':       [n.model_dump() for n in table.all()],
        }

    @rpc
    def nodes(self, data: dict):
        """Активные WS подключения (server-side) с метаданными из таблицы."""
        table = self.ctx.network.neighbor_table
        result = {}
        for node_id in self.ctx.network.nodes_manager.nodes.keys():
            info = table.get(node_id)
            result[node_id] = {
                'node_id':  node_id,
                'host':     info.host if info else '',
                'port':     info.port if info else 0,
                'version':  info.version if info else '',
                'services': list(info.services) if info else [],
            }
        return result

    @rpc
    def services(self, data: dict):
        """Сервисы зарегистрированные локально."""
        return list(self.ctx.services.services.keys())

    @rpc
    def find_service(self, data: dict):
        """Найти ноды с указанным сервисом."""
        service = data.get('service') if isinstance(data, dict) else data
        table   = self.ctx.network.neighbor_table
        found   = table.find_by_service(service)
        return [n.model_dump() for n in found]

    @rpc
    def metrics(self, data: dict):
        """Текущие метрики узла: CPU, RAM, аптайм — для тепловой карты меша."""
        vm = psutil.virtual_memory()
        boot = psutil.boot_time()
        return {
            'node_id':    self.ctx.NODE,
            'host':       self.ctx.network.local_ip(),
            'port':       self.ctx.config.network.port,
            'cpu':        psutil.cpu_percent(interval=0.2),
            'cpu_count':  psutil.cpu_count(),
            'mem_pct':    round(vm.percent, 1),
            'mem_used_gb': round(vm.used / 1073741824, 2),
            'mem_total_gb': round(vm.total / 1073741824, 2),
            'uptime_sec': int(time.time() - boot),
            'ts':         int(time.time()),
        }

    # ------------------------------------------------------------------ #
    #  Карта сети
    # ------------------------------------------------------------------ #

    @rpc
    async def topology(self, data: dict = None):
        """Карта сети: все достижимые узлы + направленные физические связи.

        Рекурсивный BFS по connected-узлам (клиенты role='client' не
        опрашиваются и выносятся в отдельный список). Каждое ребро
        {src → dst} означает «src держит outbound WS к dst»;
        ребро verified=True, если его подтвердили ОБА конца — иначе
        half-open (например, зомби-сокет на одной из сторон).

        data: {ttl} — глубина обхода (по умолчанию 4),
              {visited} — уже посещённые узлы (для рекурсии).
        Возвращает: {ok, root, nodes[], clients[], edges[], errors{}, cache_age_sec?}
        """
        data = data or {}
        try:
            ttl = max(1, min(int(data.get('ttl', 4)), _TOPO_MAX_TTL))
        except (TypeError, ValueError):
            ttl = 4
        visited = set(data.get('visited') or [])

        # кэшируется только полный снимок (запрос панели без visited)
        top_level = not visited and int(data.get('ttl', 4)) == 4
        if top_level and self._topo_cache:
            ts, snap = self._topo_cache
            if time.monotonic() - ts < _TOPO_CACHE_TTL:
                snap = dict(snap)
                snap['cache_age_sec'] = round(time.monotonic() - ts, 1)
                return snap

        own = self.ctx.NODE
        visited.add(own)
        net = self.ctx.network

        # ---- узлы: своя таблица соседей + сам узел ----
        nodes = {}
        for row in net.local_sessions():
            nodes[row['node_id']] = {
                'node_id':  row['node_id'],
                'host':     row.get('host', ''),
                'port':     row.get('port', 9000),
                'status':   row.get('status', '?'),
                'via':      row.get('via'),
                'version':  row.get('version', ''),
                'services': row.get('services', []),
                'role':     row.get('role', ROLE_NODE),
            }
        nodes[own] = {
            'node_id':  own,
            'host':     net.local_ip(),
            'port':     net.port,
            'status':   'connected',
            'via':      None,
            'version':  PROTOCOL_VERSION,
            'services': list(self.ctx.services.services.keys()),
            'role':     ROLE_NODE,
        }

        # ---- локальные рёбра из направлений каналов ----
        # outbound X→peer и inbound peer→X дают одно и то же каноническое
        # ребро (peer держит исходящий WS к X) — мержатся reported_by'ем
        edges = {}

        def _add_edge(src: str, dst: str, reporter: str):
            e = edges.setdefault(
                (src, dst), {'src': src, 'dst': dst, 'reported_by': set()})
            e['reported_by'].add(reporter)

        for row in net.local_sessions():
            d = row.get('direction') or ''
            peer = row['node_id']
            if 'outbound' in d:
                _add_edge(own, peer, own)
            if 'inbound' in d:
                _add_edge(peer, own, own)

        # ---- рекурсивный обход connected соседей-узлов ----
        errors = {}
        targets = [
            n for n in net.neighbor_table.connected()
            if getattr(n, 'role', ROLE_NODE) == ROLE_NODE
            and n.node_id not in visited
        ]
        if targets and ttl > 1:
            results = await asyncio.gather(
                *[
                    self.ctx.network.call(
                        dst=n.node_id,
                        service='netinfo',
                        method='topology',
                        data={'ttl': ttl - 1, 'visited': sorted(visited)},
                        timeout=_TOPO_CALL_TIMEOUT,
                    )
                    for n in targets
                ],
                return_exceptions=True,
            )
            for n, res in zip(targets, results):
                if isinstance(res, Exception):
                    errors[n.node_id] = str(res) or type(res).__name__
                    continue
                if not isinstance(res, dict) or not res.get('ok'):
                    errors[n.node_id] = 'bad topology payload'
                    continue
                # merge поддерева
                for nd in res.get('nodes', []) + res.get('clients', []):
                    nid = nd.get('node_id')
                    # локальные данные важнее чужих (у нас они свежее)
                    if nid and nid not in nodes:
                        nodes[nid] = nd
                for ed in res.get('edges', []):
                    src, dst = ed.get('src'), ed.get('dst')
                    if not src or not dst:
                        continue
                    e = edges.setdefault(
                        (src, dst),
                        {'src': src, 'dst': dst, 'reported_by': set()})
                    e['reported_by'].update(ed.get('reported_by', []))
                errors.update(res.get('errors', {}) or {})

        # ---- сериализация ----
        edge_rows = []
        for e in edges.values():
            rep = e['reported_by']
            edge_rows.append({
                'src':         e['src'],
                'dst':         e['dst'],
                'verified':    e['src'] in rep and e['dst'] in rep,
                'reported_by': sorted(rep),
            })
        edge_rows.sort(key=lambda x: (x['src'], x['dst']))

        all_nodes = sorted(nodes.values(), key=lambda n: n['node_id'])

        result = {
            'ok':      True,
            'root':    own,
            'nodes':   [n for n in all_nodes if n.get('role') == ROLE_NODE],
            'clients': [n for n in all_nodes if n.get('role') != ROLE_NODE],
            'edges':   edge_rows,
            'errors':  errors,
        }
        if top_level:
            self._topo_cache = (time.monotonic(), result)
        return result

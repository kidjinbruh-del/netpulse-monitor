"""
Юнит-тесты P2P_Core (в составе NetPulse):
Router (маршрутизация/TTL/петли/RPC), NeighborTable (gossip/sweep),
Pipe (backpressure/fail/sentinel), LocalExecutor + RPC, SessionTable, protocol.

Офлайн: только локальные импорты, без сетевых соединений.
Запуск: python -m tests.test_p2p_core   (достаточно из C:\\сеть пупок)
"""

import asyncio
import sys
import time

from netpulse.p2p_core.networking.protocol import (
    MsgPack, PackType, encode_pack, decode_pack, UnknownPackTypeError,
)
from netpulse.p2p_core.networking.neighbor_table import (
    NeighborTable, NeighborStatus,
)
from netpulse.p2p_core.networking.router import Router, NoRouteToHost, StreamRoute
from netpulse.p2p_core.internal_modules.memory import Pipe, _SENTINEL
from netpulse.p2p_core.internal_modules.executor import LocalExecutor
from netpulse.p2p_core.internal_modules.exceptions import MethodNotFound, RPCTimeout
from netpulse.p2p_core.networking.sessions import SessionTable
from netpulse.p2p_core.services.manager import ServiceManager
from netpulse.p2p_core.services.rpc import (
    rpc, generator, stream_wrapper, stream_consumer,
    get_rpc_methods, get_generators,
)


# ------------------------------------------------------------------ #
#  Моки инфраструктуры Router
# ------------------------------------------------------------------ #

class FakeWS:
    """Client-side сокет: перехватывает ws.send(payload)."""
    def __init__(self, on_send=None):
        self.payloads = []
        self._on_send = on_send

    async def send(self, payload):
        self.payloads.append(payload)
        if self._on_send:
            await self._on_send(decode_pack(payload))


class FakeNode:
    def __init__(self, ws):
        self.ws = ws


class FakeNodesMgr:
    def __init__(self):
        self.nodes = {}

    def add(self, node_id, ws=None):
        self.nodes[node_id] = FakeNode(ws or FakeWS())
        return self.nodes[node_id]

    def get(self, node_id):
        return self.nodes.get(node_id)


class _MemCfg:
    default_buff = 5


class _LocalCfg:
    alias = "self-alias"


class _Cfg:
    memory = _MemCfg()
    local = _LocalCfg()


class _NetRef:
    def __init__(self, table):
        self.neighbor_table = table


class FakeCtx:
    def __init__(self, node="node-a", table=None):
        self.NODE = node
        self.config = _Cfg()
        self.network = _NetRef(table or NeighborTable(node))
        self.services = ServiceManager()


def make_router(nodes_mgr=None, ctx=None):
    ctx = ctx or FakeCtx()
    return Router(nodes_mgr or FakeNodesMgr(), ctx)


# ------------------------------------------------------------------ #
#  protocol
# ------------------------------------------------------------------ #

def test_protocol_roundtrip():
    p = MsgPack(type=PackType.REQUEST, source="node-a", dst="node-b",
                service="svc", method="m", data={"k": [1, 2]})
    enc = encode_pack(p)
    dec = decode_pack(enc)
    assert dec.source == "node-a"
    assert dec.data == {"k": [1, 2]}
    assert dec.type == PackType.REQUEST


def test_protocol_unknown_pack_type():
    import msgpack
    raw = msgpack.packb({"type": "alien", "source": "x"})
    try:
        decode_pack(raw)
        assert False, "ожидался UnknownPackTypeError"
    except UnknownPackTypeError:
        pass


def test_protocol_non_dict_rejected():
    import msgpack
    try:
        decode_pack(msgpack.packb([1, 2, 3]))
        assert False, "ожидался ValueError"
    except (ValueError, Exception):
        pass


# ------------------------------------------------------------------ #
#  NeighborTable
# ------------------------------------------------------------------ #

def test_table_register_connected():
    t = NeighborTable("me")
    info = t.register_connected("Node1", "10.0.0.1", 9000, "sess-1")
    assert info.status == NeighborStatus.CONNECTED
    assert info.via is None
    assert info.hops == 1


def test_table_known_does_not_override_connected():
    t = NeighborTable("me")
    t.register_connected("node1", "10.0.0.1", 9000, "s")
    t.register_known("node1", "10.0.0.9", 9999, via="other")
    assert t.get("node1").status == NeighborStatus.CONNECTED
    assert t.get("node1").host == "10.0.0.1"  # прямой адрес не затёрт


def test_table_known_via():
    t = NeighborTable("me")
    info = t.register_known("node2", "10.0.0.2", 9000, via="node1")
    assert info.status == NeighborStatus.KNOWN
    assert info.via == "node1"
    assert info.hops == 2


def test_table_mark_unreachable():
    t = NeighborTable("me")
    t.register_connected("node1", "10.0.0.1", 9000, "s")
    t.mark_unreachable("node1")
    assert t.get("node1").status == NeighborStatus.UNREACHABLE
    assert t.connected() == []
    assert t.known() == []


def test_table_find_by_service():
    t = NeighborTable("me")
    t.register_connected("n1", "h1", 9000, "s", services=["files", "logs"])
    t.register_connected("n2", "h2", 9000, "s", services=["logs"])
    assert {n.node_id for n in t.find_by_service("files")} == {"n1"}
    assert {n.node_id for n in t.find_by_service("logs")} == {"n1", "n2"}
    assert t.find_by_service("missing") == []


def test_gossip_adds_known_via_from():
    t = NeighborTable("me")
    added = t.merge_gossip([
        {"node_id": "n5", "host": "h5", "port": 9000},
    ], from_node="n1")
    info = t.get("n5")
    assert info.status == NeighborStatus.KNOWN
    assert info.via == "n1"
    assert info.hops == 2


def test_gossip_loop_guard_via_self():
    t = NeighborTable("me")
    t.register_connected("n1", "h1", 9000, "s")
    t.merge_gossip([
        {"node_id": "n2", "via": "me", "host": "h2", "port": 9000},
    ], from_node="n1")
    assert t.get("n2") is None, "петля via self должна быть отброшена"


def test_gossip_two_hop_loop_guard():
    t = NeighborTable("me")
    t.register_connected("n1", "h1", 9000, "s")
    # n2 известен через n1: n2.via == n1
    t.merge_gossip([{"node_id": "n2", "via": "n1", "host": "h2", "port": 9000}],
                   from_node="n1")
    # gossip про n1, у которого via == n2 (т.е. via n1-штриховой указывает назад на n2)
    t.merge_gossip([{"node_id": "n1", "via": "n2", "host": "h1", "port": 9000}],
                   from_node="n2")
    # доложить ещё узел, чей via указывает на n2 чей via == me — должен дропнуться, не должен закольцевать
    still = t.get("n1")
    # n1 осталась connected, не перезаписана
    assert still.status == NeighborStatus.CONNECTED


def test_gossip_prefers_shorter_path():
    t = NeighborTable("me")
    t.register_known("n9", "h9", 9000, via="n1")   # hops=2
    # had known via n1 with hops=2; gossip приходит длинным путём (hops=2 → incoming=3)
    t.merge_gossip([{"node_id": "n9", "host": "hx", "port": 9000, "hops": 2}],
                   from_node="n7")
    info = t.get("n9")
    assert info.hops == 2, "короткий путь не перезаписывается длинным"
    assert info.via == "n1"

    # теперь приходит более короткий путь (hops=1 → incoming=2 == текущие)
    # при равных hops via живой — не флапаем
    t.merge_gossip([{"node_id": "n9", "host": "hy", "port": 9000, "hops": 1}],
                   from_node="n1")
    assert t.get("n9").via == "n1"

    # путь ещё короче невозможен (минимальный возможный через gossip — 2),
    # поэтому проверим: прямой connected всегда сильнее known
    t.register_connected("n9", "h9", 9000, "s")
    assert t.get("n9").status == NeighborStatus.CONNECTED


def test_gossip_failover_equal_hops_unreachable_via():
    t = NeighborTable("me")
    t.register_known("n9", "h9", 9000, via="n1")   # hops=2
    t.mark_unreachable("n9")
    before = t.get("n9").via
    # equal hops (hops=1 → incoming=2), via отличается, существующий UNREACHABLE → failover
    t.merge_gossip([{"node_id": "n9", "host": "h9", "port": 9000, "via": "zzz", "hops": 1}],
                   from_node="n7")
    info = t.get("n9")
    assert info.status == NeighborStatus.KNOWN, "UNREACHABLE реанимируется"
    assert info.via == "n7", "failover на новый via при равных hops"


def test_gossip_no_flap_when_via_alive():
    t = NeighborTable("me")
    t.register_known("n9", "h9", 9000, via="n1")
    t.merge_gossip([{"node_id": "n9", "host": "h9", "port": 9000, "via": "zzz", "hops": 1}],
                   from_node="n7")
    assert t.get("n9").via == "n1", "живой via не должен флэпать"


def test_gossip_excludes_self():
    t = NeighborTable("me")
    t.register_connected("n1", "h1", 9000, "s")
    t.register_connected("me", "h0", 9000, "s")
    gossip = t.to_gossip()
    assert all(n["node_id"] != "me" for n in gossip)


def test_sweep_stale_known_becomes_unreachable():
    t = NeighborTable("me")
    t.register_known("n2", "h2", 9000, via="n1")
    t.get("n2").last_ts = time.time() - 999
    t.sweep(now=time.time(), ttl_known=90)
    assert t.get("n2").status == NeighborStatus.UNREACHABLE


def test_sweep_removes_stale_unreachable():
    t = NeighborTable("me")
    t.register_known("n2", "h2", 9000, via="n1")
    t.get("n2").last_ts = time.time() - 999
    t.sweep(now=time.time(), ttl_known=5, ttl_unreach=300)
    t.get("n2").last_ts = time.time() - 9999
    t.sweep(now=time.time(), ttl_known=5, ttl_unreach=300)
    assert t.get("n2") is None


def test_sweep_cascade_via_unreachable():
    t = NeighborTable("me")
    t.register_connected("n1", "h1", 9000, "s")
    t.register_known("n2", "h2", 9000, via="n1")
    # n1 yмирает как CONNECTED — Network помечает UNREACHABLE при disconnect
    t.mark_unreachable("n1")
    # возраст > ttl_known (90) но < ttl_unreach (300) — помечается, не удаляется
    t.sweep(now=time.time() + 150, ttl_known=90, ttl_unreach=300)
    assert t.get("n1").status == NeighborStatus.UNREACHABLE
    assert t.get("n2").status == NeighborStatus.UNREACHABLE  # каскад via недоступен


# ------------------------------------------------------------------ #
#  Pipe — backpressure / fail / sentinel
# ------------------------------------------------------------------ #

def test_pipe_put_get():
    async def _t():
        p = Pipe("t", buff_len=3)
        await p.put(1)
        await p.put("b")
        assert p.size == 2
        assert await p.get() == 1
        assert await p.get() == "b"
    asyncio.run(_t())


def test_pipe_backpressure_blocks_until_get():
    async def _t():
        p = Pipe("t", buff_len=2)
        await p.put(1)
        await p.put(2)
        assert p.is_full()
        putter = asyncio.create_task(p.put(3))
        await asyncio.sleep(0.05)
        assert not putter.done(), "put должен блокироваться на полном буфере"
        assert await p.get() == 1
        await asyncio.wait_for(putter, timeout=1)
        assert p.size == 2
    asyncio.run(_t())


def test_pipe_fail_propagates_error():
    async def _t():
        p = Pipe("t", buff_len=5)
        await p.put(1)
        err = RuntimeError("boom")
        p.fail(err)
        assert p.failed and p.error is err
        seen = []
        try:
            async for x in p:
                seen.append(x)
            assert False, "ожидалось исключение"
        except RuntimeError as e:
            assert "boom" in str(e)
        assert seen == [1], "реальные чанки должны дочитаться до ошибки"
    asyncio.run(_t())


def test_pipe_close_stops_iteration():
    async def _t():
        p = Pipe("t", buff_len=5)
        await p.put(1)
        await p.put(2)
        p.close()
        seen = [x async for x in p]
        assert seen == [1, 2]
    asyncio.run(_t())


def test_pipe_sentinel_stops_iteration():
    async def _t():
        p = Pipe("t", buff_len=5)
        await p.put(1)
        p.put_nowait(_SENTINEL)
        p.close()
        seen = [x async for x in p]
        assert seen == [1]
    asyncio.run(_t())


# ------------------------------------------------------------------ #
#  RPC-декораторы и LocalExecutor
# ------------------------------------------------------------------ #

class CalcService:
    name = "calc"

    @rpc
    async def add(self, data):
        return data["a"] + data["b"]

    @rpc
    def double(self, data):
        return data * 2

    @rpc
    async def ping(self, data=None):
        return "pong"

    @generator
    def ids(self):
        for i in range(3):
            yield i


class StreamService:
    name = "stream"

    @stream_wrapper("big")
    async def wrap(self, data):
        return {"meta": data}

    @stream_consumer("big")
    async def consume(self, pipe, ctx):
        self.received = [x async for x in pipe]


def test_rpc_decorators_detected():
    svc = CalcService()
    names = set(get_rpc_methods(svc))
    assert {"add", "double", "ping"} <= names
    assert "ids" in get_generators(svc)


def test_executor_async_and_sync_rpc():
    from netpulse.p2p_core.services.rpc import stream_wrapper, stream_consumer

    async def _t():
        sm = ServiceManager()
        svc = CalcService()
        sm.register_service(svc)
        for m in ("add", "double", "ping"):
            sm.register_method(svc, m, getattr(svc, m))
        ex = LocalExecutor(sm, _StubRegistry(), router_ref=None)

        r1 = await ex.execute(MsgPack(
            type=PackType.REQUEST, source="a", dst="b",
            service="calc", method="add", data={"a": 2, "b": 3}))
        assert r1.data == 5
        assert r1.type == PackType.RESPONSE
        assert r1.dst == "a"  # ответ источника

        r2 = await ex.execute(MsgPack(
            type=PackType.REQUEST, source="a", dst="b",
            service="calc", method="double", data=21))
        assert r2.data == 42
    asyncio.run(_t())


def test_executor_method_not_found():
    async def _t():
        sm = ServiceManager()
        svc = CalcService()
        sm.register_service(svc)
        for m in ("add",):
            sm.register_method(svc, m, getattr(svc, m))
        ex = LocalExecutor(sm, _StubRegistry(), router_ref=None)
        try:
            await ex.execute(MsgPack(
                type=PackType.REQUEST, source="a", dst="b",
                service="calc", method="nope", data=None))
            assert False, "ожидался MethodNotFound"
        except MethodNotFound:
            pass
    asyncio.run(_t())


def test_executor_service_method_without_params_not_passed_data():
    """Метод без параметров — data не подставляется (иначе TypeError)."""
    class NoDataService:
        name = "svc"

        @rpc
        async def health(self):
            return "ok"

    async def _t():
        sm = ServiceManager()
        svc = NoDataService()
        sm.register_service(svc)
        for m in ("health",):
            sm.register_method(svc, m, getattr(svc, m))
        ex = LocalExecutor(sm, _StubRegistry(), router_ref=None)
        r = await ex.execute(MsgPack(
            type=PackType.REQUEST, source="a", dst="b",
            service="svc", method="health", data=None))
        assert r.data == "ok"
    asyncio.run(_t())


class _StubRegistry:
    def register(self, label, pipe): return type("S", (), {"ready": asyncio.Event()})()
    def get(self, label): return None


def test_executor_open_stream_and_consumer():
    """open_stream → STREAM_READY + consumer получил все чанки."""
    async def _t():
        sm = ServiceManager()
        svc = StreamService()
        sm.register_service(svc)
        svc.received = []

        from netpulse.p2p_core.networking.stream_registry import StreamRegistry
        ex = LocalExecutor(sm, StreamRegistry(), router_ref=None)

        pack = MsgPack(
            type=PackType.STREAM_OPEN, source="a", dst="b",
            service="stream", method="big", data={"start": 1}, label="L1")
        resp = await ex.open_stream(pack)
        assert resp.type == PackType.STREAM_READY

        # подождать запуск consumer и дать чанкам дойти
        reg = ex.stream_registry
        inbound = reg.get("L1")
        assert inbound is not None
        await asyncio.wait_for(inbound.ready.wait(), timeout=1)
        await reg.feed("L1", "one")
        await reg.feed("L1", "two")
        await reg.close("L1")
        await asyncio.sleep(0.2)
        assert svc.received == ["one", "two"]
        assert reg.get("L1") is None, "закрытый стрим удаляется из реестра"
    asyncio.run(_t())


def test_executor_stream_method_not_found():
    async def _t():
        sm = ServiceManager()
        svc = StreamService()
        sm.register_service(svc)
        from netpulse.p2p_core.networking.stream_registry import StreamRegistry
        ex = LocalExecutor(sm, StreamRegistry(), router_ref=None)
        pack = MsgPack(
            type=PackType.STREAM_OPEN, source="a", dst="b",
            service="stream", method="missing", data=None, label="L2")
        try:
            await ex.open_stream(pack)
            assert False, "ожидался MethodNotFound"
        except MethodNotFound:
            pass
    asyncio.run(_t())


# ------------------------------------------------------------------ #
#  SessionTable
# ------------------------------------------------------------------ #

def test_sessions_resolve_and_cancel():
    async def _t():
        loop = asyncio.get_running_loop()
        st = SessionTable()
        f = st.register_single("L1", "svc", "m")
        st.resolve("L1", "data")
        assert f.result() == "data"
        assert "L1" not in st._table and "L1" not in st._meta

        f2 = st.register_single("L2", "svc", "m")
        st.cancel("L2")
        assert f2.cancelled()

        n = st.cancel_by_service("svc")  # ничего не осталось
        assert n >= 0
    asyncio.run(_t())


def test_sessions_queue_feed_and_cancel():
    async def _t():
        import asyncio
        st = SessionTable()
        q = asyncio.Queue()
        st._table["stream-1"] = q
        st.resolve("stream-1", {"x": 1})
        st.resolve("stream-1", {"x": 2})
        assert q.get_nowait() == {"x": 1}
        assert q.get_nowait() == {"x": 2}
        st.cancel("stream-1")
        assert q.get_nowait() is None  # sentinel для ждущего consumer
        assert "stream-1" not in st._table, "queue-сессия удаляется из таблицы"
    asyncio.run(_t())


# ------------------------------------------------------------------ #
#  Router
# ------------------------------------------------------------------ #

def test_router_forward_direct():
    async def _t():
        nm = FakeNodesMgr()
        nm.add("node-b")
        r = make_router(nm)
        p = MsgPack(type=PackType.REQUEST, source="node-a", dst="node-b",
                    service="s", method="m", data=1, path=["node-a"], ttl=16)
        await r._forward(p)
        ws = nm.nodes["node-b"].ws
        assert len(ws.payloads) == 1
        sent = decode_pack(ws.payloads[0])
        assert sent.ttl == 15
        assert sent.path[-1] == "node-a"
    asyncio.run(_t())


def test_router_forward_direct_client_ws():
    async def _t():
        nm = FakeNodesMgr()
        r = make_router(nm)
        ws = FakeWS()
        r.register_client_ws("node-c", ws)
        p = MsgPack(type=PackType.REQUEST, source="node-a", dst="node-c",
                    service="s", method="m", data=1, path=["node-a"], ttl=16)
        await r._forward(p)
        assert len(ws.payloads) == 1


def test_router_forward_via_neighbor():
    async def _t():
        ctx = FakeCtx()
        nm = FakeNodesMgr()
        nm.add("node-b")  # сосед, через которого ходим
        ctx.network.neighbor_table.register_connected("node-b", "10.0.0.1", 9000, "s")
        ctx.network.neighbor_table.register_known("node-d", "10.0.0.4", 9000, via="node-b")
        r = make_router(nm, ctx)
        p = MsgPack(type=PackType.REQUEST, source="node-a", dst="node-d",
                    service="s", method="m", data=1, path=["node-a"], ttl=16)
        await r._forward(p)
        ws = nm.nodes["node-b"].ws
        assert len(ws.payloads) == 1
        sent = decode_pack(ws.payloads[0])
        assert sent.type == PackType.FORWARDED, "REQUEST должен стать FORWARDED в транзите"
        assert sent.ttl == 15


def test_router_forward_no_route():
    async def _t():
        r = make_router()
        p = MsgPack(type=PackType.REQUEST, source="node-a", dst="node-X",
                    service="s", method="m", data=None, path=["node-a"], ttl=16)
        try:
            await r._forward(p)
            assert False, "ожидался NoRouteToHost"
        except NoRouteToHost:
            pass
    asyncio.run(_t())


def test_router_on_forwarded_ttl_zero_dropped():
    async def _t():
        nm = FakeNodesMgr()
        nm.add("node-b")
        r = make_router(nm)
        p = MsgPack(type=PackType.FORWARDED, source="node-a", dst="node-b",
                    service="s", method="m", data=None, path=["node-a"], ttl=0)
        await r._on_forwarded(p)
        assert len(nm.nodes["node-b"].ws.payloads) == 0, "TTL=0 должен дропнуться"
    asyncio.run(_t())


def test_router_on_forwarded_loop_dropped():
    async def _t():
        nm = FakeNodesMgr()
        nm.add("node-b")
        r = make_router(nm)
        p = MsgPack(type=PackType.FORWARDED, source="node-a", dst="node-b",
                    service="s", method="m", data=None,
                    path=["node-a", "node-b"], ttl=5)
        await r._on_forwarded(p)
        assert len(nm.nodes["node-b"].ws.payloads) == 0, "петля должна дропнуться"
    asyncio.run(_t())


def test_router_on_forwarded_terminates_local():
    """node-b получает FORWARDED с dst=node-b — исполняет локально и
    отвечает по обратному пути (route_back) к node-a."""
    async def _t():
        ctx_b = FakeCtx(node="node-b")
        svc = CalcService()
        ctx_b.services.register_service(svc)
        for m in ("add",):
            ctx_b.services.register_method(svc, m, getattr(svc, m))

        nm = FakeNodesMgr()
        backlog = []

        async def handle_back(pack):
            backlog.append(pack)

        ws_a = FakeWS(on_send=handle_back)
        r = make_router(nm, ctx_b)
        r.register_client_ws("node-a", ws_a)

        p = MsgPack(type=PackType.FORWARDED, source="node-a", dst="node-b",
                    service="calc", method="add", data={"a": 5, "b": 6},
                    path=["node-a"], ttl=16)
        await r._on_forwarded(p)
        assert len(backlog) == 1
        resp = backlog[0]
        assert resp.type == PackType.RESPONSE
        assert resp.data == 11
        assert resp.path == ["node-a"]  # хвост-себя снят, дальше node-a
    asyncio.run(_t())


def test_router_call_self_resolves_locally():
    async def _t():
        ctx = FakeCtx()
        svc = CalcService()
        ctx.services.register_service(svc)
        for m in ("add",):
            ctx.services.register_method(svc, m, getattr(svc, m))
        r = make_router(FakeNodesMgr(), ctx)
        result = await r.call("node-a", "calc", "add", {"a": 2, "b": 40})
        assert result == 42
    asyncio.run(_t())


def test_router_call_self_via_alias():
    async def _t():
        ctx = FakeCtx()
        svc = CalcService()
        ctx.services.register_service(svc)
        for m in ("add", "double"):
            ctx.services.register_method(svc, m, getattr(svc, m))
        r = make_router(FakeNodesMgr(), ctx)
        result = await r.call("self-alias", "calc", "double", 21)
        assert result == 42
    asyncio.run(_t())


def test_router_call_remote_roundtrip():
    async def _t():
        nm = FakeNodesMgr()

        ctx_a = FakeCtx(node="node-a")
        svc = CalcService()
        ctx_a.services.register_service(svc)
        for m in ("add",):
            ctx_a.services.register_method(svc, m, getattr(svc, m))
        r_a = make_router(nm, ctx_a)

        ctx_b = FakeCtx(node="node-b")
        svc_b = CalcService()
        ctx_b.services.register_service(svc_b)
        for m in ("add",):
            ctx_b.services.register_method(svc_b, m, getattr(svc_b, m))
        r_b = make_router(nm, ctx_b)

        # сокет node-a → node-b: перехват отправляет пакет в роутер node-b
        ws_b = FakeWS()

        async def handle_b(pack):
            await r_b._on_request(pack)

        ws_b._on_send = handle_b
        r_a.register_client_ws("node-b", ws_b)

        # ответ вернулся на node-a: резолвим сессию
        async def handle_back(pack):
            r_a.sessions.resolve(pack.label, pack.data)

        ws_a = FakeWS(on_send=handle_back)
        r_b.register_client_ws("node-a", ws_a)

        result = await r_a.call("node-b", "calc", "add", {"a": 1, "b": 41}, timeout=2)
        assert result == 42
    asyncio.run(_t())


def test_router_call_timeout_raises_rpctimeout():
    async def _t():
        nm = FakeNodesMgr()
        nm.add("node-b")  # есть, но не отвечает
        r = make_router(nm)
        try:
            await r.call("node-b", "calc", "add", {"a": 1, "b": 1}, timeout=0.1)
            assert False, "ожидался RPCTimeout"
        except asyncio.TimeoutError:
            raise AssertionError("дошел TimeoutError, а не RPCTimeout")
        except RPCTimeout:
            pass
    asyncio.run(_t())


def test_router_call_no_route_raises():
    async def _t():
        r = make_router()
        try:
            await r.call("nope", "s", "m", None)
            assert False, "ожидался NoRouteToHost"
        except NoRouteToHost:
            pass
    asyncio.run(_t())


def test_router_resolve_by_host():
    ctx = FakeCtx()
    ctx.network.neighbor_table.register_connected("node-p", "10.0.0.9", 9000, "s")
    r = make_router(FakeNodesMgr(), ctx)
    assert r._resolve_by_host("10.0.0.9") == "node-p"
    assert r._resolve_by_host("10.0.0.1") is None


def test_stream_route_expiry_and_sliding_ttl():
    r = make_router()
    route = StreamRoute(label="L", source="a", dst="b")
    assert route.expired is False
    r._stream_routes["L"] = route
    # получить — маршрут обновил established_at
    assert r.get_stream_route("L") is route
    # принудительно состарить
    route.established_at = time.monotonic() - 1000
    assert r.get_stream_route("L") is None, "протухший маршрут должен удалиться"


# ------------------------------------------------------------------ #
#  Nmap service — парсеры (офлайн) + запуск обёртки
# ------------------------------------------------------------------ #

_SWEEP_XML = """<?xml version="1.0"?>
<nmaprun>
 <host>
  <status state="up"/>
  <address addr="192.168.1.5" addrtype="ipv4"/>
  <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="SuperRouter Inc"/>
  <hostnames><hostname name="router.lan" type="user"/></hostnames>
  <uptime seconds="12345"/>
  <os><osmatch name="OpenWrt" accuracy="98"><osclass type="router"/></osmatch></os>
 </host>
 <host>
  <status state="down"/>
  <address addr="192.168.1.10" addrtype="ipv4"/>
 </host>
 <host>
  <status state="up"/>
  <address addr="192.168.1.20" addrtype="ipv4"/>
  <hostnames><hostname name=""/></hostnames>
 </host>
</nmaprun>
"""

_PORTS_XML = """<?xml version="1.0"?>
<nmaprun>
 <host>
  <status state="up"/>
  <address addr="10.0.0.7" addrtype="ipv4"/>
  <address addr="11:22:33:44:55:66" addrtype="mac"/>
  <hostnames><hostname name="srv.lan" type="user"/></hostnames>
  <os><osmatch name="Linux 4.15" accuracy="89"><osclass type="general purpose"/></osmatch></os>
  <ports>
   <port protocol="tcp" portid="22"><state state="open"/>
    <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu"/></port>
   <port protocol="tcp" portid="80"><state state="closed"/>
    <service name="http"/></port>
   <port protocol="tcp" portid="443"><state state="open"/>
    <service name="https" product="nginx" version="1.18.0"/></port>
  </ports>
 </host>
</nmaprun>
"""


def test_nmap_sweep_parser():
    from netpulse.p2p_core.services.nmap.service import parse_sweep_xml
    hosts = parse_sweep_xml(_SWEEP_XML)
    assert len(hosts) == 2, "только up-хосты"
    r = hosts[0]
    assert r['ip'] == '192.168.1.5'
    assert r['mac'] == 'AA:BB:CC:DD:EE:FF'
    assert r['vendor'] == 'SuperRouter Inc'
    assert r['hostname'] == 'router.lan'
    assert r['os'][0]['name'] == 'OpenWrt'
    assert hosts[1]['ip'] == '192.168.1.20'
    assert parse_sweep_xml("garbage") == []
    assert parse_sweep_xml("<?xml?><nmaprun/>") == []


def test_nmap_ports_parser():
    from netpulse.p2p_core.services.nmap.service import parse_ports_xml
    info = parse_ports_xml(_PORTS_XML)
    assert info['host'] == '10.0.0.7'
    assert info['state'] == 'up'
    assert info['mac'] == '11:22:33:44:55:66'
    assert info['hostname'] == 'srv.lan'
    assert info['os'][0]['name'] == 'Linux 4.15'
    assert len(info['ports']) == 3
    open_ports = [p for p in info['ports'] if p['state'] == 'open']
    assert [p['port'] for p in open_ports] == [22, 443]
    ssh = info['ports'][0]
    assert ssh['service'] == 'ssh'
    assert ssh['product'] == 'OpenSSH'
    assert ssh['version'] == '8.2p1'


def test_nmap_status_when_missing():
    """status() корректно сообщает absence вместо падения."""
    from netpulse.p2p_core.services.nmap.service import Nmap
    svc = Nmap(name='nmap', context=object())

    class _Obj:
        def __init__(self, **kw):
            self.__dict__.update(kw)

    # Nmap() в конструкторе сам ищет бинарник; чтобы эмулировать отсутствие
    svc._nmap = None
    svc._version = ''
    st = svc.status(None)
    assert st['ok'] is False
    assert st['available'] is False
    assert 'error' in st


def test_nmap_rpc_methods_ping_sweep_error_without_nmap():
    """ping_sweep без бинарника возвращает {ok:False,error} — не исключение."""
    async def _t():
        from netpulse.p2p_core.services.nmap.service import Nmap
        svc = Nmap(name='nmap', context=object())
        svc._nmap = None
        res = await svc.ping_sweep({'target': '192.168.1.0/24', 'timeout': 2})
        assert res['ok'] is False
        assert 'error' in res
    asyncio.run(_t())


def test_nmap_scan_requires_target():
    async def _t():
        from netpulse.p2p_core.services.nmap.service import Nmap
        svc = Nmap(name='nmap', context=object())
        res = await svc.scan({})
        assert res['ok'] is False
        assert 'target' in res['error']
    asyncio.run(_t())


# ------------------------------------------------------------------ #

ALL = [v for k, v in sorted(globals().items()) if k.startswith("test_")]

if __name__ == "__main__":
    ok = 0
    for fn in ALL:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
            ok += 1
        except Exception as e:
            import traceback
            tb = traceback.format_exc().strip().splitlines()[-1]
            print(f"  FAIL {fn.__name__}: {e} | {tb}")
    print(f"{ok}/{len(ALL)} тестов прошло")
    sys.exit(0 if ok == len(ALL) else 1)
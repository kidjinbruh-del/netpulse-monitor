"""Unit: mesh (WS-кодек через socketpair, pick/status, ошибки без связи)."""
import socket

import pytest

from netpulse import mesh as M
from netpulse.p2p_core.networking.mesh_auth import SIG_FIELD


def _paired():
    a, b = socket.socketpair()
    wa, wb = M.WSClient("h", 1, "/"), M.WSClient("h", 1, "/")
    wa.sock, wb.sock = a, b
    return wa, wb, a, b


def _server_frame(opcode, payload: bytes) -> bytes:
    """Не маскированный серверный фрейм (как шлёт решётка)."""
    hdr = bytes([0x80 | opcode])
    ln = len(payload)
    if ln <= 125:
        hdr += bytes([ln])
    elif ln <= 0xFFFF:
        hdr += bytes([126]) + ln.to_bytes(2, "big")
    else:
        hdr += bytes([127]) + ln.to_bytes(8, "big")
    return hdr + payload


def _read_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        assert chunk
        data += chunk
    return data


def test_frame_text_roundtrip():
    wa, wb, a, b = _paired()
    try:
        # Сервер → клиент: не маскированный фрейм.
        a.sendall(_server_frame(M.WS_OP_TEXT, "привет".encode("utf-8")))
        fin, op, payload = wb.recv_frame()
        assert fin and op == M.WS_OP_TEXT
        assert payload == "привет".encode("utf-8")
        # Клиент → сервер: маскированный фрейм, проверяем структуру.
        wa.send_text("hi")
        b0, b1 = _read_exact(b, 2)
        assert b0 == 0x81 and b1 & 0x80 and (b1 & 0x7F) == 2
        mask = _read_exact(b, 4)
        masked = _read_exact(b, 2)
        assert bytes(x ^ mask[i % 4] for i, x in enumerate(masked)) == b"hi"
    finally:
        a.close()
        b.close()


def test_frame_binary_large():
    wa, wb, a, b = _paired()
    try:
        big = bytes(range(256)) * 300  # >64KB → 127-бит длина
        a.sendall(_server_frame(M.WS_OP_BINARY, big))
        fin, op, payload = wb.recv_frame()
        assert op == M.WS_OP_BINARY and payload == big
        mid = b"x" * 200  # 126-бит длина
        a.sendall(_server_frame(M.WS_OP_BINARY, mid))
        _, op2, p2 = wb.recv_frame()
        assert op2 == M.WS_OP_BINARY and p2 == mid
    finally:
        a.close()
        b.close()


def test_close_sets_flag():
    wa, wb, a, b = _paired()
    try:
        wa.close()
        assert wa.connected is False
    finally:
        a.close()
        b.close()


def _cfg(**kw):
    base = {"enabled": True, "host": "127.0.0.1", "port": 9000,
            "node_id": "hub", "target_node": "node0", "secret": "s"}
    base.update(kw)
    return base


def test_client_call_without_connection():
    c = M.MeshClient(_cfg())
    with pytest.raises(M.MeshError):
        c.call("netinfo", "neighbors", {})


def test_client_status_shape():
    st = M.MeshClient(_cfg()).status
    assert st["uri"] == "ws://127.0.0.1:9000/ws/hub"
    assert st["connected"] is False
    assert st["target_node"] == "node0"


def test_hub_pick_and_status():
    hub = M.MeshHub({**_cfg(), "targets": [
        {"node_id": "node0", "port": 9000},
        {"node_id": "node1", "port": 9001},
    ]})
    assert len(hub.clients) == 2
    assert hub.pick("node1").target == "node1"
    assert hub.pick("NODE0").target == "node0"
    assert hub.connected is False
    st = hub.status
    assert st["target_node"] == "node0, node1"
    assert st["links"][0]["uri"].endswith(":9000/ws/hub")
    with pytest.raises(M.MeshError):
        M.MeshHub({"enabled": True, "targets": []}).call("s", "m", {})


def test_hello_packet_shape():
    c = M.MeshClient(_cfg())
    pkt = c._hello_packet()
    assert pkt["type"] == "hello"
    assert pkt["dst"] == "node0"
    data = pkt["data"]
    assert data["version"] == M.PROTOCOL_VERSION
    assert data["session_id"] == c.session_id
    assert SIG_FIELD in data and isinstance(data[SIG_FIELD], str)


def test_on_pack_gossip_announce_response():
    c = M.MeshClient(_cfg())
    c._on_pack({"type": "gossip", "data": {"neighbors": [{"node_id": "n1"}]}})
    c._on_pack({"type": "announce", "data": {"services": ["netinfo"]}})
    assert c.gossip_nodes == [{"node_id": "n1"}]
    assert c.announce_services == ["netinfo"]
    import threading
    ev = threading.Event()
    c._pending["lbl"] = (ev, {})
    c._on_pack({"type": "response", "label": "lbl", "data": {"ok": 1}})
    assert ev.is_set()
    assert c._pending.pop("lbl")[1] == {"result": {"ok": 1}}
    c._pending["e"] = (threading.Event(), {})
    c._on_pack({"type": "error", "label": "e", "error": "boom"})
    assert c._pending["e"][1] == {"error": "boom"}

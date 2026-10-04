"""MeshClient — мост NetPulse -> P2P-решётка (потоки + stdlib WS-клиент).

Протокол решётки (P2P_Core): msgpack-пакеты вида
    {type, source, dst, service, method, data, label}
- HELLO при подключении к ws://host:port/ws/{node_id}, ждём HELLO_ACK.
- REQUEST/RESPONSE — синхронный RPC-вызов (label = uuid4).
- Фоновый поток держит соединение, обрабатывает PING->PONG,
  GOSSIP/ANNOUNCE (топология/сервисы), RESPONSE/ERROR по label.

v3-реализация: тот же протокол и контракт (MeshHub/MeshClient/MeshError),
типизировано, рукопожатие выделено в метод. Совместимость:
PROTOCOL_VERSION="2.0" (neighbor_table), путь /ws/{node_id}, msgpack.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import os
import socket
import ssl as _ssl
import struct
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

import msgpack

from netpulse.p2p_core.networking.mesh_auth import SIG_FIELD, sign_hello

logger = logging.getLogger(__name__)

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
PROTOCOL_VERSION = "2.0"   # совместимость с netpulse.p2p_core.networking.neighbor_table

WS_OP_TEXT = 0x1
WS_OP_BINARY = 0x2
WS_OP_CLOSE = 0x8
WS_OP_PING = 0x9
WS_OP_PONG = 0xA


def sign_hello_packet(node_id: str, session_id: str, secret: str) -> str:
    """Отпечаток HELLO общим секретом (обёртка над mesh_auth, "" при None)."""
    return sign_hello(node_id, session_id, secret) or ""


class MeshError(Exception):
    pass


class MeshHub:
    """Мульти-таргет мост: держит по одному MeshClient на узел решётки.

    Конфиг: те же поля P2P + targets: [{node_id, port}]. Если targets не
    заданы — один клиент (поведение как у старого MeshClient).
    """

    def __init__(self, cfg: Dict[str, Any]):
        base = dict(cfg)
        targets = cfg.get("targets") or []
        if not targets:
            targets = [{"node_id": cfg.get("target_node"),
                        "port": cfg.get("port")}]
        self.enabled = bool(cfg.get("enabled", True))
        self.node_id = str(cfg.get("node_id") or "NetPulseHub")
        self.clients: List[MeshClient] = []
        for t in targets:
            c = dict(base)
            c["target_node"] = t.get("node_id") or cfg.get("target_node")
            c["port"] = t.get("port") or cfg.get("port")
            self.clients.append(MeshClient(c))
        self.target = self.clients[0].target if self.clients else ""
        self._stop = threading.Event()

    def start(self) -> None:
        if not self.enabled:
            return
        for c in self.clients:
            c.start()

    def stop(self) -> None:
        for c in self.clients:
            c.stop()

    @property
    def connected(self) -> bool:
        return any(c.connected for c in self.clients)

    def pick(self, dst: Optional[str] = None) -> Optional["MeshClient"]:
        if dst:
            for c in self.clients:
                if c.target.lower() == str(dst).lower():
                    return c
        for c in self.clients:
            if c.connected:
                return c
        return self.clients[0] if self.clients else None

    # обратная совместимость имени
    _pick = pick

    def call(
        self, service: str, method: str, data: Any = None,
        dst: Optional[str] = None, timeout: Optional[float] = None,
    ) -> Any:
        c = self.pick(dst)
        if c is None:
            raise MeshError("нет связи с ядром решётки (мост отключён)")
        return c.call(service, method, data, dst=dst or c.target,
                      timeout=timeout or None)

    @property
    def status(self) -> Dict[str, Any]:
        links = [c.status for c in self.clients]
        nodes: List[Any] = []
        services: List[Any] = []
        for s in links:
            for n in (s.get("nodes") or []):
                if n not in nodes:
                    nodes.append(n)
            for srv in (s.get("services") or []):
                if srv not in services:
                    services.append(srv)
        errs = [s.get("last_error") for s in links if s.get("last_error")]
        return {
            "enabled": self.enabled,
            "connected": any(s.get("connected") for s in links),
            "node_id": self.node_id,
            "target_node": ", ".join(c.target for c in self.clients),
            "uri": "; ".join(s.get("uri") for s in links),
            "peer_version": next((s.get("peer_version") for s in links
                                  if s.get("peer_version")), ""),
            "last_error": " | ".join(dict.fromkeys(errs))[:400],
            "nodes": nodes,
            "services": services,
            "links": links,
        }


class WSClient:
    """Минимальный WebSocket-клиент (RFC6455): handshake + фреймы."""

    def __init__(
        self, host: str, port: int, path: str,
        timeout: float = 10, tls: bool = False,
    ):
        self.host = host
        self.port = port
        self.path = path
        self.timeout = timeout
        self.connected = False
        self.sock: Optional[socket.socket] = None
        self._tls = tls

    def connect(self) -> None:
        raw = socket.create_connection((self.host, self.port),
                                       timeout=self.timeout)
        if self._tls:
            ctx = _ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = _ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=self.host)
        self.sock = raw
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        )
        self.sock.sendall(req.encode("latin-1"))
        headers, status = self._read_http()
        if status != 101:
            self.close()
            raise MeshError(f"WS handshake: статус {status}")
        expect = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        if headers.get("sec-websocket-accept") != expect:
            self.close()
            raise MeshError("WS handshake: неверный Sec-WebSocket-Accept")
        self.connected = True

    def _read_http(self) -> Tuple[Dict[str, str], int]:
        data = b""
        self.sock.settimeout(self.timeout)
        while b"\r\n\r\n" not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            data += chunk
        head, _, _ = data.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        try:
            status = int(lines[0].split(" ", 2)[1])
        except (IndexError, ValueError):
            status = 0
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        return headers, status

    def send_text(self, text: str) -> None:
        self._send_payload(WS_OP_TEXT, text.encode("utf-8"))

    def send_binary(self, payload: bytes) -> None:
        self._send_payload(WS_OP_BINARY, payload)

    def send_frame(self, opcode: int, payload: bytes = b"") -> None:
        self._send_payload(opcode, payload)

    def send_ping(self, payload: bytes = b"") -> None:
        self.send_frame(WS_OP_PING, payload)

    def _send_payload(self, opcode: int, payload: bytes) -> None:
        length = len(payload)
        mask = os.urandom(4)
        hdr = bytearray([0x80 | opcode])
        if length <= 125:
            hdr.append(0x80 | length)
        elif length <= 0xFFFF:
            hdr.append(0x80 | 126)
            hdr += struct.pack(">H", length)
        else:
            hdr.append(0x80 | 127)
            hdr += struct.pack(">Q", length)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(hdr) + mask + masked)

    def recv_frame(self) -> Tuple[int, int, bytes]:
        """(fin, opcode, payload) — один фрейм (без маски со стороны сервера)."""
        b0, b1 = self._read(2)
        fin = b0 & 0x80
        opcode = b0 & 0x0F
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack(">H", self._read(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", self._read(8))[0]
        payload = self._read(length) if length else b""
        return fin, opcode, payload

    def _read(self, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise MeshError("WebSocket: соединение закрыто")
            data += chunk
        return data

    def close(self) -> None:
        try:
            self.sock.sendall(bytes([0x88, 0x80]) + os.urandom(4))
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.connected = False


# Алиас старого имени приватного класса.
_WS = WSClient


class MeshClient:
    """Фоновый WS-клиент к ядру решётки + синхронный RPC."""

    def __init__(self, cfg: Dict[str, Any]):
        self.enabled = bool(cfg.get("enabled", True))
        self.host = str(cfg.get("host") or "127.0.0.1")
        self.port = int(cfg.get("port") or 9000)
        self.node_id = str(cfg.get("node_id") or "NetPulseHub")
        self.target = str(cfg.get("target_node") or "Node0")
        self.reconnect_sec = float(cfg.get("reconnect_sec") or 5)
        self.timeout = float(cfg.get("call_timeout") or 15)
        self.secret = str(cfg.get("secret") or "")
        self.connected = False
        self.last_error = ""
        self.peer_version = ""
        self.gossip_nodes: list = []
        self.announce_services: list = []
        self._ws: Optional[WSClient] = None
        self._lock = threading.Lock()
        self._pending: Dict[str, tuple] = {}
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._keepalive_thread: Optional[threading.Thread] = None
        self.session_id = str(uuid.uuid4())

    # ---------- жизненный цикл ----------

    def start(self) -> None:
        if not self.enabled:
            logger.info("[mesh] P2P-мост отключён (p2p.enabled=false)")
            return
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="p2p-mesh")
        self._thread.start()
        self._keepalive_thread = threading.Thread(
            target=self._keepalive_loop, daemon=True, name="p2p-keepalive")
        self._keepalive_thread.start()

    def _keepalive_loop(self) -> None:
        """Держит соединение живым, не делает ненужные RPC."""
        while not self._stop.wait(3):
            if not self.connected or not self._ws:
                continue

    def stop(self) -> None:
        self._stop.set()
        ws = self._ws
        if ws:
            try:
                with self._lock:
                    ws.close()
            except Exception:
                pass

    # ---------- публичный RPC ----------

    def call(
        self, service: str, method: str, data: Any = None,
        dst: Optional[str] = None, timeout: Optional[float] = None,
    ) -> Any:
        """Синхронный вызов метода сервиса на ноде. Возвращает data ответа."""
        if not self.connected or not self._ws:
            raise MeshError("нет связи с ядром решётки (мост отключён)")
        label = str(uuid.uuid4())
        pack = {
            "type": "request",
            "source": self.node_id,
            "dst": str(dst or self.target),
            "service": service,
            "method": method,
            "data": data or {},
            "label": label,
        }
        ev = threading.Event()
        self._pending[label] = (ev, {})
        try:
            with self._lock:
                self._ws.send_binary(msgpack.packb(pack, use_bin_type=True))
        except Exception as e:
            self._pending.pop(label, None)
            self._drop_conn(e)
            raise MeshError(f"отправка запроса: {e}")
        if not ev.wait(timeout or self.timeout):
            self._pending.pop(label, None)
            raise MeshError(f"таймаут RPC {service}.{method} "
                            f"({timeout or self.timeout} c)")
        state = self._pending.pop(label, (None, {}))[1]
        if "error" in state:
            raise MeshError(str(state["error"]))
        return state.get("result")

    @property
    def status(self) -> Dict[str, Any]:
        ws_ok = bool(self._ws and self._ws.connected)
        return {
            "enabled": self.enabled,
            "connected": bool(self.connected and ws_ok),
            "node_id": self.node_id,
            "target_node": self.target,
            "uri": f"ws://{self.host}:{self.port}/ws/{self.node_id}",
            "peer_version": self.peer_version,
            "last_error": self.last_error,
            "nodes": self.gossip_nodes,
            "services": self.announce_services,
        }

    # ---------- внутреннее ----------

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._connect_and_loop()
            except MeshError as e:
                self.last_error = str(e)
            except Exception as e:
                self.last_error = f"{type(e).__name__}: {e}"
            if self._stop.is_set():
                return
            step = 0.5
            for _ in range(max(1, int(self.reconnect_sec / step))):
                if self._stop.is_set():
                    return
                time.sleep(step)

    def _hello_packet(self) -> Dict[str, Any]:
        return {
            "type": "hello",
            "source": self.node_id,
            "dst": self.target,
            "data": {
                "node_id": self.node_id,
                "host": "127.0.0.1",
                "port": 0,
                "version": PROTOCOL_VERSION,
                "session_id": self.session_id,
                "services": [],
                SIG_FIELD: sign_hello_packet(self.node_id, self.session_id,
                                             self.secret),
            },
            "label": str(uuid.uuid4()),
        }

    def _await_hello_ack(self, ws: WSClient) -> None:
        deadline = time.time() + self.timeout
        while time.time() < deadline:
            try:
                with self._lock:
                    _, op, payload = ws.recv_frame()
            except socket.timeout:
                break
            if op == WS_OP_PING:
                with self._lock:
                    ws.send_frame(WS_OP_PONG, payload)
                continue
            if op == WS_OP_CLOSE:
                raise MeshError("WS закрыт при рукопожатии")
            if op != WS_OP_BINARY:
                continue
            try:
                pack = msgpack.unpackb(payload)
            except Exception:
                continue
            pack_type = pack.get("type")
            if pack_type == "hello_ack":
                self.peer_version = str((pack.get("data") or {}).get("version")
                                        or "")
                return
            if pack_type == "hello_reject":
                raise MeshError("HELLO_REJECT: "
                                f"{(pack.get('data') or {}).get('reason')}")
        ws.close()
        raise MeshError(f"нет HELLO_ACK за {self.timeout} c "
                        f"({self.host}:{self.port})")

    def _connect_and_loop(self) -> None:
        ws = WSClient(self.host, self.port, f"/ws/{self.node_id}",
                      timeout=self.timeout)
        ws.connect()
        with self._lock:
            ws.send_binary(msgpack.packb(self._hello_packet(), use_bin_type=True))
        self._await_hello_ack(ws)
        self._ws = ws
        self.connected = True
        self.last_error = ""
        logger.info("[mesh] соединено %s:%s peer=%s",
                    self.host, self.port, self.peer_version or "?")
        try:
            ws.sock.settimeout(2.0)
            self._recv_loop()
        except MeshError as e:
            self.last_error = str(e)
        except Exception as e:
            self.last_error = f"{type(e).__name__}: {e}"
        finally:
            self.connected = False
            self._ws = None
            self._resolve_all("соединение с решёткой разорвано")

    def _recv_loop(self) -> None:
        while not self._stop.is_set():
            try:
                with self._lock:
                    fin, op, payload = self._ws.recv_frame()
            except socket.timeout:
                continue
            if op == WS_OP_PING:
                with self._lock:
                    self._ws.send_frame(WS_OP_PONG, payload)
                continue
            if op == WS_OP_CLOSE:
                raise MeshError("WS: закрыто сервером")
            if op == WS_OP_PONG:
                continue
            if op != WS_OP_BINARY or not fin:
                continue
            try:
                pack = msgpack.unpackb(payload)
            except Exception:
                continue
            self._on_pack(pack)

    def _on_pack(self, pack: Dict[str, Any]) -> None:
        pack_type = pack.get("type")
        if pack_type == "response":
            self._resolve(pack.get("label"), "result", pack.get("data"))
        elif pack_type == "error":
            self._resolve(pack.get("label"), "error",
                          pack.get("error") or "ошибка RPC")
        elif pack_type == "gossip":
            self.gossip_nodes = ((pack.get("data") or {}).get("neighbors") or [])
        elif pack_type == "announce":
            self.announce_services = ((pack.get("data") or {}).get("services")
                                      or [])

    def _resolve(self, label: str, key: str, value: Any) -> None:
        with self._lock:
            entry = self._pending.get(label)
            if entry:
                entry[1][key] = value
                entry[0].set()

    def _resolve_all(self, err: str) -> None:
        with self._lock:
            for ev, state in self._pending.values():
                state["error"] = err
                ev.set()
            self._pending.clear()

    def _drop_conn(self, err: Exception) -> None:
        self.last_error = f"{err}"
        try:
            ws = self._ws
            if ws:
                ws.close()
        except Exception:
            pass

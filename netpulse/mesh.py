"""
MeshClient — мост NetPulse -> P2P-решётка (чистый stdlib, без внешних зависимостей).

Протокол решётки (P2P_Core): JSON-пакеты вида
    {type, source, dst, service, method, data, label}
- HELLO при подключении к ws://host:port/ws/{node_id}, ждём HELLO_ACK.
- REQUEST/RESPONSE — синхронный RPC-вызов (label = uuid4).
- Фоновый поток держит соединение, обрабатывает PING->PONG,
  GOSSIP/ANNOUNCE (топология/сервисы), RESPONSE/ERROR по label.
"""

import base64
import hashlib
import hmac
import logging
import os
import socket
import ssl as _ssl
import struct
import threading
import time
import uuid

import msgpack

logger = logging.getLogger(__name__)

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
PROTOCOL_VERSION = "2.0"   # совместимость с src.networking.neighbor_table
SIG_FIELD = "sig"


def _sign_hello(node_id, session_id, secret):
    """Отпечаток HELLO общим секретом (аналог src.networking.mesh_auth)."""
    if not secret:
        return ""
    msg = f"{node_id}\n{session_id}".encode("utf-8")
    return base64.b64encode(
        hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()
    ).decode("ascii")


class MeshError(Exception):
    pass


class _WS:
    """Минимальный WebSocket-клиент (RFC6455), текстовые фреймы вручную."""

    def __init__(self, host, port, path, timeout=10, tls=False):
        self.host = host
        self.port = port
        self.path = path
        self.timeout = timeout
        self.connected = False
        self.sock = None
        self._tls = tls

    def connect(self):
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

    def _read_http(self):
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

    def send_text(self, text):
        self._send_payload(0x1, text.encode("utf-8"))

    def send_binary(self, payload: bytes):
        self._send_payload(0x2, payload)

    def send_frame(self, opcode, payload=b""):
        self._send_payload(opcode, payload)

    def _send_payload(self, opcode, payload):
        ln = len(payload)
        mask = os.urandom(4)
        hdr = bytearray([0x80 | opcode])
        if ln <= 125:
            hdr.append(0x80 | ln)
        elif ln <= 0xFFFF:
            hdr.append(0x80 | 126)
            hdr += struct.pack(">H", ln)
        else:
            hdr.append(0x80 | 127)
            hdr += struct.pack(">Q", ln)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(hdr) + mask + masked)

    def recv_frame(self):
        """(fin, opcode, payload) — один фрейм (без маски со стороны сервера)."""
        b0, b1 = self._read(2)
        fin = b0 & 0x80
        opcode = b0 & 0x0F
        ln = b1 & 0x7F
        if ln == 126:
            ln = struct.unpack(">H", self._read(2))[0]
        elif ln == 127:
            ln = struct.unpack(">Q", self._read(8))[0]
        payload = self._read(ln) if ln else b""
        return fin, opcode, payload

    def _read(self, n):
        data = b""
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                raise MeshError("WebSocket: соединение закрыто")
            data += chunk
        return data

    def close(self):
        try:
            self.sock.sendall(bytes([0x88, 0x80]) + os.urandom(4))
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.connected = False


class MeshClient:
    """Фоновый WS-клиент к ядру решётки + синхронный RPC."""

    def __init__(self, cfg):
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
        self.gossip_nodes = []
        self.announce_services = []
        self._ws = None
        self._lock = threading.Lock()
        self._pending = {}
        self._stop = threading.Event()
        self._thread = None
        self.session_id = str(uuid.uuid4())

    # ---------- жизненный цикл ----------

    def start(self):
        if not self.enabled:
            logger.info("[mesh] P2P-мост отключён (p2p.enabled=false)")
            return
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="p2p-mesh")
        self._thread.start()
        self._keepalive_thread = threading.Thread(target=self._keepalive_loop,
                                                  daemon=True, name="p2p-keepalive")
        self._keepalive_thread.start()

    def _keepalive_loop(self):
        """PING каждые 3 сек + RPC meta каждые 10 сек — держим WS живым."""
        meta_counter = 0
        while not self._stop.is_set():
            time.sleep(3)
            if self._stop.is_set():
                break
            if not self.connected or not self._ws:
                continue
            # PING фрейм каждые 3 сек
            try:
                with self._lock:
                    self._ws.send_frame(0x9, b"")
            except Exception:
                pass
            # RPC meta каждые ~10 сек (каждый 3-й тик)
            meta_counter += 1
            if meta_counter >= 4:
                meta_counter = 0
                try:
                    self.call("webpanel", "meta", {}, dst=self.target, timeout=5)
                except Exception:
                    pass

    def stop(self):
        self._stop.set()
        ws = self._ws
        if ws:
            try:
                with self._lock:
                    ws.close()
            except Exception:
                pass

    # ---------- публичный RPC ----------

    def call(self, service, method, data=None, dst=None, timeout=None):
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
    def status(self):
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

    def _run(self):
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

    def _connect_and_loop(self):
        ws = _WS(self.host, self.port, f"/ws/{self.node_id}",
                 timeout=self.timeout)
        ws.connect()
        hello = {
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
                SIG_FIELD: _sign_hello(self.node_id, self.session_id,
                                      self.secret),
            },
            "label": str(uuid.uuid4()),
        }
        with self._lock:
            ws.send_binary(msgpack.packb(hello, use_bin_type=True))
        deadline = time.time() + self.timeout
        acked = False
        while time.time() < deadline:
            try:
                with self._lock:
                    _, op, payload = ws.recv_frame()
            except socket.timeout:
                break
            if op == 0x9:                      # ping
                with self._lock:
                    ws.send_frame(0xA, payload)
                continue
            if op == 0x8:                      # close
                raise MeshError("WS закрыт при рукопожатии")
            if op != 0x2:
                continue
            try:
                pack = msgpack.unpackb(payload)
            except Exception:
                continue
            t = pack.get("type")
            if t == "hello_ack":
                acked = True
                self.peer_version = str((pack.get("data") or {}).get("version")
                                        or "")
                break
            if t == "hello_reject":
                raise MeshError(f"HELLO_REJECT: "
                                f"{(pack.get('data') or {}).get('reason')}")
        if not acked:
            ws.close()
            raise MeshError(f"нет HELLO_ACK за {self.timeout} c "
                            f"({self.host}:{self.port})")
        self._ws = ws
        self.connected = True
        self.last_error = ""
        logger.info(f"[mesh] соединено {self.host}:{self.port} "
                    f"peer={self.peer_version or '?'}")
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

    def _recv_loop(self):
        while not self._stop.is_set():
            try:
                with self._lock:
                    fin, op, payload = self._ws.recv_frame()
            except socket.timeout:
                continue
            if op == 0x9:                      # ping -> pong
                with self._lock:
                    self._ws.send_frame(0xA, payload)
                continue
            if op == 0x8:                      # close
                raise MeshError("WS: закрыто сервером")
            if op == 0xA:
                continue
            if op != 0x2 or not fin:           # бинарный msgpack-фрейм
                continue
            try:
                pack = msgpack.unpackb(payload)
            except Exception:
                continue
            self._on_pack(pack)

    def _on_pack(self, pack):
        t = pack.get("type")
        if t == "response":
            self._resolve(pack.get("label"), "result", pack.get("data"))
        elif t == "error":
            self._resolve(pack.get("label"), "error",
                          pack.get("error") or "ошибка RPC")
        elif t == "gossip":
            self.gossip_nodes = ((pack.get("data") or {})
                                 .get("neighbors") or [])
        elif t == "announce":
            self.announce_services = ((pack.get("data") or {})
                                      .get("services") or [])

    def _resolve(self, label, key, value):
        with self._lock:
            entry = self._pending.get(label)
            if entry:
                entry[1][key] = value
                entry[0].set()

    def _resolve_all(self, err):
        with self._lock:
            for ev, state in self._pending.values():
                state["error"] = err
                ev.set()
            self._pending.clear()

    def _drop_conn(self, err):
        self.last_error = f"{err}"
        try:
            ws = self._ws
            if ws:
                ws.close()
        except Exception:
            pass
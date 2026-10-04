"""Захват пакетов (Wireshark-идея, stdlib raw socket).

v3-реализация: тот же контракт RawCaptureService, типизировано.
"""
from __future__ import annotations

import logging
import socket
import struct
import threading
import time
from collections import deque
from typing import Any, Deque, Dict, List, Optional

logger = logging.getLogger(__name__)


class RawCaptureService:
    PROTO_NAMES = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 2: "IGMP"}

    def __init__(self, service: Any):
        self.svc = service
        self.running = False
        self.packets: Deque[Dict[str, Any]] = deque(maxlen=600)
        self.stats: Dict[str, int] = {"total": 0, "tcp": 0, "udp": 0,
                                      "icmp": 0, "other": 0, "bytes": 0}
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._filter_proto = ""

    @staticmethod
    def available() -> bool:
        from .quality import _is_admin
        return _is_admin()

    def start(self, filter_proto: Optional[str] = None) -> Dict[str, Any]:
        if self.running:
            return {"ok": False, "error": "уже запущен"}
        if not self.available():
            return {"ok": False,
                    "error": "нужны права администратора для захвата пакетов"}

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW,
                                 socket.IPPROTO_IP)
            host_ip = self._default_local_ip()
            sock.bind((host_ip, 0))
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            sock.settimeout(1)
            self._sock = sock
        except Exception as e:
            return {"ok": False, "error": f"raw socket: {e}"}

        self.packets.clear()
        for k in self.stats:
            self.stats[k] = 0
        self._filter_proto = (filter_proto or "").upper()
        self._stop.clear()
        self.running = True
        self._thread = threading.Thread(target=self._loop, daemon=True,
                                        name="np-capture")
        self._thread.start()
        return {"ok": True}

    @staticmethod
    def _default_local_ip() -> str:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
        except Exception:
            return "127.0.0.1"
        finally:
            sock.close()

    def stop(self) -> None:
        self.running = False
        self._stop.set()
        try:
            if self._sock:
                self._sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                self._sock.close()
        except Exception:
            pass
        self._sock = None

    def _loop(self) -> None:
        while self.running and not self._stop.is_set():
            try:
                data = self._sock.recv(65535)
                parsed = self.parse_packet(data, self._filter_proto)
                if parsed is None:
                    continue
                self.packets.appendleft(parsed[0])
                for key, delta in parsed[1].items():
                    self.stats[key] = self.stats.get(key, 0) + delta
            except socket.timeout:
                continue
            except OSError:
                break
            except Exception:
                continue

    @classmethod
    def parse_packet(
        cls, data: bytes, filter_proto: str = ""
    ) -> Optional[tuple]:
        """Разбор IPv4-пакета. Возврат (запись, дельты статистики) или None."""
        if len(data) < 20:
            return None
        ver_ihl = data[0]
        if ver_ihl >> 4 != 4:
            return None
        ihl = (ver_ihl & 0xF) * 4
        proto = data[9]
        src = socket.inet_ntoa(data[12:16])
        dst = socket.inet_ntoa(data[16:20])
        length = struct.unpack("!H", data[2:4])[0]

        pname = cls.PROTO_NAMES.get(proto, f"IP-{proto}")
        if filter_proto and pname != filter_proto:
            return None

        info = ""
        if proto in (6, 17) and len(data) >= ihl + 4:
            sport, dport = struct.unpack("!HH", data[ihl:ihl + 4])
            info = f"{sport} → {dport}"

        key = pname.lower() if pname in ("TCP", "UDP", "ICMP") else "other"
        return (
            {"ts": time.time(), "src": src, "dst": dst,
             "proto": pname, "len": length, "info": info},
            {"total": 1, "bytes": length, key: 1},
        )

    def snapshot(self, limit: int = 120) -> Dict[str, Any]:
        return {"running": self.running, "available": self.available(),
                "stats": dict(self.stats),
                "packets": list(self.packets)[:limit]}

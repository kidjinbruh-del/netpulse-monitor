"""Wake-on-LAN: пробуждение машин по magic-packet.

MAC берётся из lan_devices, при отсутствии — из свежего ARP (и сохраняется).

v3-реализация: тот же контракт WolController(service), типизировано.
service обязан давать .db.
"""
from __future__ import annotations

import logging
import re
import socket
import subprocess
import sys
from typing import Any, Dict, Optional

from core.utils import decode_process_output

logger = logging.getLogger(__name__)

WOL_PORT = 9
WOL_BROADCAST = "255.255.255.255"


def build_packet(mac: str) -> bytes:
    clean = str(mac).replace(":", "").replace("-", "").strip().lower()
    if len(clean) != 12:
        raise ValueError(f"MAC битый: {mac}")
    int(clean, 16)  # проверка hex
    return bytes.fromhex("FF" * 6 + clean * 16)


def send_wol(
    mac: str, broadcast: str = WOL_BROADCAST, port: int = WOL_PORT
) -> None:
    pkt = build_packet(mac)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(pkt, (broadcast, port))
    finally:
        sock.close()
    logger.info("WoL пакет отправлен на %s (%s:%s)", mac, broadcast, port)


class WolController:
    def __init__(self, service: Any):
        self.svc = service

    @staticmethod
    def is_self(host: Optional[str]) -> bool:
        h = str(host or "").lower().strip()
        local = {"127.0.0.1", "localhost", "::1", socket.gethostname().lower()}
        return h in local

    @staticmethod
    def arp_lookup(ip: str) -> Optional[str]:
        """Свежий arp -a: иногда запись есть, а последний скан её не застал."""
        try:
            flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            result = subprocess.run(["arp", "-a"], capture_output=True,
                                    timeout=5, creationflags=flags)
            txt = decode_process_output(result.stdout or b"")
            m = re.search(re.escape(ip) +
                          r"\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})", txt)
            if m:
                return m.group(1).lower().replace("-", ":")
        except Exception:
            pass
        return None

    def _mac_from_db(self, key: str) -> Optional[str]:
        row = self.svc.db.execute(
            """SELECT mac FROM lan_devices
               WHERE ip = ? OR hostname = ? OR alias = ? LIMIT 1""",
            (key, key, key), fetch=True)
        if row and row[0].get("mac"):
            return row[0]["mac"]
        return None

    def _remember_mac(self, key: str, mac: str) -> None:
        exists = self.svc.db.execute(
            "SELECT mac FROM lan_devices WHERE mac = ?", (mac,), fetch=True)
        if exists:
            self.svc.db.execute(
                "UPDATE lan_devices SET ip = ? WHERE mac = ?", (key, mac))
        else:
            self.svc.db.execute(
                """INSERT INTO lan_devices
                   (mac, ip, hostname, vendor, first_seen, last_seen)
                   VALUES (?,?,?,?,datetime('now','localtime'),
                           datetime('now','localtime'))""",
                (mac, key, "-", "WOL"))
        logger.info("WoL: MAC %s для %s найден через ARP", mac, key)

    def wake(self, host: Optional[str]) -> Dict[str, Any]:
        """host = имя или IP. Себя будить нельзя — честно скажем."""
        key = str(host or "").strip()
        if not key:
            return {"ok": False, "error": "нужен host"}
        if self.is_self(key):
            return {"ok": False, "self": True,
                    "error": "Это этот ПК — он уже включён"}

        mac = self._mac_from_db(key)
        if not mac:
            mac = self.arp_lookup(key)
            if mac:
                # Запомним, чтобы в следующий раз мгновенно.
                try:
                    self._remember_mac(key, mac)
                except Exception as e:
                    logger.warning("WoL: не сохранил MAC: %s", e)

        if not mac:
            return {"ok": False,
                    "error": f"MAC для {key} не найден — выполните "
                             f"сканирование локальной сети"}
        try:
            send_wol(mac)
        except Exception as e:
            return {"ok": False, "error": str(e)}
        return {"ok": True, "mac": mac, "host": key}

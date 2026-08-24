"""
Wake-on-LAN: пробуждение машин по magic-packet.
MAC берётся из lan_devices, при отсутствии — из свежего ARP (и сохраняется).
"""

import logging
import re
import socket
import subprocess
import sys

from core.utils import decode_process_output

logger = logging.getLogger(__name__)


def build_packet(mac):
    clean = str(mac).replace(":", "").replace("-", "").strip().lower()
    if len(clean) != 12:
        raise ValueError(f"MAC битый: {mac}")
    int(clean, 16)  # проверка hex
    return bytes.fromhex("FF" * 6 + clean * 16)


def send_wol(mac, broadcast="255.255.255.255", port=9):
    pkt = build_packet(mac)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(pkt, (broadcast, port))
    finally:
        s.close()
    logger.info("WoL пакет отправлен на %s (%s:%s)", mac, broadcast, port)


class WolController:
    def __init__(self, service):
        self.svc = service

    def _is_self(self, host):
        h = str(host or "").lower().strip()
        local = {"127.0.0.1", "localhost", "::1", socket.gethostname().lower()}
        return h in local

    def _arp_lookup(self, ip):
        """Свежий arp -a: иногда запись есть, а последний скан её не застал."""
        try:
            flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            r = subprocess.run(["arp", "-a"], capture_output=True,
                               timeout=5, creationflags=flags)
            txt = decode_process_output(r.stdout or b"")
            m = re.search(re.escape(ip) +
                          r"\s+([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})", txt)
            if m:
                return m.group(1).lower().replace("-", ":")
        except Exception:
            pass
        return None

    def wake(self, host):
        """host = имя или IP. Себя будить нельзя — честно скажем."""
        key = str(host or "").strip()
        if not key:
            return {"ok": False, "error": "нужен host"}
        if self._is_self(key):
            return {"ok": False, "self": True,
                    "error": "Это этот ПК — он уже включён"}

        mac = None
        row = self.svc.db.execute(
            """SELECT mac FROM lan_devices
               WHERE ip = ? OR hostname = ? OR alias = ? LIMIT 1""",
            (key, key, key), fetch=True)
        if row and row[0]["mac"]:
            mac = row[0]["mac"]

        if not mac:
            mac = self._arp_lookup(key)
            if mac:
                # запомним, чтобы в следующий раз мгновенно
                exists = self.svc.db.execute(
                    "SELECT mac FROM lan_devices WHERE mac = ?",
                    (mac,), fetch=True)
                if exists:
                    self.svc.db.execute(
                        "UPDATE lan_devices SET ip = ? WHERE mac = ?",
                        (key, mac))
                else:
                    self.svc.db.execute(
                        """INSERT INTO lan_devices
                           (mac, ip, hostname, vendor, first_seen, last_seen)
                           VALUES (?,?,?,?,datetime('now','localtime'),
                                   datetime('now','localtime'))""",
                        (mac, key, "-", "WOL",))
                logger.info("WoL: MAC %s для %s найден через ARP", mac, key)

        if not mac:
            return {"ok": False,
                    "error": f"MAC для {key} не найден — выполните "
                             f"сканирование локальной сети"}
        try:
            send_wol(mac)
        except Exception as e:
            return {"ok": False, "error": str(e)}
        return {"ok": True, "mac": mac, "host": key}

"""
Wake-on-LAN: пробуждение машин по magic-packet.
MAC берётся из lan_devices по IP машины (заполняется сканером локальной сети).
"""

import logging
import socket

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

    def wake(self, host):
        """host = имя или IP; MAC ищем в lan_devices."""
        key = str(host or "").strip()
        if not key:
            return {"ok": False, "error": "нужен host"}
        row = self.svc.db.execute(
            """SELECT mac FROM lan_devices
               WHERE ip = ? OR hostname = ? LIMIT 1""",
            (key, key), fetch=True)
        if not row or not row[0]["mac"]:
            return {"ok": False,
                    "error": f"MAC для {key} не найден — выполните "
                             f"сканирование локальной сети"}
        try:
            send_wol(row[0]["mac"])
        except Exception as e:
            return {"ok": False, "error": str(e)}
        return {"ok": True, "mac": row[0]["mac"], "host": key}

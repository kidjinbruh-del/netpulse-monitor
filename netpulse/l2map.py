"""
L2-карта: физическая топология по SNMP.

Где сидит устройство физически (порт коммутатора), соседи по LLDP/CDP и
PTR-резолв имён для устройств без hotname. Всё на чистом stdlib:
SNMP GETNEXT поверх существующего BER-кода из infra.py.

- Bridge-MIB (dot1dTpFdbTable): MAC -> порт моста -> ifIndex -> имя интерфейса
- LLDP-MIB (lldpRemTable): соседи устройства (sysName/chassis MAC)
- PTR (socket.gethostbyaddr): подпись имён для lan_devices без hostname
"""

import logging
import socket
import threading
import time
from datetime import datetime

from .infra import _tlv, _int_enc, _oid_enc, _octet, _tlv_parse, _oid_dec, \
    _val_convert, ping as infra_ping

logger = logging.getLogger(__name__)

# Bridge-MIB: dot1dTpFdbTable -> dot1dTpFdbPort (индекс = MAC)
OID_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
# Bridge-MIB: dot1dBasePortIfIndex (индекс = порт моста)
OID_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"
# IF-MIB: ifName / ifDescr
OID_IFNAME = "1.3.6.1.2.1.31.1.1.1.1"
OID_IFDESCR = "1.3.6.1.2.1.2.2.1.2"
# LLDP-MIB: lldpRemTable
OID_LLDP_CHASSIS = "1.0.8802.1.1.2.1.4.1.1.5"
OID_LLDP_PORTID = "1.0.8802.1.1.2.1.4.1.1.6"
OID_LLDP_SYSNAME = "1.0.8802.1.1.2.1.4.1.1.9"

_MAX_VARS = 40


def _now_iso():
    return datetime.now().isoformat()


# ---------- SNMP GETNEXT / walk ----------

def snmp_getnext(ip, community, oid, timeout=2.0, max_vars=_MAX_VARS):
    """Один GETNEXT. Возврат: (end_oid, list[(oid, value)]) или (None, [])."""
    req_id = int(time.time()) & 0x7FFFFFFF
    varbind = _tlv(0x30, _oid_enc(oid) + _tlv(0x05, b""))
    pdu = _tlv(0xA1, _int_enc(req_id) + _int_enc(0) + _int_enc(0)
               + _tlv(0x30, varbind))
    packet = _tlv(0x30, _int_enc(1) + _octet(community) + pdu)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(packet, (ip, 161))
        data, _ = s.recvfrom(65535)
    except (socket.timeout, OSError):
        return None, []
    finally:
        s.close()

    try:
        _, outer, _ = _tlv_parse(data, 0)
        pos = 0
        _, _, pos = _tlv_parse(outer, pos)
        _, _, pos = _tlv_parse(outer, pos)
        _, pdu_c, _ = _tlv_parse(outer, pos)
        p = 0
        _, _, p = _tlv_parse(pdu_c, p)
        _, err, p = _tlv_parse(pdu_c, p)
        errv = int.from_bytes(err, "big") if err else 0
        _, _, p = _tlv_parse(pdu_c, p)
        vtag, vblist, _ = _tlv_parse(pdu_c, p)
        if vtag != 0x30 or errv:
            return None, []
        out, q = [], 0
        while q < len(vblist):
            tag1, c1, q = _tlv_parse(vblist, q)
            if tag1 != 0x30:
                break
            _, oid_c, q2 = _tlv_parse(c1, 0)
            vtag, vraw, _ = _tlv_parse(c1, q2)
            out.append((_oid_dec(oid_c), _val_convert(vtag, vraw)))
        return (out[-1][0] if out else None), out
    except Exception as e:
        logger.debug("GETNEXT %s (%s): %s", ip, oid, e)
        return None, []


def snmp_walk(ip, community, base_oid, timeout=2.0, limit=500, check_first=None):
    """Полный walk по base_oid (включительно). Возврат: [(oid, value)]."""
    result, current, guard = [], base_oid, 0
    while current and guard < limit:
        guard += 1
        end, pairs = snmp_getnext(ip, community, current, timeout=timeout)
        if not end:
            break
        prefix = base_oid + "."
        if not str(end).startswith(base_oid):
            break
        for oid, val in pairs:
            if not str(oid).startswith(prefix):
                continue
            if check_first and None in val:
                pass
            result.append((oid, val))
            if len(result) >= limit:
                return result
        current = end
        time.sleep(0.02)
    return result


def mac_iso(raw):
    """Нормализация hex-MAC ('001122334455') -> '00:11:22:33:44:55'."""
    raw = str(raw or "").replace(":", "").replace("-", "")
    raw = raw[:12].lower()
    return ":".join(raw[i:i + 2] for i in range(0, len(raw), 2)) if len(raw) == 12 else None


def _hexstr_to_bytes(raw):
    raw = str(raw or "")
    return bytes(int(raw[i:i + 2], 16) for i in range(0, len(raw), 2))


# ---------- модуль ----------

class L2Map:
    def __init__(self, service):
        self.svc = service
        self._lock = threading.Lock()
        self.last_ports = []
        self.last_lldp = []
        self.scanning = False
        self._ensure()

    def _ensure(self):
        cols = [r["name"] for r in (self.svc.db.execute(
            "PRAGMA table_info(lan_devices)", fetch=True) or [])]
        if cols and "hostname" not in cols:
            self.svc.db.execute("ALTER TABLE lan_devices ADD COLUMN hostname TEXT")
        self.svc.db.execute(
            """CREATE TABLE IF NOT EXISTS l2_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                mac TEXT NOT NULL,
                switch_ip TEXT NOT NULL,
                if_index INTEGER,
                if_name TEXT,
                UNIQUE(mac, switch_ip))""")
        self.svc.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_l2ports_mac ON l2_ports(mac)")

    # ---------- 1. MAC -> порт коммутатора ----------

    def find_switches(self):
        """Кандидаты в коммутаторы: живые хосты со SNMP."""
        hosts = self.svc.inventory.list_hosts()
        up = [h for h in hosts if h.get("online")]
        if not up:
            return [{"name": "192.168.1.1", "ip": "192.168.1.1"}]
        return [{"name": h.get("name"), "ip": h.get("ip")} for h in up]

    def port_map(self, switch_ip, community="public"):
        """MAC -> {port, if_index, if_name} для одного коммутатора."""
        fdb = snmp_walk(switch_ip, community, OID_FDB_PORT, limit=4000)
        if not fdb:
            return {}
        ports = {}
        for oid, val in fdb:
            mac = mac_iso(oid.split(".")[-6:])
            if not mac:
                continue
            try:
                ports[mac] = int(val)
            except (TypeError, ValueError):
                continue

        # индекс порта -> ifIndex
        port_if = {}
        pi = snmp_walk(switch_ip, community, OID_PORT_IFINDEX, limit=500)
        for oid, val in pi:
            idx = oid.split(".")[-1]
            try:
                port_if[int(idx)] = int(val)
            except (TypeError, ValueError):
                continue

        # ifIndex -> имя
        ifnames = {}
        for walk_oid in (OID_IFNAME, OID_IFDESCR):
            for oid, val in snmp_walk(switch_ip, community, walk_oid, limit=500):
                try:
                    idx = int(oid.rsplit(".", 1)[-1])
                except (TypeError, ValueError):
                    continue
                if names := ifnames.get(idx):
                    if not names and val:
                        ifnames[idx] = str(val)[:32]
                else:
                    ifnames[idx] = str(val)[:32]

        out = {}
        for mac, port in ports.items():
            if_index = port_if.get(port)
            out[mac] = {
                "mac": mac,
                "port": port,
                "if_index": if_index,
                "if_name": (ifnames.get(if_index) if if_index is not None else None)
                           or f"port {port}",
            }
        return out

    def scan_ports(self):
        """Обновляет l2_ports по живым коммутаторам с SNMP."""
        cfg = self.svc.cfg.get("infra", {})
        community = cfg.get("community", "public")
        all_ports, errors = [], []
        for sw in self.find_switches():
            ip = sw["ip"]
            if not infra_ping(ip):
                continue
            try:
                pm = self.port_map(ip, community)
            except Exception as e:
                logger.debug("port_map %s: %s", ip, e)
                continue
            for mac, info in pm.items():
                self.svc.db.execute(
                    """INSERT INTO l2_ports (timestamp, mac, switch_ip, if_index, if_name)
                       VALUES (?,?,?,?,?)
                       ON CONFLICT(mac, switch_ip) DO UPDATE SET
                         timestamp = excluded.timestamp,
                         if_index = excluded.if_index,
                         if_name = excluded.if_name""",
                    (_now_iso(), mac, ip, info["if_index"], info["if_name"]))
                info["switch_ip"] = ip
                all_ports.append(info)
        with self._lock:
            self.last_ports = all_ports
        self.scanning = False
        return {"ok": True, "ports": len(all_ports), "errors": len(errors)}

    def ports_for(self, mac):
        mac = mac_iso(str(mac or "").lower())
        if not mac:
            return []
        return self.svc.db.execute(
            """SELECT switch_ip, if_index, if_name, timestamp FROM l2_ports
               WHERE mac = ? ORDER BY timestamp DESC""",
            (mac,), fetch=True) or []

    # ---------- 2. LLDP / CDP соседи ----------

    def lldp_neighbors(self, prefer="192.168.1.1", community="public"):
        """Соседи устройства по LLDP-MIB. Возврат списка словарей."""
        rows = snmp_walk(prefer, community, OID_LLDP_CHASSIS, limit=800)
        if not rows:
            return []
        portids = dict((k, v) for k, v
                       in snmp_walk(prefer, community, OID_LLDP_PORTID, limit=800))
        sysnames = dict((k, v) for k, v
                        in snmp_walk(prefer, community, OID_LLDP_SYSNAME, limit=800))
        out = []
        for oid, chassis in rows:
            oid_head = oid.replace(OID_LLDP_CHASSIS, "", 1)
            try:
                # размер длины chassis-строка: последний предаиндекс
                parts = oid_head.strip(".").split(".")
                if len(parts) < 3:
                    continue
                mac = mac_iso(parts[-6:])
                if not mac:
                    continue
            except Exception:
                continue
            out.append({
                "remote_mac": mac,
                "remote_port": portids.get(oid_head),
                "remote_sysname": sysnames.get(oid_head, ""),
                "remote_if": oid_head,
            })
        with self._lock:
            self.last_lldp = out
        return out

    # ---------- 3. PTR-резолв имён ----------

    def resolve_ptrs(self):
        """PTR-резолв для lan_devices без hostname. Возвращает число обновлений."""
        rows = self.svc.db.execute(
            """SELECT ip FROM lan_devices WHERE hostname IS NULL OR hostname = '-'
               OR hostname = ''""", fetch=True) or []
        updated = 0
        for r in rows:
            ip = str(r["ip"] or "").strip()
            if not ip or ip.startswith("127."):
                continue
            try:
                host = socket.gethostbyaddr(ip)[0]
            except Exception:
                continue
            self.svc.db.execute(
                "UPDATE lan_devices SET hostname = ? WHERE ip = ?", (host, ip))
            updated += 1
        return updated

    # ---------- жизненный цикл ----------

    def scan(self):
        if self.scanning:
            return {"ok": True, "skipped": True}
        self.scanning = True
        self.resolve_ptrs()
        return self.scan_ports()

    def status(self):
        return {
            "ports": len(self.last_ports),
            "lldp": len(self.last_lldp),
            "scanning": self.scanning,
        }
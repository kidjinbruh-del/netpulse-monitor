"""
Инфраструктура: роутеры, коммутаторы, серверы.

SNMP v2c GET на чистом stdlib (BER-кодирование вручную) — sysName, sysDescr,
sysUpTime, sysContact, sysLocation, ifNumber. Классификация устройств:
шлюз по умолчанию -> router; SNMP ответил -> switch/router/infra;
WinRM отвечает -> pc (ставит сторож).
"""

import logging
import re
import socket
import subprocess
import sys
import time
from datetime import datetime

logger = logging.getLogger(__name__)

# OID'ы MIB-2 system
OIDS = {
    "1.3.6.1.2.1.1.1.0": "sysDescr",
    "1.3.6.1.2.1.1.2.0": "sysObjectID",
    "1.3.6.1.2.1.1.3.0": "sysUpTime",
    "1.3.6.1.2.1.1.4.0": "sysContact",
    "1.3.6.1.2.1.1.5.0": "sysName",
    "1.3.6.1.2.1.1.6.0": "sysLocation",
    "1.3.6.1.2.1.2.1.0": "ifNumber",
}


# ---------- BER: кодирование ----------

def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0x7F]) + out
        n >>= 7
    return bytes([0x80 | len(out)]) + out


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def _int_enc(v: int) -> bytes:
    out = b""
    while True:
        out = bytes([v & 0xFF]) + out
        v >>= 8
        if v == 0:
            break
    if out and out[0] & 0x80:
        out = b"\x00" + out
    return _tlv(0x02, out)


def _oid_enc(oid: str) -> bytes:
    parts = [int(x) for x in oid.strip().split(".")]
    first = 40 * parts[0] + parts[1]
    rest = bytes([first])
    for p in parts[2:]:
        if p < 0x80:
            rest += bytes([p])
        else:
            chunk = b""
            while p:
                chunk = bytes([(p & 0x7F) | 0x80]) + chunk
                p >>= 7
            rest += chunk[:-1] + bytes([chunk[-1] & 0x7F])
    return _tlv(0x06, rest)


def _octet(s: str) -> bytes:
    return _tlv(0x04, s.encode("utf-8", "replace"))


# ---------- BER: разбор ----------

def _tlv_parse(buf: bytes, pos: int):
    tag = buf[pos]
    ln = buf[pos + 1]
    hlen = 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[pos + 2:pos + 2 + n], "big")
        hlen = 2 + n
    content = buf[pos + hlen:pos + hlen + ln]
    return tag, content, pos + hlen + ln


def _oid_dec(content: bytes) -> str:
    if not content:
        return "?"
    b0 = content[0]
    parts = [b0 // 40, b0 % 40]
    v = 0
    for b in content[1:]:
        v = (v << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(v)
            v = 0
    return ".".join(str(x) for x in parts)


def _val_convert(tag: int, raw: bytes):
    if tag == 0x04 or tag == 0x16:
        return raw.decode("utf-8", "replace").strip()
    if tag in (0x02, 0x41, 0x43, 0x46, 0x47, 0x48):
        v = 0
        for b in raw:
            v = (v << 8) | b
        return v
    if tag == 0x05:
        return ""
    return raw.hex()


def snmp_get(ip: str, community: str = "public", timeout: float = 2.0):
    """SNMP v2c GET по системным OID'ам. Возврат: {sysName: ..., ...} или None."""
    req_id = int(time.time()) & 0x7FFFFFFF
    varbinds = b"".join(_tlv(0x30, _oid_enc(oid) + _tlv(0x05, b""))
                        for oid in OIDS)
    pdu = _tlv(0xA0, _int_enc(req_id) + _int_enc(0) + _int_enc(0)
               + _tlv(0x30, varbinds))
    packet = _tlv(0x30, _int_enc(1) + _octet(community) + pdu)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(packet, (ip, 161))
        data, _ = s.recvfrom(4096)
    except (socket.timeout, OSError):
        return None
    finally:
        s.close()
    return parse_snmp_response(data)


def parse_snmp_response(data: bytes):
    try:
        _, outer, _ = _tlv_parse(data, 0)
        pos = 0
        _, c1, pos = _tlv_parse(outer, pos)      # version
        _, c2, pos = _tlv_parse(outer, pos)      # community
        ptag, pdu_c, _ = _tlv_parse(outer, pos)  # response PDU
        if ptag != 0xA2:
            return None
        p = 0
        _, p, p = _tlv_parse(pdu_c, p)           # request-id
        _, err, p = _tlv_parse(pdu_c, p)         # error-status
        errv = int.from_bytes(err, "big") if err else 0
        _, _, p = _tlv_parse(pdu_c, p)           # error-index
        vtag, vblist, _ = _tlv_parse(pdu_c, p)   # varbind list
        if vtag != 0x30:
            return None
        out, q = {}, 0
        while q < len(vblist):
            tag1, c1, q = _tlv_parse(vblist, q)
            if tag1 != 0x30:
                break
            _, oid_c, q2 = _tlv_parse(c1, 0)
            vtag, vraw, _ = _tlv_parse(c1, q2)
            oid = _oid_dec(oid_c)
            if oid in OIDS:
                out[OIDS[oid]] = _val_convert(vtag, vraw)
        if errv:
            out["_error"] = f"SNMP errstatus {errv}"
        return out or None
    except Exception as e:
        logger.debug("SNMP parse %s: %s", ip, e)
        return None


def ping(ip: str, timeout_ms=800) -> bool:
    cmd = (["ping", "-n", "1", "-w", str(timeout_ms), ip] if sys.platform == "win32"
           else ["ping", "-c", "1", "-W", "1", ip])
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=3,
                           creationflags=flags)
        return r.returncode == 0
    except Exception:
        return False


# ---------- модуль ----------

def _now_iso():
    return datetime.now().isoformat()


class Infra:
    def __init__(self, service):
        self.svc = service
        self._ensure()
        self._gw_cache = (None, 0.0)

    def _ensure(self):
        cols = [r["name"] for r in (self.svc.db.execute(
            "PRAGMA table_info(hosts)", fetch=True) or [])]
        if not cols:
            return
        for col, typ in (("dtype", "TEXT"), ("dtype_manual", "INTEGER"),
                         ("sys_name", "TEXT"), ("sys_descr", "TEXT"),
                         ("uptime_h", "REAL"), ("snmp_at", "TEXT")):
            if col not in cols:
                self.svc.db.execute(f"ALTER TABLE hosts ADD COLUMN {col} {typ}")

    # ---------- шлюз ----------

    def gateway_ip(self):
        ts, gw = self._gw_cache
        if gw and time.time() - ts < 600:
            return gw
        best = None  # (metric, ip)
        try:
            flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            r = subprocess.run(["route", "print", "0.0.0.0"], capture_output=True,
                               timeout=6, creationflags=flags)
            from core.utils import decode_process_output
            txt = decode_process_output(r.stdout or b"")
            # 0.0.0.0  0.0.0.0  <шлюз>  <интерфейс>  <метрика> — берём минимум
            for m in re.finditer(
                    r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\d+\.\d+\.\d+\.\d+)\s+"
                    r"(\d+\.\d+\.\d+\.\d+)\s+(\d+)", txt):
                metric = int(m.group(3))
                if best is None or metric < best[0]:
                    best = (metric, m.group(1))
        except Exception as e:
            logger.debug("gateway: %s", e)
        gw = best[1] if best else None
        self._gw_cache = (time.time(), gw)
        return gw

    # ---------- классификация ----------

    def classify(self, ip, snmp_info=None, winrm_ok=None):
        if ip and ip == self.gateway_ip():
            return "router"
        if snmp_info:
            descr = (str(snmp_info.get("sysDescr", "")) + " "
                     + str(snmp_info.get("sysName", ""))).lower()
            if "switch" in descr or "catalyst" in descr or "procurve" in descr:
                return "switch"
            if any(k in descr for k in ("router", "mikrotik", "ios ", "juniper")):
                return "router"
            return "infra"
        if winrm_ok:
            return "pc"
        return None

    def set_dtype(self, host_id, dtype, manual=True):
        allowed = {"router", "switch", "server", "pc", "infra", "host", "unknown"}
        if dtype not in allowed:
            return {"ok": False, "error": "тип: " + ", ".join(sorted(allowed))}
        self.svc.db.execute(
            "UPDATE hosts SET dtype = ?, dtype_manual = ? WHERE id = ?",
            (dtype, 1 if manual else 0, host_id))
        return {"ok": True}

    # ---------- опрос ----------

    def scan_infra(self, community=None):
        community = (community or (self.svc.cfg.get("infra") or {})
                     .get("community") or "public")
        hosts = self.svc.inventory.list_hosts()
        results = []
        for h in hosts:
            ip = (h.get("ip") or "").strip()
            if not ip or ip.startswith("127."):
                continue
            hid = h["id"]
            alive = ping(ip)
            snmp = snmp_get(ip, community) if alive else None
            upd = {"online": 1 if alive else 0, "snmp_at": _now_iso()}
            if alive:
                upd["last_seen"] = _now_iso()
            if snmp:
                up = snmp.get("sysUpTime")
                upd.update({
                    "sys_name": str(snmp.get("sysName") or "")[:80],
                    "sys_descr": str(snmp.get("sysDescr") or "")[:200],
                    "uptime_h": round(up / 360000.0, 1) if isinstance(up, int) else None,
                })
            if not h.get("dtype_manual"):
                dtype = self.classify(ip, snmp, winrm_ok=None)
                if dtype:
                    upd["dtype"] = dtype
            sets = ", ".join(f"{k} = ?" for k in upd)
            self.svc.db.execute(f"UPDATE hosts SET {sets} WHERE id = ?",
                                (*upd.values(), hid))
            results.append({"host": h.get("name"), "ip": ip,
                            "alive": alive, "snmp": bool(snmp),
                            "sys_name": upd.get("sys_name"),
                            "uptime_h": upd.get("uptime_h")})
        try:
            self.svc.push_alert(
                "INFRA_SCAN",
                f"Опрос инфраструктуры: {sum(1 for r in results if r['alive'])}"
                f"/{len(results)} живы, SNMP ответили: "
                f"{sum(1 for r in results if r['snmp'])}", "infra", rate=300)
        except Exception:
            pass
        return {"ok": True, "devices": results}

    def device_list(self):
        return self.svc.db.execute(
            """SELECT h.id, h.name, h.ip, h.dtype, h.online, h.health_score,
                      h.sys_name, h.sys_descr, h.uptime_h, h.snmp_at, h.os,
                      (SELECT vendor FROM lan_devices
                       WHERE ip = h.ip AND vendor != '' LIMIT 1) AS vendor
               FROM hosts h
               ORDER BY CASE h.dtype WHEN 'router' THEN 0 WHEN 'switch' THEN 1
                                     WHEN 'server' THEN 2 ELSE 3 END, h.name""",
            fetch=True) or []

    def _wl_match(self, rules, **fields):
        for r in rules or []:
            if not isinstance(r, dict):
                continue
            ok = True
            for k, v in fields.items():
                rv = r.get(k)
                if rv and str(rv).lower() not in str(v).lower():
                    ok = False
                    break
            if ok and any(r.get(k) for k in fields):
                return True
        return False

    def whitelist_match_hidden(self, path):
        wl = (self.svc.cfg.get("ids", {}).get("whitelist") or [])
        return self._wl_match(wl, path=path)

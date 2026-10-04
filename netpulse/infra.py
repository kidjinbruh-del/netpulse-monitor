"""Инфраструктура: роутеры, коммутаторы, серверы.

SNMP v2c GET на чистом stdlib (BER-кодирование вручную) — sysName, sysDescr,
sysUpTime, sysContact, sysLocation, ifNumber. Классификация устройств:
шлюз по умолчанию -> router; SNMP ответил -> switch/router/infra;
WinRM отвечает -> pc (ставит сторож).

v3-реализация: те же функции и контракт Infra(service), типизировано.
service обязан давать .db; опционально .cfg/.inventory/.push_alert,
.profile_thresholds (профили порогов пинга).
"""
from __future__ import annotations

import json
import logging
import re
import socket
import subprocess
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

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

SNMP_PORT = 161
SNMP_TIMEOUT = 2.0
GW_CACHE_SEC = 600


# ---------- BER: кодирование ----------

def ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0x7F]) + out
        n >>= 7
    return bytes([0x80 | len(out)]) + out


def ber_tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + ber_len(len(content)) + content


def ber_int(v: int) -> bytes:
    out = b""
    while True:
        out = bytes([v & 0xFF]) + out
        v >>= 8
        if v == 0:
            break
    if out and out[0] & 0x80:
        out = b"\x00" + out
    return ber_tlv(0x02, out)


def ber_oid(oid: str) -> bytes:
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
    return ber_tlv(0x06, rest)


def ber_octet(s: str) -> bytes:
    return ber_tlv(0x04, s.encode("utf-8", "replace"))


# ---------- BER: разбор ----------

def ber_parse(buf: bytes, pos: int) -> Tuple[int, bytes, int]:
    tag = buf[pos]
    length = buf[pos + 1]
    hlen = 2
    if length & 0x80:
        n = length & 0x7F
        length = int.from_bytes(buf[pos + 2:pos + 2 + n], "big")
        hlen = 2 + n
    content = buf[pos + hlen:pos + hlen + length]
    return tag, content, pos + hlen + length


def oid_decode(content: bytes) -> str:
    if not content:
        return "?"
    first = content[0]
    parts = [first // 40, first % 40]
    value = 0
    for b in content[1:]:
        value = (value << 7) | (b & 0x7F)
        if not b & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(x) for x in parts)


def value_convert(tag: int, raw: bytes) -> Any:
    if tag == 0x04 or tag == 0x16:
        return raw.decode("utf-8", "replace").strip()
    if tag in (0x02, 0x41, 0x43, 0x46, 0x47, 0x48):
        value = 0
        for b in raw:
            value = (value << 8) | b
        return value
    if tag == 0x05:
        return ""
    return raw.hex()


def build_snmp_request(community: str = "public") -> bytes:
    req_id = int(time.time()) & 0x7FFFFFFF
    varbinds = b"".join(ber_tlv(0x30, ber_oid(oid) + ber_tlv(0x05, b""))
                        for oid in OIDS)
    pdu = ber_tlv(0xA0, ber_int(req_id) + ber_int(0) + ber_int(0)
                  + ber_tlv(0x30, varbinds))
    return ber_tlv(0x30, ber_int(1) + ber_octet(community) + pdu)


def parse_snmp_response(data: bytes) -> Optional[Dict[str, Any]]:
    try:
        _, outer, _ = ber_parse(data, 0)
        pos = 0
        _, _, pos = ber_parse(outer, pos)      # version
        _, _, pos = ber_parse(outer, pos)      # community
        ptag, pdu_c, _ = ber_parse(outer, pos)  # response PDU
        if ptag != 0xA2:
            return None
        p = 0
        _, _, p = ber_parse(pdu_c, p)          # request-id
        _, err, p = ber_parse(pdu_c, p)        # error-status
        errv = int.from_bytes(err, "big") if err else 0
        _, _, p = ber_parse(pdu_c, p)          # error-index
        vtag, vblist, _ = ber_parse(pdu_c, p)  # varbind list
        if vtag != 0x30:
            return None
        out: Dict[str, Any] = {}
        q = 0
        while q < len(vblist):
            tag1, c1, q = ber_parse(vblist, q)
            if tag1 != 0x30:
                break
            _, oid_c, q2 = ber_parse(c1, 0)
            vtag2, vraw, _ = ber_parse(c1, q2)
            oid = oid_decode(oid_c)
            if oid in OIDS:
                out[OIDS[oid]] = value_convert(vtag2, vraw)
        if errv:
            out["_error"] = f"SNMP errstatus {errv}"
        return out or None
    except Exception as e:
        logger.debug("SNMP parse: %s", e)
        return None


def snmp_get(
    ip: str, community: str = "public", timeout: float = SNMP_TIMEOUT
) -> Optional[Dict[str, Any]]:
    """SNMP v2c GET по системным OID'ам. Возврат: {sysName: ..., ...} или None."""
    packet = build_snmp_request(community)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (ip, SNMP_PORT))
        data, _ = sock.recvfrom(4096)
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()
    return parse_snmp_response(data)


def ping(ip: str, timeout_ms: int = 800) -> bool:
    cmd = (["ping", "-n", "1", "-w", str(timeout_ms), ip] if sys.platform == "win32"
           else ["ping", "-c", "1", "-W", "1", ip])
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=3,
                                creationflags=flags)
        return result.returncode == 0
    except Exception:
        return False


def ping_ms(ip: str, timeout_ms: int = 800) -> Optional[float]:
    """Замер латентности (миллисекунды) или None."""
    cmd = (["ping", "-n", "1", "-w", str(timeout_ms), ip] if sys.platform == "win32"
           else ["ping", "-c", "1", "-W", "1", ip])
    flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=3,
                                creationflags=flags)
        out = result.stdout.decode("utf-8", "replace")
        m = re.search(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*(?:мс|ms)", out, re.IGNORECASE)
        return float(m.group(1).replace(",", ".")) if m else None
    except Exception:
        return None


# ---------- модуль ----------

def _now_iso() -> str:
    return datetime.now().isoformat()


DTYPE_ALLOWED = {"router", "switch", "server", "pc", "infra", "host", "unknown"}


class Infra:
    def __init__(self, service: Any):
        self.svc = service
        self._ensure_schema()
        self._gw_cache: Tuple[float, Optional[str]] = (0.0, None)

    def _ensure_schema(self) -> None:
        cols = [r["name"] for r in (self.svc.db.execute(
            "PRAGMA table_info(hosts)", fetch=True) or [])]
        if not cols:
            return
        for col, typ in (("dtype", "TEXT"), ("dtype_manual", "INTEGER"),
                         ("sys_name", "TEXT"), ("sys_descr", "TEXT"),
                         ("uptime_h", "REAL"), ("snmp_at", "TEXT")):
            if col not in cols:
                self.svc.db.execute(f"ALTER TABLE hosts ADD COLUMN {col} {typ}")
        self.svc.db.execute(
            """CREATE TABLE IF NOT EXISTS infra_snaps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                host_id INTEGER NOT NULL,
                snapshot TEXT NOT NULL)""")
        self.svc.db.execute(
            "CREATE INDEX IF NOT EXISTS idx_snaps_host ON infra_snaps(host_id)")

    # ---------- снапшоты и diff ----------

    def save_snapshot(self, host_id: int) -> None:
        """Снэпшот SNMP-состояния устройства (для истории изменений)."""
        row = self.svc.db.execute(
            "SELECT name, ip, dtype, sys_name, sys_descr, uptime_h FROM hosts "
            "WHERE id = ?", (host_id,), fetch=True)
        if not row:
            return
        snap = json.dumps(dict(row[0]), ensure_ascii=False, sort_keys=True)
        self.svc.db.execute(
            """INSERT INTO infra_snaps (timestamp, host_id, snapshot)
               VALUES (?,?,?)""",
            (_now_iso(), host_id, snap))

    def snap_diff(
        self, host_id: int, limit: int = 2
    ) -> Dict[str, Any]:
        """Сравнение двух последних снэпшотов: что изменилось."""
        rows = self.svc.db.execute(
            """SELECT timestamp, snapshot FROM infra_snaps
               WHERE host_id = ? ORDER BY id DESC LIMIT ?""",
            (host_id, max(2, int(limit))), fetch=True) or []
        if len(rows) < 2:
            return {"diff": [], "note": "нужно минимум 2 снэпшота"}
        new = json.loads(rows[0]["snapshot"])
        old = json.loads(rows[1]["snapshot"])
        changes = []
        for key in sorted(set(new) | set(old)):
            if new.get(key) != old.get(key):
                changes.append({"field": key, "old": old.get(key),
                                "new": new.get(key)})
        return {"diff": changes,
                "compared": [rows[1]["timestamp"], rows[0]["timestamp"]]}

    def auto_diff(
        self, host_id: int, name: str = "", ip: str = ""
    ) -> None:
        """Авто-сравнение последних двух снапшотов; при расхождении — алерт."""
        try:
            diff = self.snap_diff(host_id, 2)
        except Exception as e:
            logger.debug("auto_diff %s: %s", host_id, e)
            return
        changes = diff.get("diff") or []
        if not changes:
            return
        interesting = [c for c in changes if c["field"] in
                       ("sys_name", "sys_descr", "dtype", "uptime_h")]
        if not interesting:
            return
        # uptime_h стал значительно меньше прошлого -> перезагрузка устройства
        changed = ", ".join(
            f"{c['field']}: {c['old']} -> {c['new']}" for c in interesting[:4])
        try:
            self.svc.push_alert(
                "INFRA_DIFF",
                f"Конфигурация изменилась: {name or ip} — {changed}",
                "infra", rate=600)
        except Exception:
            pass

    def snapshots_list(self, host_id: int) -> List[Dict[str, Any]]:
        return self.svc.db.execute(
            """SELECT timestamp, snapshot FROM infra_snaps
               WHERE host_id = ? ORDER BY id DESC LIMIT 50""",
            (host_id,), fetch=True) or []

    # ---------- шлюз ----------

    def gateway_ip(self) -> Optional[str]:
        ts, gw = self._gw_cache
        if gw and time.time() - ts < GW_CACHE_SEC:
            return gw
        best = None  # (metric, ip)
        try:
            flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
            result = subprocess.run(["route", "print", "0.0.0.0"],
                                    capture_output=True, timeout=6,
                                    creationflags=flags)
            from core.utils import decode_process_output
            txt = decode_process_output(result.stdout or b"")
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

    def classify(
        self,
        ip: str,
        snmp_info: Optional[Dict[str, Any]] = None,
        winrm_ok: Optional[bool] = None,
    ) -> Optional[str]:
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

    def set_dtype(
        self, host_id: int, dtype: str, manual: bool = True
    ) -> Dict[str, Any]:
        if dtype not in DTYPE_ALLOWED:
            return {"ok": False, "error": "тип: " + ", ".join(sorted(DTYPE_ALLOWED))}
        self.svc.db.execute(
            "UPDATE hosts SET dtype = ?, dtype_manual = ? WHERE id = ?",
            (dtype, 1 if manual else 0, host_id))
        return {"ok": True}

    # ---------- опрос ----------

    def scan_infra(self, community: Optional[str] = None) -> Dict[str, Any]:
        community = (community or (self.svc.cfg.get("infra") or {})
                     .get("community") or "public")
        hosts = self.svc.inventory.list_hosts()
        results = []
        for h in hosts:
            ip = (h.get("ip") or "").strip()
            if not ip or ip.startswith("127."):
                continue
            results.append(self._scan_host(h, ip, community))
        try:
            self.svc.push_alert(
                "INFRA_SCAN",
                f"Опрос инфраструктуры: {sum(1 for r in results if r['alive'])}"
                f"/{len(results)} живы, SNMP ответили: "
                f"{sum(1 for r in results if r['snmp'])}", "infra", rate=300)
        except Exception:
            pass
        return {"ok": True, "devices": results}

    def _scan_host(
        self, h: Dict[str, Any], ip: str, community: str
    ) -> Dict[str, Any]:
        hid = h["id"]
        alive = ping(ip)
        snmp = snmp_get(ip, community) if alive else None
        upd: Dict[str, Any] = {"online": 1 if alive else 0, "snmp_at": _now_iso()}
        if alive:
            upd["last_seen"] = _now_iso()
        if snmp:
            uptime = snmp.get("sysUpTime")
            upd.update({
                "sys_name": str(snmp.get("sysName") or "")[:80],
                "sys_descr": str(snmp.get("sysDescr") or "")[:200],
                "uptime_h": round(uptime / 360000.0, 1)
                if isinstance(uptime, int) else None,
            })
        self._check_profile(h, ip, alive)
        if not h.get("dtype_manual"):
            dtype = self.classify(ip, snmp, winrm_ok=None)
            if dtype:
                upd["dtype"] = dtype
        if snmp:
            try:
                self.save_snapshot(hid)
                self.auto_diff(hid, h.get("name"), ip)
            except Exception as e:
                logger.debug("снэпшот %s: %s", ip, e)
        sets = ", ".join(f"{k} = ?" for k in upd)
        self.svc.db.execute(f"UPDATE hosts SET {sets} WHERE id = ?",
                            (*upd.values(), hid))
        return {"host": h.get("name"), "ip": ip,
                "alive": alive, "snmp": bool(snmp),
                "sys_name": upd.get("sys_name"),
                "uptime_h": upd.get("uptime_h")}

    def _check_profile(
        self, h: Dict[str, Any], ip: str, alive: bool
    ) -> None:
        """Профиль порогов для типа устройства: алерт при превышении пинга."""
        if not (alive and h.get("dtype")):
            return
        try:
            prof = self.svc.profile_thresholds(h["dtype"])
            if prof:
                ms = ping_ms(ip)
                if ms is not None and ms > prof["ping_high"]:
                    self.svc.push_alert(
                        "PROFILE_LIMIT",
                        f"{h.get('name') or ip}: пинг {ms:.0f}мс больше "
                        f"профиля {h['dtype']} "
                        f"({prof['ping_high']:.0f}мс)", "infra", rate=1800)
        except Exception:
            pass

    def device_list(self) -> List[Dict[str, Any]]:
        return self.svc.db.execute(
            """SELECT h.id, h.name, h.ip, h.dtype, h.online, h.health_score,
                      h.sys_name, h.sys_descr, h.uptime_h, h.snmp_at, h.os,
                      (SELECT vendor FROM lan_devices
                       WHERE ip = h.ip AND vendor != '' LIMIT 1) AS vendor
               FROM hosts h
               ORDER BY CASE h.dtype WHEN 'router' THEN 0 WHEN 'switch' THEN 1
                                     WHEN 'server' THEN 2 ELSE 3 END, h.name""",
            fetch=True) or []

    @staticmethod
    def match_rules(
        rules: List[Dict[str, Any]], **fields: str
    ) -> bool:
        for rule in rules or []:
            if not isinstance(rule, dict):
                continue
            ok = True
            for key, value in fields.items():
                rule_value = rule.get(key)
                if rule_value and str(rule_value).lower() not in str(value).lower():
                    ok = False
                    break
            if ok and any(rule.get(k) for k in fields):
                return True
        return False

    def whitelist_match_hidden(self, path: str) -> bool:
        wl = (self.svc.cfg.get("ids", {}).get("whitelist") or [])
        return self.match_rules(wl, path=path)

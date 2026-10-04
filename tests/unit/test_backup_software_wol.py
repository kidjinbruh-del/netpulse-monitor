"""Unit: BackupWatch, SoftwareInventory, WolController (фейки, без сети)."""
import os
import sqlite3
import time

import pytest

from netpulse.backupwatch import BackupWatch
from netpulse.softwareinv import SoftwareInventory
from netpulse.wol import WolController, build_packet


class FakeDB:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
            CREATE TABLE hosts (id INTEGER PRIMARY KEY, name TEXT, ip TEXT,
                os TEXT, cpu TEXT, ram_gb REAL, online INTEGER DEFAULT 1,
                health_score INTEGER DEFAULT 100,
                first_seen TEXT, last_seen TEXT, updated_at TEXT);
            CREATE TABLE backup_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT, resource TEXT,
                path TEXT, interval_h INTEGER, last_ok TEXT, ok INTEGER);
            CREATE TABLE journal (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
                source TEXT, host_id INTEGER, user_name TEXT,
                text TEXT, minutes INTEGER);
            CREATE TABLE sw_inventory (
                id INTEGER PRIMARY KEY AUTOINCREMENT, host_id INTEGER,
                name TEXT, version TEXT, publisher TEXT, seen TEXT);
            CREATE TABLE lan_devices (
                mac TEXT, ip TEXT, hostname TEXT, alias TEXT, vendor TEXT,
                first_seen TEXT, last_seen TEXT);
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
                host_id INTEGER, kind TEXT, severity TEXT, source TEXT,
                text TEXT, dedup_key TEXT);
        """)

    def connection(self):
        return self.conn

    def execute(self, sql, params=(), fetch=False):
        cur = self.conn.execute(sql, params)
        self.conn.commit()
        if fetch:
            return [dict(r) for r in cur.fetchall()]
        return cur.rowcount


class FakeSvc:
    def __init__(self, cfg=None):
        self.cfg = cfg or {}
        self.db = FakeDB()
        self.alerts = []
        from netpulse.inventory import Inventory
        self.inventory = Inventory(self)

    def push_alert(self, *a, **k):
        self.alerts.append(a)


# ---------- BackupWatch ----------

def test_backupwatch_fresh_and_stale(tmp_path):
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    (fresh / "b.zip").write_text("x", encoding="utf-8")
    old = tmp_path / "old"
    old.mkdir()
    (old / "b.zip").write_text("x", encoding="utf-8")
    ancient = time.time() - 100 * 3600
    os.utime(old / "b.zip", (ancient, ancient))

    svc = FakeSvc({"backupwatch": {"resources": [
        {"name": "fresh", "path": str(fresh), "interval_h": 24},
        {"name": "old", "path": str(old), "interval_h": 24},
        {"name": "broken", "path": str(tmp_path / "nope"), "interval_h": 24},
    ]}})
    bw = BackupWatch(svc)
    res = bw.check_once()
    assert res["ok"] is True and res["checked"] == 3
    by_name = {r["resource"]: r for r in res["results"]}
    assert by_name["fresh"]["ok"] is True
    assert by_name["old"]["ok"] is False
    assert by_name["broken"]["ok"] is False
    assert len(bw.status_list()) == 3
    assert any(a[0] == "BACKUP_STALE" for a in svc.alerts)


def test_newest_mtime_missing():
    assert BackupWatch.newest_mtime("/definitely/not/here") == 0


# ---------- SoftwareInventory ----------

def test_receive_report_full_cycle():
    svc = FakeSvc()
    si = SoftwareInventory(svc)
    body = {"hostname": "PC-01", "ip": "10.0.0.5", "os": "Win11",
            "cpu": "i7", "ram_gb": 16,
            "software": [{"name": "Chrome", "version": "120", "publisher": "Google"},
                         {"name": "", "version": "x"},
                         "junk",
                         {"name": "7zip", "version": "23"}]}
    res = si.receive_report(body)
    assert res == {"ok": True, "host": "PC-01", "packages": 2}
    assert len(si.for_host(1, 200)) == 2
    assert si.search("chrom")[0]["host"] == "PC-01"
    assert si.stats() == {"hosts": 1, "packages": 2}
    # повторный отчёт заменяет, не дублирует
    si.receive_report({**body, "software": [{"name": "A"}]})
    assert si.stats() == {"hosts": 1, "packages": 1}


def test_receive_report_validation():
    svc = FakeSvc()
    si = SoftwareInventory(svc)
    assert si.receive_report("nope")[0] == 400
    assert si.receive_report({"hostname": "", "software": []})[0] == 400
    assert si.search("") == []


# ---------- WoL ----------

def test_build_packet():
    pkt = build_packet("AA:BB:CC:DD:EE:FF")
    assert len(pkt) == 102
    assert pkt[:6] == b"\xff" * 6
    import pytest as _p
    with _p.raises(ValueError):
        build_packet("bad")


def test_wol_self_and_empty():
    ctl = WolController(FakeSvc())
    assert ctl.wake("") == {"ok": False, "error": "нужен host"}
    assert ctl.wake("127.0.0.1")["self"] is True


def test_wol_from_db(monkeypatch):
    svc = FakeSvc()
    svc.db.execute(
        "INSERT INTO lan_devices (mac, ip) VALUES (?,?)",
        ("aa:bb:cc:dd:ee:ff", "10.0.0.9"))
    sent = []
    import netpulse.wol as wol_mod
    monkeypatch.setattr(wol_mod, "send_wol", lambda mac, **k: sent.append(mac))
    res = WolController(svc).wake("10.0.0.9")
    assert res == {"ok": True, "mac": "aa:bb:cc:dd:ee:ff", "host": "10.0.0.9"}
    assert sent == ["aa:bb:cc:dd:ee:ff"]


def test_wol_unknown_host():
    ctl = WolController(FakeSvc())
    res = ctl.wake("10.255.255.253")
    assert res["ok"] is False and "MAC" in res["error"]

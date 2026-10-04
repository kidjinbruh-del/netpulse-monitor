"""Unit: ParkWatchdog (правила, прогноз, resolve) — без powershell/сети."""
import sqlite3
from datetime import datetime, timedelta

import pytest

from netpulse.watchdog import ParkWatchdog


class FakeDB:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
            CREATE TABLE hosts (id INTEGER PRIMARY KEY, name TEXT, ip TEXT,
                os TEXT, online INTEGER DEFAULT 1, health_score INTEGER DEFAULT 100,
                dtype TEXT, dtype_manual INTEGER DEFAULT 0,
                first_seen TEXT, last_seen TEXT, updated_at TEXT);
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
                host_id INTEGER, kind TEXT, severity TEXT, source TEXT,
                text TEXT, dedup_key TEXT);
            CREATE TABLE disk_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
                host_id INTEGER, drive TEXT, free_gb REAL, total_gb REAL);
            CREATE TABLE lan_devices (
                mac TEXT, ip TEXT, hostname TEXT, alias TEXT, vendor TEXT,
                first_seen TEXT, last_seen TEXT);
        """)

    def connection(self):
        return self.conn

    def execute(self, sql, params=(), fetch=False):
        cur = self.conn.execute(sql, params)
        self.conn.commit()
        if fetch:
            return [dict(r) for r in cur.fetchall()]
        return cur.rowcount

    def execute_many(self, sql, rows):
        self.conn.executemany(sql, rows)
        self.conn.commit()


class FakeSvc:
    def __init__(self, cfg=None):
        self.cfg = cfg or {}
        self.db = FakeDB()
        self.alerts = []
        from netpulse.inventory import Inventory
        self.inventory = Inventory(self)

    def push_alert(self, *a, **k):
        self.alerts.append(a)


def _svc(**watchdog_cfg):
    base = {"enabled": True, "interval_min": 15, "timeout_sec": 5,
            "hosts": [], "disk_free_pct": 10, "ram_free_mb": 500,
            "event_ids": [41, 6008], "event_hours": 24,
            "offline_after_polls": 3}
    base.update(watchdog_cfg)
    return FakeSvc({"watchdog": base})


def _data(**kw):
    d = {"host": "pc1", "os": "Win11", "disks": [], "errors": [],
         "smart": [], "ramFreeMB": 4000}
    d.update(kw)
    return d


def test_apply_rules_disk_ram_event_smart():
    svc = _svc()
    wd = ParkWatchdog(svc)
    hid = svc.inventory.upsert_host("pc1")
    data = _data(disks=[{"drive": "C:", "free": 5, "total": 100}],
                 ramFreeMB=100,
                 errors=[{"id": 41, "text": "reboot"}],
                 smart=[{"reason": "heat"}])
    n = wd.apply_rules("pc1", hid, data)
    assert n == 4
    kinds = {e["kind"] for e in svc.inventory.recent_events()}
    assert kinds == {"disk", "ram", "eventlog", "smart"}
    # повтор — дедупликация, новых событий нет
    assert wd.apply_rules("pc1", hid, data) == 4
    assert len(svc.inventory.recent_events()) == 4


def test_apply_rules_healthy():
    svc = _svc()
    wd = ParkWatchdog(svc)
    hid = svc.inventory.upsert_host("pc1")
    data = _data(disks=[{"drive": "C:", "free": 50, "total": 100}],
                 errors=[{"id": 999, "text": "other"}])
    assert wd.apply_rules("pc1", hid, data) == 0


def test_disk_forecast():
    svc = _svc()
    wd = ParkWatchdog(svc)
    hid = svc.inventory.upsert_host("pc1")
    now = datetime.now()
    for i in range(5):
        ts = (now - timedelta(days=4 - i)).isoformat()
        svc.db.execute(
            "INSERT INTO disk_history (timestamp, host_id, drive, free_gb, total_gb)"
            " VALUES (?,?,?,?,?)", (ts, hid, "C:", 100 - i * 10, 200))
    out = wd.disk_forecast(window_days=7)
    assert len(out) == 1
    assert out[0]["drive"] == "C:"
    assert out[0]["rate_gb_day"] == -10.0
    assert out[0]["days_left"] == 6  # 60 GB / 10 в день


def test_disk_forecast_static_skipped():
    svc = _svc()
    wd = ParkWatchdog(svc)
    hid = svc.inventory.upsert_host("pc1")
    now = datetime.now()
    for i in range(3):
        ts = (now - timedelta(days=2 - i)).isoformat()
        svc.db.execute(
            "INSERT INTO disk_history (timestamp, host_id, drive, free_gb, total_gb)"
            " VALUES (?,?,?,?,?)", (ts, hid, "D:", 150, 200))
    assert wd.disk_forecast(window_days=7) == []


def test_resolve_hosts_explicit_and_auto():
    svc = _svc(hosts=["10.0.0.9"])
    wd = ParkWatchdog(svc)
    assert wd.resolve_hosts(wd._cfg()) == ["10.0.0.9"]
    svc2 = _svc(hosts=["auto"])
    wd2 = ParkWatchdog(svc2)
    svc2.inventory.upsert_host("pc1", "10.0.0.5")
    hosts = wd2.resolve_hosts(wd2._cfg())
    assert "pc1" in hosts and "10.0.0.5" in hosts
    assert not any(h.startswith("127.") for h in hosts)


def test_status():
    wd = ParkWatchdog(_svc())
    st = wd.status()
    assert st["enabled"] is True and st["running"] is False
    assert st["interval_min"] == 15

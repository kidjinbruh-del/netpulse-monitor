"""Unit: Inventory (карма, события, хосты) на in-memory SQLite."""
import sqlite3
from datetime import datetime, timedelta

import pytest

from netpulse.inventory import Inventory, SEVERITY_WEIGHT

SCHEMA = """
CREATE TABLE hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT, ip TEXT, os TEXT, online INTEGER DEFAULT 1,
    health_score INTEGER DEFAULT 100,
    first_seen TEXT, last_seen TEXT, updated_at TEXT);
CREATE TABLE events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT, host_id INTEGER, kind TEXT, severity TEXT,
    source TEXT, text TEXT, dedup_key TEXT);
CREATE TABLE karma_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT, host_id INTEGER, score INTEGER);
CREATE TABLE journal (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT, source TEXT, host_id INTEGER,
    user_name TEXT, text TEXT, minutes INTEGER);
"""


class FakeDB:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def connection(self):
        return self.conn

    def execute(self, sql, params=(), fetch=False):
        cur = self.conn.execute(sql, params)
        self.conn.commit()
        if fetch:
            return [dict(r) for r in cur.fetchall()]
        return cur.rowcount


class FakeSvc:
    def __init__(self):
        self.db = FakeDB()
        self.alerts = []

    def push_alert(self, *a, **k):
        self.alerts.append(a)


@pytest.fixture()
def inv():
    return Inventory(FakeSvc())


def test_upsert_and_resolve(inv):
    hid = inv.upsert_host("pc1", "10.0.0.1", "Win11")
    assert hid == 1
    assert inv.resolve_host_id("pc1") == 1
    assert inv.resolve_host_id("10.0.0.1") == 1
    # повторный upsert обновляет, не дублирует
    assert inv.upsert_host("pc1", "10.0.0.2") == 1
    assert len(inv.list_hosts()) == 1
    assert inv.list_hosts()[0]["ip"] == "10.0.0.2"
    assert inv.upsert_host("") is None
    assert inv.resolve_host_id("") is None


def test_mark_online(inv):
    hid = inv.upsert_host("pc1")
    inv.mark_online(hid, False)
    assert inv.list_hosts()[0]["online"] == 0


def test_host_detail(inv):
    assert inv.host_detail("bad") == {"error": "нужен числовой id"}
    assert inv.host_detail(999) == {"error": "машина не найдена"}
    hid = inv.upsert_host("pc1")
    d = inv.host_detail(hid)
    assert d["name"] == "pc1" and d["events"] == [] and d["journal"] == []


def test_note_event_dedup(inv):
    svc = inv.svc
    hid = inv.upsert_host("pc1")
    r1 = inv.note_event(hid, "disk", "HIGH", "watchdog", "low disk", dedup_key="k1")
    assert r1 == {"ok": True}
    r2 = inv.note_event(hid, "disk", "HIGH", "watchdog", "low disk", dedup_key="k1")
    assert r2 == {"ok": True, "dedup": True}
    assert len(inv.recent_events()) == 1
    assert len(svc.alerts) == 1  # алерт только за первое
    # неизвестная severity → MEDIUM
    inv.note_event(hid, "x", "WEIRD", "s", "t")
    assert inv.recent_events()[0]["severity"] == "MEDIUM"


def test_karma_decay_and_weights(inv):
    hid = inv.upsert_host("pc1")
    now = datetime.now()
    old = (now - timedelta(days=89)).isoformat()
    inv.svc.db.execute(
        "INSERT INTO events (timestamp, host_id, kind, severity, source, text)"
        " VALUES (?,?,?,?,?,?)",
        (old, hid, "old", "CRITICAL", "t", "t"))
    inv.svc.db.execute(
        "INSERT INTO events (timestamp, host_id, kind, severity, source, text)"
        " VALUES (?,?,?,?,?,?)",
        (now.isoformat(), hid, "new", "LOW", "t", "t"))
    res = inv.recompute_health()
    assert res == {"ok": True, "hosts": 1}
    # CRITICAL 89 дней назад: вес 8 * (1 - 89/90) ≈ 0.09; LOW свежий: 1
    score = inv.list_hosts()[0]["health_score"]
    assert score == 99
    assert inv.karma_history(hid) == [99]
    assert inv.worst_hosts(5)[0]["name"] == "pc1"


def test_score_static():
    assert Inventory._score_for_penalties([(8, 0)]) == 92
    assert Inventory._score_for_penalties([(8, 45)]) == 96
    assert Inventory._score_for_penalties([(100, 0)]) == 0
    assert Inventory._score_for_penalties([]) == 100

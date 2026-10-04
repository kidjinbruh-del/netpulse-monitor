"""Unit: Healing, CustomChecks, geo, CVEChecker (фейки, без сети)."""
import sqlite3

import pytest

from netpulse import geo
from netpulse.cve import CVEChecker
from netpulse.customchecks import CustomChecks
from netpulse.healing import Healing


class FakeDB:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
            CREATE TABLE sw_cve (
                id INTEGER PRIMARY KEY AUTOINCREMENT, product TEXT,
                version TEXT, cve TEXT, severity TEXT, summary TEXT,
                checked_at TEXT, UNIQUE(product, version, cve));
            CREATE TABLE sw_inventory (
                id INTEGER PRIMARY KEY, host_id INTEGER, name TEXT);
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
        self.journal_entries = []
        self.executed = []

    def push_alert(self, *a, **k):
        pass

    class _Journal:
        def __init__(self, outer):
            self.outer = outer

        def add(self, **kw):
            self.outer.journal_entries.append(kw)
            return {"ok": True}

    class _Runbooks:
        def __init__(self, outer):
            self.outer = outer

        def execute(self, rb, params, actor="x"):
            self.outer.executed.append((rb, params, actor))
            return {"ok": True}

    @property
    def journal(self):
        return FakeSvc._Journal(self)

    @property
    def runbooks(self):
        return FakeSvc._Runbooks(self)


# ---------- Healing ----------

def _healing_svc(rules):
    return FakeSvc({"healing": {"enabled": True, "rules": rules}})


def test_healing_disabled_by_default():
    h = Healing(FakeSvc())
    h.on_event(1, "disk", "HIGH")
    assert h.status_list() == {"enabled": False, "rules": []}


def test_healing_fires_and_rate_limits():
    svc = _healing_svc([{"on_event": "disk", "runbook": "cleanup",
                         "max_per_hour": 1}])
    h = Healing(svc)
    h.on_event(1, "disk", "HIGH", "pc1")
    h.on_event(1, "disk", "HIGH", "pc1")  # второй за час — отсечён
    assert len(svc.executed) == 1
    assert svc.executed[0] == ("cleanup", {"host": "pc1"}, "healing")
    assert len(svc.journal_entries) == 1
    st = h.status_list()
    assert st["enabled"] is True
    assert st["rules"][0]["runbook"] == "cleanup"
    # legacy-семантика: last_run виден только для запусков без хоста
    assert st["rules"][0]["last_run"] is None
    h2 = Healing(_healing_svc([{"on_event": "disk", "runbook": "rb"}]))
    h2.on_event(1, "disk", "HIGH")  # без host_name
    assert h2.status_list()["rules"][0]["last_run"] is not None


def test_healing_skips():
    svc = _healing_svc([
        {"on_event": "disk", "runbook": "rb", "confirm": True},
        {"on_event": "other", "runbook": "rb2"},
    ])
    h = Healing(svc)
    h.on_event(1, "disk", "HIGH")   # confirm → пропуск
    h.on_event(1, "disk", "LOW")    # LOW → пропуск
    h.on_event(1, "nomatch", "HIGH")
    assert svc.executed == []


# ---------- CustomChecks ----------

def test_customchecks_run_and_cache(tmp_path):
    d = tmp_path / "checks"
    d.mkdir()
    (d / "ok_check.py").write_text(
        'NAME = "OK"\nINTERVAL_MIN = 60\ndef run():\n    return {"ok": True, "text": "fine"}\n',
        encoding="utf-8")
    (d / "fail_check.py").write_text(
        'def run():\n    raise RuntimeError("boom")\n',
        encoding="utf-8")
    (d / "broken.py").write_text("def broken(:\n", encoding="utf-8")
    cc = CustomChecks(FakeSvc(), checks_dir=str(d))
    assert cc.load()["count"] == 2
    res = cc.run_all(force=True)
    assert res["ok"] is True
    by_name = {r["name"]: r for r in res["results"]}
    assert by_name["OK"]["ok"] is True and by_name["OK"]["text"] == "fine"
    assert by_name["fail_check"]["ok"] is False
    assert "boom" in by_name["fail_check"]["text"]
    # повтор без force — из кэша, без повторного запуска
    res2 = cc.run_all()
    assert [r["name"] for r in res2["results"]] == [r["name"] for r in res["results"]]
    assert cc.results()["count"] == 2


# ---------- geo ----------

def test_geo_country():
    assert geo.country("192.168.1.1") == "Локальная сеть"
    assert geo.country("127.0.0.1") == "Служебная"
    assert geo.country("185.165.29.5") == "Россия"
    assert geo.country("8.8.8.8") == "?"
    assert geo.country("bad") == "?"
    assert geo.country("") == "?"


def test_geo_top_and_flag():
    top = geo.top_countries([{"ip": "192.168.0.1"}, "185.165.29.5", "8.8.8.8"])
    assert top[0] == ("Локальная сеть", 1)
    assert geo.flag("Локальная сеть") == "●"
    assert geo.flag("Россия") == "🌐"


# ---------- CVE ----------

def test_cve_status_empty():
    st = CVEChecker(FakeSvc()).status()
    assert st == {"found": 0, "last": None}


def test_cve_cache_hit_no_network():
    svc = FakeSvc()
    svc.db.execute(
        "INSERT INTO sw_cve (product, version, cve, severity, summary, checked_at)"
        " VALUES (?,?,?,?,?,?)",
        ("Chrome", "120", "CVE-2024-1", "HIGH", "desc", "2024-01-01"))
    checker = CVEChecker(svc)
    found = checker.check_products([("Chrome", "120")])
    assert found == [{"cve": "CVE-2024-1", "severity": "HIGH",
                      "summary": "desc", "checked_at": "2024-01-01",
                      "product": "Chrome"}]
    assert checker.status()["found"] == 1

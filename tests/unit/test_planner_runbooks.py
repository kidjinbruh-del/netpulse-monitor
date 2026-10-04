"""Unit: Planner + RunbookRunner (фейковый service, без powershell)."""
import json
import sqlite3

import pytest

from netpulse.planner import Planner
from netpulse.runbooks import RunbookRunner


class FakeDB:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
            CREATE TABLE hosts (id INTEGER PRIMARY KEY, name TEXT, ip TEXT);
            CREATE TABLE planner_state (name TEXT PRIMARY KEY, last_done TEXT);
            CREATE TABLE journal (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
                source TEXT, host_id INTEGER, user_name TEXT,
                text TEXT, minutes INTEGER);
            CREATE TABLE runbook_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
                runbook TEXT, params TEXT, actor TEXT, target TEXT,
                exit_code INTEGER, output TEXT);
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
        from netpulse.journal import WorkJournal
        self.journal = WorkJournal(self)

    def push_alert(self, *a, **k):
        self.alerts.append(a)


@pytest.fixture()
def planner():
    svc = FakeSvc({"planner": {"enabled": True, "tasks": [
        {"name": "toner", "every_days": 14},
        {"name": "ups", "every_days": 30},
    ]}})
    return Planner(svc)


def test_planner_status_and_done(planner):
    statuses = planner.status_list()
    assert len(statuses) == 2
    assert all(s["due"] for s in statuses)  # ни разу не выполнялись
    res = planner.mark_done("toner", actor="tester")
    assert res["ok"] is True
    statuses = {s["name"]: s for s in planner.status_list()}
    assert statuses["toner"]["due"] is False
    assert statuses["toner"]["days_left"] == 14
    assert statuses["ups"]["due"] is True
    # журнал записан
    entries = planner.svc.journal.list_entries()
    assert any("toner" in e["text"] for e in entries)


def test_planner_unknown_task(planner):
    assert planner.mark_done("nope") == {
        "ok": False, "error": "задача не найдена в planner.tasks"}


def test_planner_check_alerts(planner):
    planner.check_alerts()
    kinds = [a[0] for a in planner.svc.alerts]
    assert "PLANNER_DUE" in kinds


def _runner_with_defs(tmp_path, monkeypatch, defs):
    import netpulse.runbooks as rb_mod
    rb_dir = tmp_path / "rb"
    rb_dir.mkdir()
    for d in defs:
        (rb_dir / f"{d['id']}.json").write_text(
            json.dumps(d), encoding="utf-8")
    monkeypatch.setattr(rb_mod, "RB_DIR", str(rb_dir))
    return RunbookRunner(FakeSvc())


def test_runbook_list_and_validation(tmp_path, monkeypatch):
    runner = _runner_with_defs(tmp_path, monkeypatch, [{
        "id": "demo", "name": "Demo", "scope": "local",
        "command": "echo {host}",
        "params": [{"name": "host", "required": True}],
    }])
    assert [r["id"] for r in runner.list()] == ["demo"]
    assert runner.execute("missing") == {"ok": False, "error": "runbook не найден"}
    bad = runner.execute("demo", {"host": "a;b"})
    assert bad["ok"] is False and "недопустимый" in bad["error"]
    missing = runner.execute("demo", {})
    assert missing["ok"] is False and "не хватает" in missing["error"]
    extra = runner.execute("demo", {"host": "pc1", "zzz": "1"})
    assert extra["ok"] is False and "лишние" in extra["error"]


def test_runbook_execute_local(tmp_path, monkeypatch):
    import subprocess
    runner = _runner_with_defs(tmp_path, monkeypatch, [{
        "id": "demo", "name": "Demo", "scope": "local",
        "command": "echo hello",
        "params": [],
    }])

    class FakeProc:
        returncode = 0
        stdout = "hello".encode()
        stderr = b""

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc())
    res = runner.execute("demo", {}, actor="tester")
    assert res["ok"] is True and res["exit_code"] == 0
    assert res["output"] == "hello"
    log = runner.recent_log()
    assert len(log) == 1 and log[0]["actor"] == "tester"


def test_runbook_remote_needs_host(tmp_path, monkeypatch):
    runner = _runner_with_defs(tmp_path, monkeypatch, [{
        "id": "rem", "name": "Rem", "scope": "remote",
        "command": "Restart-Service X",
        "params": [],
    }])
    res = runner.execute("rem", {})
    assert res == {"ok": False, "error": "для remote нужен host"}

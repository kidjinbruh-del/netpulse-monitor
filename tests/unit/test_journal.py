"""Unit: WorkJournal на in-memory SQLite (фейковый service)."""
import sqlite3

import pytest

from netpulse.journal import WorkJournal


class FakeDB:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
            CREATE TABLE hosts (id INTEGER PRIMARY KEY, name TEXT, ip TEXT);
            CREATE TABLE journal (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT, source TEXT, host_id INTEGER,
                user_name TEXT, text TEXT, minutes INTEGER);
            INSERT INTO hosts (id, name) VALUES (1, 'pc1');
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
    def __init__(self):
        self.db = FakeDB()
        from netpulse.inventory import Inventory
        self.inventory = Inventory(self)


@pytest.fixture()
def journal():
    return WorkJournal(FakeSvc())


def test_add_and_list(journal):
    r = journal.add("test entry", source="manual", user_name="tester", minutes=5)
    assert r["ok"] is True and r["id"] == 1
    entries = journal.list_entries()
    assert len(entries) == 1
    assert entries[0]["text"] == "test entry"
    assert entries[0]["minutes"] == 5


def test_add_empty_rejected(journal):
    assert journal.add("   ") == {"ok": False, "error": "пустой текст записи"}


def test_add_with_host_resolves_id(journal):
    r = journal.add("visit", host="pc1")
    assert r["ok"] is True
    entries = journal.list_entries()
    assert entries[0]["host"] == "pc1"


def test_delete(journal):
    journal.add("bye")
    assert journal.delete(1) == {"ok": True, "deleted": 1}
    assert journal.list_entries() == []
    assert journal.delete("bad") == {"ok": False, "error": "нужен числовой id"}


def test_list_filters(journal):
    journal.add("one", source="manual")
    journal.add("two", source="chat", user_name="bob")
    assert len(journal.list_entries(source="chat")) == 1
    assert len(journal.list_entries(q="bob")) == 1
    assert len(journal.list_entries(q="zzz")) == 0


def test_month_report(journal):
    journal.add("work", user_name="ann", minutes=60)
    rep = journal.month_report(30)
    assert rep["entries"] == 1
    assert rep["minutes"] == 60
    assert rep["hours"] == 1.0
    assert rep["by_source"][0]["source"] == "manual"

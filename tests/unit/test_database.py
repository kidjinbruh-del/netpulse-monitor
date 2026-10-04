"""Unit: DatabaseManager (пул, схема, cleanup, close-гонка)."""
from core.database import DatabaseManager


def test_init_and_tables(tmp_path):
    db = DatabaseManager(str(tmp_path / "t.db"), pool_size=2)
    tables = {r["name"] for r in
              db.execute("SELECT name FROM sqlite_master WHERE type='table'",
                         fetch=True)}
    for t in ("traffic", "pings", "traces", "alerts", "hosts", "events",
              "journal", "runbook_log", "backup_status"):
        assert t in tables
    m = db.get_metrics()
    assert m["pool_max"] == 2 and m["queries"] >= 1
    db.close()


def test_execute_insert_fetch(tmp_path):
    db = DatabaseManager(str(tmp_path / "t.db"), pool_size=1)
    n = db.execute("INSERT INTO alerts (timestamp, alert_type) VALUES (?,?)",
                   ("2024-01-01", "X"))
    assert n == 1  # rowcount
    rows = db.execute("SELECT alert_type FROM alerts", fetch=True)
    assert rows == [{"alert_type": "X"}]
    db.close()


def test_execute_many(tmp_path):
    db = DatabaseManager(str(tmp_path / "t.db"), pool_size=1)
    assert db.execute_many(
        "INSERT INTO alerts (timestamp) VALUES (?)",
        [("a",), ("b",)]) is True
    assert db.execute_many("INSERT INTO alerts (timestamp) VALUES (?)", []) is False
    rows = db.execute("SELECT COUNT(*) AS n FROM alerts", fetch=True)
    assert rows[0]["n"] == 2
    db.close()


def test_cleanup_old_records(tmp_path):
    db = DatabaseManager(str(tmp_path / "t.db"), pool_size=1)
    db.execute("INSERT INTO alerts (timestamp) VALUES (?)",
               ("2000-01-01T00:00:00",))
    db.execute("INSERT INTO alerts (timestamp) VALUES (?)",
               ("2999-01-01T00:00:00",))
    assert db.cleanup_old_records(days=30) is True
    rows = db.execute("SELECT timestamp FROM alerts", fetch=True)
    assert [r["timestamp"] for r in rows] == ["2999-01-01T00:00:00"]
    db.close()


def test_closed_race_silent(tmp_path):
    db = DatabaseManager(str(tmp_path / "t.db"), pool_size=1)
    db.close()
    assert db.execute("SELECT 1", fetch=True) is None
    assert db.execute_many("SELECT 1", [(1,)]) is False
    assert db.cleanup_old_records() is False
    db.close()  # двойное закрытие — без исключений


def test_connection_context(tmp_path):
    db = DatabaseManager(str(tmp_path / "t.db"), pool_size=1)
    with db.connection() as conn:
        conn.execute("INSERT INTO alerts (timestamp) VALUES ('x')")
        conn.commit()
    rows = db.execute("SELECT COUNT(*) AS n FROM alerts", fetch=True)
    assert rows[0]["n"] == 1
    db.close()

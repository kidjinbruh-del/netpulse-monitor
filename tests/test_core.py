"""
Тесты ядра: БД, парсеры, сниффер, AI, пингер, graceful shutdown.
Работают и через pytest, и напрямую: python -m tests.test_core
"""

import os
import sys
import tempfile
import time
import random
import logging

from core import DatabaseManager, Pinger, Sniffer, Tracer
from core.utils import parse_ping_output, parse_trace_output, decode_process_output
from ai import AIOrchestrator

logging.getLogger().setLevel(logging.CRITICAL)


def _fresh_cwd():
    tmp = tempfile.mkdtemp()
    os.chdir(tmp)
    return tmp


# ---------- База данных ----------

def test_db_clean_init_no_warnings():
    _fresh_cwd()
    records = []

    class Cap(logging.Handler):
        def emit(self, r):
            records.append(r.getMessage())

    logging.getLogger("core.database").addHandler(Cap())
    logging.getLogger("core.database").setLevel(logging.WARNING)

    db = DatabaseManager(db_path="t.db")
    bad = [m for m in records if "no such" in m or "ERROR" in m]
    assert not bad, f"шум при инициализации: {bad}"
    db.close()


def test_db_migration_old_schema():
    """Старая схема (без jitter/target/deltas) должна мигрировать автоматически"""
    _fresh_cwd()
    db = DatabaseManager(db_path="t.db")
    db.execute("DROP TABLE pings")
    db.execute("CREATE TABLE pings (id INTEGER PRIMARY KEY, timestamp TEXT, ping_ms REAL, loss INTEGER)")
    db.execute("DROP TABLE traffic")
    db.execute("""CREATE TABLE traffic (id INTEGER PRIMARY KEY, timestamp TEXT,
                  speed REAL, bytes_in INTEGER, bytes_out INTEGER)""")
    db.close()

    db2 = DatabaseManager(db_path="t.db")
    cols_p = [r["name"] for r in db2.execute("PRAGMA table_info(pings)", fetch=True)]
    cols_t = [r["name"] for r in db2.execute("PRAGMA table_info(traffic)", fetch=True)]
    assert "jitter" in cols_p and "target" in cols_p, cols_p
    assert "bytes_in_delta" in cols_t and "anomaly_score" in cols_t, cols_t
    db2.close()


def test_db_localtime_filters():
    """Свежие записи должны попадать в окно 'последний час' (проверка localtime-фикса)"""
    _fresh_cwd()
    db = DatabaseManager(db_path="t.db")
    from datetime import datetime
    now_iso = datetime.now().isoformat()
    db.execute(
        "INSERT INTO traffic (timestamp, speed) VALUES (?, ?)", (now_iso, 123.0))
    rows = db.execute(
        """SELECT speed FROM traffic WHERE timestamp > datetime('now','localtime','-1 hour')""",
        fetch=True)
    assert rows and abs(rows[0]["speed"] - 123.0) < 0.01
    db.close()


def test_db_user_version():
    _fresh_cwd()
    db = DatabaseManager(db_path="t.db")
    ver = db.execute("PRAGMA user_version", fetch=True)
    assert ver and ver[0]["user_version"] >= 1
    db.close()


# ---------- Парсеры ----------

def test_parse_ping_russian():
    ms, loss = parse_ping_output("Ответ от 8.8.8.8: число байт=32 время=23мс TTL=118")
    assert ms == 23.0 and not loss


def test_parse_ping_english_timeout():
    ms, loss = parse_ping_output("Request timed out.")
    assert loss


def test_parse_ping_mojibake_oem():
    """Реальный вывод ping.exe в cp866, ошибочно декодированный как latin-1,
    должен парситься по цифрам (регрессия: 100% ложных потерь)"""
    raw = "Ответ от 8.8.8.8: число байт=32 время=25мс TTL=107".encode("cp866")
    out = decode_process_output(raw)
    ms, loss = parse_ping_output(out)
    assert not loss and ms == 25.0


def test_parse_trace_skips_header_target():
    """Первый IP в заголовке трассировки - сама цель; хопы должны её игнорировать"""
    out = ("Трассировка маршрута к 8.8.8.8 с максимум 30 прыжками\n"
           "  1    1ms  192.168.1.1\n"
           "  2   10ms  100.64.0.1")
    ip, _ = parse_trace_output(out, target="8.8.8.8")
    assert ip == "192.168.1.1"
    # Достижение цели: только она одна во всём выводе
    ip2, _ = parse_trace_output("Трассировка к 1.1.1.1...\nОтвет от 1.1.1.1: время=9мс", target="1.1.1.1")
    assert ip2 == "1.1.1.1"


# ---------- Сниффер ----------

def test_sniffer_record_and_split_speeds():
    sn = Sniffer()
    now = time.time()
    for i in range(5):
        sn._record_traffic(10_000, 1_000, now - i)
        with sn.lock:
            sn._updown.append((now - i, 10_000, 1_000))
    stats = sn.get_stats()
    assert stats["bytes_in"] == 50_000 and stats["bytes_out"] == 5_000
    down, up = sn.get_speed_split()
    assert down > 0 and up > 0 and down > up


def test_sniffer_ip_cap():
    sn = Sniffer()
    for i in range(1200):
        with sn.lock:
            sn.stats["ips"][f"1.2.3.{i}"]["bytes"] = i
            sn.stats["ips"][f"1.2.3.{i}"]["packets"] = 1
    sn._cleanup_old_ips()
    assert len(sn.stats["ips"]) <= 500


def test_sniffer_top_ips_hidden_not_in_real_mode():
    sn = Sniffer()
    sn.mode = "psutil"
    assert sn.get_top_ips() == []


# ---------- AI ----------

def _hist(n=60):
    return [{"speed": random.gauss(100, 20),
             "bytes_in": random.gauss(5000, 1000),
             "ping_ms": random.gauss(30, 5)} for _ in range(n)]


def test_ai_train_analyze_feature_consistency():
    orch = AIOrchestrator(config={"features": ["speed", "bytes_in", "ping_ms"],
                                  "anomaly_threshold": 0.6})
    hist = _hist()
    assert orch.train_model(hist)
    # Лишние ключи не должны ломать анализ (раньше падал scaler.transform)
    r = orch.process_traffic_data({"speed": 100, "bytes_in": 5000, "ping_ms": 30,
                                   "jitter": 9, "loss": 0})
    assert "score" in r["analysis"]


def test_ai_background_training_with_provider():
    hist = _hist()
    orch = AIOrchestrator(config={}, data_provider=lambda: hist)
    orch.start_background_training(interval=1)
    time.sleep(1.5)
    assert orch.traffic_agent.stats["model_trained"], "фоновое обучение не отработало"
    orch.stop()
    time.sleep(0.2)


# ---------- Пингер ----------

def test_pinger_alert_threshold_and_spam_guard():
    alerts = []
    p = Pinger(target="127.0.0.1",
               alert_thresholds={"ping_high": 10},
               alert_callback=lambda t, m: alerts.append((t, m)))
    p._check_alerts(200, False)
    p._check_alerts(200, False)
    p._check_alerts(20, False)
    assert len(alerts) == 1, f"ожидался 1 алерт, получено {len(alerts)}"
    assert alerts[0][0] == "ВЫСОКИЙ ПИНГ"


def test_pinger_set_target_live():
    p = Pinger(target="8.8.8.8")
    p.set_target("1.1.1.1")
    assert p.target == "1.1.1.1"
    p.set_target("")
    assert p.target == "1.1.1.1"


# ---------- Tracer ----------

def test_tracer_parse_helpers():
    ip, ms = parse_trace_output("Ответ от 93.184.216.34: число байт=32 время=45мс")
    assert ip == "93.184.216.34" and ms == 45.0


# ---------- Runner ----------

ALL_TESTS = [v for k, v in sorted(globals().items()) if k.startswith("test_")]


def run_all():
    passed, failed = 0, []
    start = time.time()
    cwd = os.getcwd()
    for fn in ALL_TESTS:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
            passed += 1
        except Exception as e:
            failed.append((fn.__name__, e))
            print(f"  FAIL {fn.__name__}: {e}")
        os.chdir(cwd)
    dt = time.time() - start
    print(f"\n{passed}/{len(ALL_TESTS)} тестов прошло за {dt:.1f}с")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    run_all()

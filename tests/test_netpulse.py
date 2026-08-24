"""
Тесты NetPulse v2: конфиг, качество, сервер+auth, сканер портов, IDS, квоты, бэкапы.
Запуск: python -m tests.test_netpulse
"""

import os
import sys
import json
import time
import copy
import socket
import threading
import tempfile
import urllib.request

from netpulse.config import load_config, merge_updates
from netpulse.services import quality_score


def test_config_merge():
    cfg = load_config()
    assert isinstance(cfg["quota"], dict) and "web_auth_enabled" in cfg
    merge_updates(cfg, {"quality": {"good_ping_ms": 30}})
    assert cfg["quality"]["good_ping_ms"] == 30


def test_quality_scoring():
    q = {"good_ping_ms": 50, "warn_ping_ms": 120, "max_jitter_ms": 15, "max_loss_pct": 2}
    assert quality_score(20, 2, 0, q) >= 95
    mid = quality_score(100, 5, 1, q)
    assert 55 <= mid <= 90, mid
    bad = quality_score(400, 40, 15, q)
    assert bad <= 25, bad


def test_portscanner_local_open_port():
    from netpulse.services import PortScanner
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(5)
    try:
        result = PortScanner.tcp_scan("127.0.0.1", ports=[port, 9, 9998], timeout=0.4)
        open_ports = [p["port"] for p in result["open"]]
        assert port in open_ports, result
    finally:
        srv.close()


def test_ids_dedup_and_rate():
    """push_alert с rate=0 пишет каждый раз, дедуп в ленте работает"""
    class FakeDB:
        def execute(self, *a, **k):
            return None
    class FakeSvc:
        cfg = {}
        db = FakeDB()
        def __init__(self):
            self.alerts = []
            self.live = []
            self._alert_rl = {}
        def push_alert(self, t, m, s, rate=0):
            self.alerts.append((t, m))
        def notify_external(self, t, m):
            pass

    from netpulse.services import ProcessMonitor
    svc = FakeSvc()
    pm = ProcessMonitor(svc)
    pm._raise_ids("PORT_SCAN", "тест")
    pm._raise_ids("PORT_SCAN", "тест")   # дубль - в алерты не уйдёт повторно
    pm._raise_ids("SUSPICIOUS_CONN", "другое")
    assert len(pm.ids_events) == 3
    types = [a[0] for a in svc.alerts]
    assert types.count("PORT_SCAN") == 1
    assert "SUSPICIOUS_CONN" in types


def test_quota_manager_math():
    class FakeRow(dict):
        pass
    class FakeDB:
        def __init__(self, day_b, month_b):
            self.day_b, self.month_b = day_b, month_b
        def execute(self, q, fetch=False, **k):
            if "start of day" in q:
                return [{"b": self.day_b}]
            return [{"b": self.month_b}]
    class FakeSvc:
        def __init__(self, day, month):
            self.cfg = {"quota": {"daily_mb": 100, "monthly_gb": 1, "warn_pct": 80}}
            self.db = FakeDB(day, month)
            self.alerts = []
            self._alert_rl = {}
        def push_alert(self, t, m, s, rate=0):
            self.alerts.append(t)

    # 50 MB из 100 MB дневных -> 50%
    svc = FakeSvc(50 * 1048576, 0)
    from netpulse.services import QuotaManager
    qm = QuotaManager(svc)
    data = qm.usage()
    assert abs(data["daily_pct"] - 50.0) < 0.5
    assert not any(t.startswith("QUOTA") for t in svc.alerts)

    # 95% -> предупреждение QUOTA_DAY
    svc2 = FakeSvc(95 * 1048576, 0)
    qm2 = QuotaManager(svc2)
    d2 = qm2.usage()
    assert d2["daily_pct"] == 95.0
    assert "QUOTA_DAY" in svc2.alerts


def test_backup_rotate():
    tmp = tempfile.mkdtemp()
    from netpulse.server import BackupManager
    bm = BackupManager({"backup": {"dir": tmp, "keep": 2}})
    for i in range(5):
        with open(os.path.join(tmp, f"netpulse_auto_2026010{i}_0000.rar"), "w") as f:
            f.write("x")
    open(os.path.join(tmp, "other.rar"), "w").close()
    bm.rotate(keep=2)
    left_auto = [f for f in os.listdir(tmp) if f.startswith("netpulse_auto_")]
    other = [f for f in os.listdir(tmp) if f.startswith("other")]
    assert len(left_auto) == 2, left_auto
    assert len(other) == 1  # чужие файлы не трогаем


# ---------- живой HTTP ----------

class MiniService:
    def __init__(self):
        self.snapshot = {
            "ts": time.time(), "down_kbps": 12.3, "up_kbps": 4.5,
            "total_kbps": 16.8, "total_down_mb": 1, "total_up_mb": 0.5,
            "max_kbps": 16.8, "pernic": {},
            "ping": {"current": 21, "jitter": 1.2, "loss_pct": 0, "min": 18, "max": 26},
            "quality": {"score": 93.4, "label": "Отлично", "color": "#22d3a7"},
            "system": {"cpu": 10, "mem_pct": 40, "mem_used_gb": 4, "mem_total_gb": 16},
            "uptime_sec": 42, "mode": {"traffic": "psutil", "admin": False},
            "alerts_unread": 0,
        }

    def get_snapshot(self):
        return copy.deepcopy(self.snapshot)

    def get_history(self, seconds=300):
        t = time.time()
        return [(t - i, 10.0 + i, 1.0, 20.0) for i in range(10)]

    def forecast_speed(self):
        return None

    class _QuotaStub:
        def usage(self):
            return {"daily_used_mb": 0, "daily_limit_mb": 0, "daily_pct": None,
                    "monthly_used_gb": 0, "monthly_limit_gb": 0, "monthly_pct": None}
    quota = _QuotaStub()


def _start_server(cfg_overrides=None):
    tmp = tempfile.mkdtemp()
    os.chdir(tmp)
    cfg = load_config()
    if cfg_overrides:
        merge_updates(cfg, cfg_overrides)

    svc = MiniService()
    svc.cfg = cfg

    from netpulse.server import build_server, BackupManager
    httpd = build_server(svc, cfg, BackupManager(cfg), port=0)
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever,
                          kwargs={"poll_interval": 0.2}, daemon=True)
    th.start()
    return httpd, port, cfg


def _get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def test_server_endpoints_and_auth():
    httpd, port, cfg = _start_test_server_auth()
    base = f"http://127.0.0.1:{port}"
    try:
        code, html = _get(base + "/")
        assert code == 200 and "NETPULSE" in html.upper()

        # auth включен - без токена 401
        code, _ = _get(base + "/api/state")
        assert code == 401, f"ожидался 401, получен {code}"

        # с токеном в заголовке - ок
        code, body = _get(base + "/api/state", {"X-Auth": "secret123"})
        assert code == 200
        state = json.loads(body)
        assert abs(state["down_kbps"] - 12.3) < 0.01

        # с токеном в query (для SSE/EventSource) - тоже ок
        code, _ = _get(base + f"/api/state?token=secret123")
        assert code == 200

        # metrics без auth запрещён
        code, _ = _get(base + "/metrics")
        assert code == 401
        code, body = _get(base + "/metrics", {"X-Auth": "secret123"})
        assert code == 200 and b"np_quality_score".decode() in body
    finally:
        httpd.shutdown()


def _start_test_server_auth():
    return _start_server({"web_auth_enabled": True, "web_token": "secret123"})


def test_server_public_mode():
    httpd, port, cfg = _start_server(None)
    base = f"http://127.0.0.1:{port}"
    try:
        code, body = _get(base + "/api/state")
        assert code == 200
        code, body = _get(base + "/api/history?minutes=1")
        hist = json.loads(body)
        assert len(hist["points"]) == 10
        code, _ = _get(base + "/style.css")
        assert code == 200
        code, _body = _get(base + "/..%2fconfig.py")
        assert code in (403, 404), f"path traversal должен блокироваться, получен {code}"
    finally:
        httpd.shutdown()


def test_reports_require_auth():
    """Отчёты содержат данные — при включённом auth тоже под замком."""
    httpd, port, cfg = _start_server(
        {"web_auth_enabled": True, "web_token": "secret123"})
    base = f"http://127.0.0.1:{port}"
    try:
        for p in ("/journal.txt", "/journal.csv", "/report.txt"):
            code, _ = _get(base + p)
            assert code == 401, f"{p} без токена: {code}"
        for p in ("/journal.txt", "/journal.csv", "/report.txt"):
            code, _ = _get(base + p, {"X-Auth": "secret123"})
            assert code == 200, f"{p} с токеном: {code}"
    finally:
        httpd.shutdown()


ALL = [v for k, v in sorted(globals().items()) if k.startswith("test_")]

if __name__ == "__main__":
    cwd = os.getcwd()
    ok = 0
    for fn in ALL:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
            ok += 1
        except Exception as e:
            print(f"  FAIL {fn.__name__}: {e}")
        os.chdir(cwd)
    print(f"{ok}/{len(ALL)} тестов прошло")
    sys.exit(0 if ok == len(ALL) else 1)

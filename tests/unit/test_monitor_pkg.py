"""Unit: netpulse.monitor (quality, portscan, quota, mtr-stats, procmon)."""
import socket

from netpulse.monitor import (
    MTREngine, PortScanner, ProcessMonitor, QuotaManager, quality_label,
    quality_score,
)


def test_quality_score_bands():
    q = {"good_ping_ms": 50, "warn_ping_ms": 120, "max_jitter_ms": 15,
         "max_loss_pct": 2}
    assert quality_score(10, 0, 0, q) == 100.0
    assert quality_score(85, 0, 0, q) < 100.0
    assert quality_score(500, 0, 0, q) < 75.0
    assert quality_score(None, None, None, q) == 100.0
    assert quality_score(10, 0, 50, q) < 100.0
    assert quality_label(90) == ("Отлично", "#22d3a7")
    assert quality_label(70) == ("Нормально", "#8bd450")
    assert quality_label(50) == ("Проблемы", "#f5b942")
    assert quality_label(10) == ("Плохо", "#ff5c74")


def test_portscan_loopback():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        res = PortScanner.tcp_scan("127.0.0.1", [port, 64000], timeout=0.5,
                                   workers=4)
        assert res["host"] == "127.0.0.1" and res["scanned"] == 2
        assert any(p["port"] == port for p in res["open"])
        assert all(p["port"] != 64000 for p in res["open"])
    finally:
        srv.close()


class FakeDB:
    def __init__(self, traffic_bytes=0):
        self.traffic_bytes = traffic_bytes

    def execute(self, sql, params=(), fetch=False):
        if fetch:
            return [{"b": self.traffic_bytes}]
        return 1


class FakeSvc:
    def __init__(self, cfg=None, traffic_bytes=0):
        self.cfg = cfg or {}
        self.db = FakeDB(traffic_bytes)
        self.alerts = []

    def push_alert(self, *a, **k):
        self.alerts.append(a)


def test_quota_no_limits():
    qm = QuotaManager(FakeSvc({"quota": {}}, traffic_bytes=10 * 1048576))
    usage = qm.usage()
    assert usage["daily_used_mb"] == 10.0
    assert usage["daily_limit_mb"] == 0
    assert usage["daily_pct"] is None
    assert usage["monthly_used_gb"] == round(10 / 1024, 3)
    # кэш: второй вызов тот же объект
    assert qm.usage() is usage


def test_quota_alerts():
    svc = FakeSvc({"quota": {"daily_mb": 5, "monthly_gb": 0, "warn_pct": 80}},
                  traffic_bytes=10 * 1048576)
    usage = QuotaManager(svc).usage()
    assert usage["daily_pct"] == 200.0
    assert svc.alerts and svc.alerts[0][0] == "QUOTA_DAY"


def test_mtr_stats_shape():
    import threading
    from collections import deque
    eng = MTREngine.__new__(MTREngine)
    eng._lock = threading.RLock()
    eng.target = "8.8.8.8"
    eng.running = False
    eng.cycles_done = 3
    eng.hops = [{"hop": 1, "ip": "192.168.1.1",
                 "samples": deque([(True, 1.0), (True, 3.0), (False, None)])}]
    st = MTREngine.stats(eng)
    assert st["cycles"] == 3 and st["target"] == "8.8.8.8"
    hop = st["hops"][0]
    assert hop["loss_pct"] == round(100 * (3 - 2) / 3, 1)
    assert hop["avg_ms"] == 2.0 and hop["min_ms"] == 1.0
    assert hop["graph"] == [1.0, 3.0, None]


def test_procmon_live_shapes():
    pm = ProcessMonitor(FakeSvc())
    pm.sample()  # живой psutil — не должен падать
    assert isinstance(pm.top_io(5), list)
    assert isinstance(pm.new_connections(5), list)
    assert isinstance(pm.ids_feed(5), list)

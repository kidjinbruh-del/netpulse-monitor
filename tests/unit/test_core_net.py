"""Unit: pinger/sniffer/security — математика и контракты, без демонов."""
import time

from core.pinger import Pinger
from core.security import SecurityScanner, _is_whitelisted_name
from core.sniffer import Sniffer


def test_pinger_record_and_alerts():
    alerts = []
    p = Pinger(target="127.0.0.1",
               alert_thresholds={"ping_high": 100, "loss_critical": 50,
                                 "loss_high": 20, "jitter_high": 30},
               alert_callback=lambda t, m: alerts.append((t, m)))
    p._record_result(500.0, False)  # высокий пинг
    assert p.current_ping == 500.0
    assert p.total_packets == 1 and p.lost_packets == 0
    assert alerts and alerts[0][0] == "ВЫСОКИЙ ПИНГ"
    p._record_result(0.0, True)  # потеря → 50% > loss_high 20
    assert p.get_loss_percent() == 50.0
    assert p.get_display_ping() == 500.0
    st = p.get_stats()
    assert st["total"] == 2 and st["lost"] == 1
    assert st["buffer_size"] == 2


def test_pinger_flush_and_recovery():
    saved = []
    p = Pinger(target="127.0.0.1")
    p.set_db_callback(saved.extend)
    p._record_result(10.0, False)
    p._flush_saves()
    assert len(saved) == 1 and saved[0]["ping_ms"] == 10.0
    assert p._pending_saves == []
    p._flush_saves()  # пустой буфер — no-op
    p.set_target("1.1.1.1")
    assert p.target == "1.1.1.1"
    p.set_target("")
    assert p.target == "1.1.1.1"
    p.set_thresholds({"ping_high": 1})
    assert p._alert_thresholds == {"ping_high": 1}
    p.set_thresholds("junk")  # не dict — игнорируем
    assert p._alert_thresholds == {"ping_high": 1}


def test_sniffer_math():
    s = Sniffer()
    now = time.time()
    s._record_traffic(2048, 1024, now)
    assert s.stats["bytes_in"] == 2048
    assert s.stats["bytes_out"] == 1024
    speed = s.get_speed()
    assert speed > 0
    assert s.stats["max_speed"] == speed
    # uptime-форматы
    s.start_time = time.time() - 30
    assert s.get_uptime() == "30с"
    s.start_time = time.time() - 90
    assert s.get_uptime() == "1м"
    s.start_time = time.time() - 3700
    assert s.get_uptime() == "1ч 1м"
    # top ips только в real
    assert s.get_top_ips() == []
    assert s.get_stats()["mode"] == "psutil"


def test_sniffer_split_fallback():
    s = Sniffer()
    down, up = s.get_speed_split()
    assert (down, up) == (0, 0)
    now = time.time()
    s._updown.append((now, 2048.0, 1024.0))
    down, up = s.get_speed_split()
    assert down == 2.0 and up == 1.0


def test_sniffer_cleanup_ips():
    s = Sniffer()
    for i in range(1100):
        s.stats["ips"][f"10.0.0.{i % 256}.{i}"] = {"bytes": i, "packets": 1}
    s._cleanup_old_ips()
    assert len(s.stats["ips"]) == 500


def test_whitelist_names():
    pats = {"CodeSetup*.exe", "svchost.exe"}
    assert _is_whitelisted_name("CodeSetup123.exe", pats) is True
    assert _is_whitelisted_name("svchost.exe", pats) is True
    assert _is_whitelisted_name("SVCHOST.EXE", pats) is True
    assert _is_whitelisted_name("evil.exe", pats) is False


def test_security_hosts_file_shape():
    res = SecurityScanner.check_hosts_file()
    assert isinstance(res, list)


def test_security_full_scan_keys(monkeypatch):
    import core.security as sec
    monkeypatch.setattr(sec.SecurityScanner, "detect_suspicious_connections",
                        staticmethod(lambda p=None: []))
    monkeypatch.setattr(sec.SecurityScanner, "detect_hidden_processes",
                        staticmethod(lambda: []))
    monkeypatch.setattr(sec.SecurityScanner, "check_hosts_file",
                        staticmethod(lambda: []))
    monkeypatch.setattr(sec.SecurityScanner, "check_autorun",
                        staticmethod(lambda: []))
    res = SecurityScanner.run_full_scan([])
    assert set(res) == {"Подозрительные соединения", "Скрытые процессы",
                        "HOSTS файл", "Автозагрузка"}


def test_detect_connections_parses_netstat(monkeypatch):
    import subprocess
    import sys

    out = ("  TCP    192.168.1.50:54321    203.0.113.7:4444       ESTABLISHED\n"
           "  TCP    192.168.1.50:54322    8.8.8.8:443            ESTABLISHED\n")

    class FakeProc:
        stdout = out

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc())
    if sys.platform != "win32":
        return  # формат выше — виндовый netstat
    res = SecurityScanner.detect_suspicious_connections([4444])
    assert len(res) == 1
    assert res[0]["remote"] == "203.0.113.7:4444"
    assert res[0]["severity"] == "HIGH"

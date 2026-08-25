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
    class _MiniDB:
        """Настоящий sqlite in-memory: аудит/таблицы создаются и читаются."""
        def __init__(self):
            import sqlite3
            self._c = sqlite3.connect(":memory:", check_same_thread=False)
            self._c.row_factory = sqlite3.Row

        def execute(self, q, params=(), fetch=False, **k):
            try:
                cur = self._c.execute(q, params)
                if fetch:
                    return [dict(r) for r in cur.fetchall()]
                self._c.commit()
                return cur.rowcount
            except Exception:
                try:
                    self._c.rollback()
                except Exception:
                    pass
                return None

        def execute_many(self, q, params_list, **k):
            try:
                self._c.executemany(q, params_list)
                self._c.commit()
                return True
            except Exception:
                return False

    db = _MiniDB()

    class _MiniJournal:
        def list_entries(self, *a, **k):
            return []
        def add(self, *a, **k):
            return {"ok": True, "id": 1}
        def month_report(self, *a, **k):
            return {"entries": 0, "minutes": 0, "hours": 0, "by_source": [],
                    "top_users": [], "top_hosts": [], "per_day": []}
    journal = _MiniJournal()

    def apply_settings(self, updates):
        from netpulse.config import merge_updates, save_config
        merge_updates(self.cfg, updates)
        save_config(self.cfg)
        return True
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
    httpd.svc = svc
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


def _post(url, body, headers=None, ctype="application/json"):
    h = {"Content-Type": ctype}
    h.update(headers or {})
    req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"),
                                 headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def test_post_csrf_guards():
    """Мутации требуют честный JSON + заголовок X-Auth (анти-CSRF)."""
    from netpulse.server import reset_auth_state
    reset_auth_state()
    httpd, port, cfg = _start_server(
        {"web_auth_enabled": True, "web_token": "secret123"})
    base = f"http://127.0.0.1:{port}"
    try:
        code, body = _post(base + "/api/alertsack", {},
                           {"X-Auth": "secret123"}, ctype="text/plain")
        assert code == 415, f"{code} {body[:120]}"
        # без кредов вообще -> 401
        code, body = _post(base + "/api/alertsack", {})
        assert code == 401, f"{code} {body[:120]}"
        # auth через cookie БЕЗ X-Auth -> это CSRF-сценарий -> 403
        code, body = _post(base + "/api/alertsack", {},
                           {"Cookie": "np_session=secret123"})
        assert code == 403, f"{code} {body[:120]}"
        # cookie + X-Auth -> ок
        code, body = _post(base + "/api/alertsack", {},
                           {"Cookie": "np_session=secret123",
                            "X-Auth": "secret123"})
        assert code == 200, f"{code} {body[:120]}"
    finally:
        httpd.shutdown()
        reset_auth_state()


def test_rate_limit_429():
    """5 неверных токенов с одного IP -> блок 429."""
    from netpulse.server import reset_auth_state
    reset_auth_state()
    httpd, port, cfg = _start_server(
        {"web_auth_enabled": True, "web_token": "secret123"})
    base = f"http://127.0.0.1:{port}"
    try:
        codes = []
        for _ in range(6):
            code, _ = _get(base + "/api/state", {"X-Auth": "wrong"})
            codes.append(code)
        assert codes[:5] == [401] * 5, codes
        assert codes[5] == 429, codes
    finally:
        httpd.shutdown()
        reset_auth_state()


def test_whoami_identity():
    """Сайт помнит, кто именно вошёл (по токену из web_admins)."""
    from netpulse.server import reset_auth_state
    reset_auth_state()
    httpd, port, cfg = _start_server({
        "web_auth_enabled": True, "web_token": "secret123",
        "web_admins": [{"name": "Пётр", "token": "petr-token",
                        "role": "admin"}]})
    base = f"http://127.0.0.1:{port}"
    try:
        code, body = _get(base + "/api/whoami", {"X-Auth": "petr-token"})
        assert code == 200
        assert json.loads(body)["user"] == "Пётр", body
        code, body = _get(base + "/api/whoami", {"X-Auth": "secret123"})
        assert json.loads(body)["user"] == "admin"
    finally:
        httpd.shutdown()
        reset_auth_state()


def test_audit_log_and_config_backup():
    """Аудит мутаций пишется; перед сохранением конфига создаётся бэкап."""
    from netpulse.server import reset_auth_state
    reset_auth_state()
    httpd, port, cfg = _start_server(
        {"web_auth_enabled": True, "web_token": "secret123"})
    base = f"http://127.0.0.1:{port}"
    try:
        code, body = _post(base + "/api/journaladd",
                           {"text": "аудит-тест", "minutes": 3},
                           {"X-Auth": "secret123"})
        assert code == 200, f"journaladd: {code} {body[:120]}"
        code, body = _get(base + "/api/audit?limit=10",
                          {"X-Auth": "secret123"})
        assert code == 200, f"audit: {code} {body[:150]}"
        entries = json.loads(body)["entries"]
        a = next(e for e in entries if e["action"] == "journaladd")
        assert a["status"] == 200 and a["user"] == "admin", a
        # секрет в details замаскирован (меняем telegram-токен, не web_token!)
        code, _ = _post(base + "/api/settings",
                        {"telegram": {"token": "sekret"}},
                        {"X-Auth": "secret123"})
        code, body = _get(base + "/api/audit?limit=5",
                          {"X-Auth": "secret123"})
        assert code == 200, f"audit2: {code} {body[:150]}"
        entries = json.loads(body)["entries"]
        a2 = next(e for e in entries if e["action"] == "settings")
        assert "sekret" not in (a2["details"] or ""), a2
        # бэкап конфига: повторное сохранение копирует предыдущий файл
        code, _ = _post(base + "/api/settings", {"theme": "light"},
                        {"X-Auth": "secret123"})
        assert code == 200, code
        backups = os.listdir(os.path.join("backups", "config"))
        assert len(backups) >= 1, backups
    finally:
        httpd.shutdown()
        reset_auth_state()


def test_webhook_payload():
    """notify_external с webhook шлёт JSON нужной структуры."""
    import netpulse.services as SvcMod
    from unittest import mock

    class FakeSvc3: pass
    fs = FakeSvc3()
    fs.cfg = {"webhook": {"enabled": True,
                          "url": "http://127.0.0.1:1/hook"},
              "telegram": {"enabled": False}}
    captured = {}

    def fake_urlopen(req, timeout=5):
        captured["url"] = req.full_url
        captured["data"] = json.loads(req.data.decode("utf-8"))

        class R:
            def read(self, n=-1):
                return b"{}"
        return R()

    with mock.patch("urllib.request.urlopen", fake_urlopen):
        SvcMod.MonitorService.notify_external(fs, "TEST_ALERT", "тело")

    assert captured["url"] == "http://127.0.0.1:1/hook"
    assert captured["data"]["type"] == "TEST_ALERT"
    assert captured["data"]["message"] == "тело"
    assert "NetPulse" in captured["data"]["text"]


def test_server_endpoints_and_auth():
    from netpulse.server import reset_auth_state
    reset_auth_state()
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
    from netpulse.server import reset_auth_state
    reset_auth_state()
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
            import traceback
            tb = traceback.format_exc().strip().splitlines()[-1]
            print(f"  FAIL {fn.__name__}: {e} | {tb}")
        os.chdir(cwd)
    print(f"{ok}/{len(ALL)} тестов прошло")
    sys.exit(0 if ok == len(ALL) else 1)

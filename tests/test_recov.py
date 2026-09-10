"""
Тесты восстановления NetPulse: решётка (mesh-auth), security, конфиг.
Запуск: python -m tests.test_recov   (достаточно из C:\\сеть пупок)
"""

import os
import sys
import base64
import hashlib
import json
import tempfile
import threading
import urllib.request
import urllib.error

import hmac

from netpulse.config import load_config

DONE_MESH_AUTH = False


# ---------- mesh-auth ----------

def test_mesh_auth_sign_again():
    """Подпись HELLO детерминирована и одна и та же для одной сессии."""
    from netpulse.p2p_core.networking.mesh_auth import sign_hello
    s1 = sign_hello("node0", "sess", "sekret")
    s2 = sign_hello("node0", "sess", "sekret")
    s3 = sign_hello("node0", "sess2", "sekret")
    assert s1 == s2, "подпись должна быть детерминированной"
    assert s1 != s3, "разная сессия => разная подпись"
    assert sign_hello("node0", "s", None) is None, "без секрета — None"


def test_mesh_auth_verify_matrix():
    from netpulse.p2p_core.networking.mesh_auth import verify_sig, sign_hello
    s = "sekret"
    sig = sign_hello("node0", "sess-1", s)
    assert verify_sig("node0", "sess-1", s, sig) is True
    assert verify_sig("nodeX", "sess-1", s, sig) is False   # чужой узел
    assert verify_sig("node0", "sess-2", s, sig) is False   # другая сессия
    assert verify_sig("node0", "sess-1", s, None) is False  # подпись отсутствует
    assert verify_sig("node0", "sess-1", "wrong", sig) is False
    # backward compat: секрет None на приёмнике => открытый mesh
    assert verify_sig("node0", "sess-1", None, "garbage") is True


def test_mesh_auth_cross_compat_with_hub():
    """Подпись hub (netpulse/mesh.py) валидна для P2P_Core verify."""
    from netpulse.p2p_core.networking.mesh_auth import verify_sig
    import importlib.util
    spec = importlib.util.spec_from_file_location("meshmod", r"C:\сеть пупок\netpulse\mesh.py")
    meshmod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(meshmod)

    SHARED = "mesh-shared-secret-2026"
    sig = meshmod._sign_hello("NetPulseHub", "sess-hub", SHARED)
    assert sig, "hub должен давать непустую подпись при заданном секрете"
    assert verify_sig("NetPulseHub", "sess-hub", SHARED, sig) is True
    assert verify_sig("NetPulseHub", "sess-hub", "wrong", sig) is False
    # без секрета hub не подписывает (""), но при секрете None приёмник должен принять (backward)
    assert meshmod._sign_hello("hub", "s", None) == ""


# ---------- security: allowlist ----------

def test_ip_allowlist_matrix():
    from netpulse.server import _ip_in_network, _allowlist_denied
    cfg_on = {"ip_allowlist": {"enabled": True, "networks": ["192.168.1.0/24", "127.0.0.0/8"]}}
    assert _allowlist_denied("192.168.1.55", cfg_on) is False
    assert _allowlist_denied("192.168.2.1", cfg_on) is True
    assert _allowlist_denied("127.0.0.1", cfg_on) is False
    assert _allowlist_denied("10.0.0.5", cfg_on) is True
    # выключенный allowlist ничего не запрещает
    assert _allowlist_denied("8.8.8.8", {"ip_allowlist": {"enabled": False}}) is False
    # edge: хост ровно /32
    assert _ip_in_network("10.0.0.5", "10.0.0.5/32") is True
    assert _ip_in_network("10.0.0.6", "10.0.0.5/32") is False
    # мусор -> не блокируем
    assert _ip_in_network("abc", "192.168.1.0/24") is False


def test_config_default_has_security_keys():
    """Конфиг содержит новые ключи (p2p.secret, ip_allowlist)."""
    cfg = load_config()
    assert "p2p" in cfg and "secret" in cfg["p2p"]
    assert isinstance(cfg["p2p"]["secret"], str), "p2p.secret должен быть строкой"
    assert "ip_allowlist" in cfg
    assert cfg["ip_allowlist"]["enabled"] is False
    assert "web_auth_enabled" in cfg


# ---------- DPAPI ----------

def test_dpapi_encrypt_decrypt_roundtrip():
    from core.secrets import encrypt_config, decrypt_config
    secret = {"token": "sk-123456"}
    enc = encrypt_config(secret)
    assert isinstance(enc, dict)
    assert enc["token"].startswith("dpapi:"), enc
    dec = decrypt_config(enc)
    assert dec == secret, f"{dec} != {secret}"
    # расшифровка не-секретных значений без префикса возвращает как есть
    assert decrypt_config({"plain": "v"}) == {"plain": "v"}


def test_dpapi_in_config_json_roundtrip():
    """Токен в настоящем config.json зашифрован dpapi и расшифровывается."""
    p = r"C:\сеть пупок\config.json"
    if not os.path.exists(p):
        return  # не критично для CI
    with open(p, encoding="utf-8") as f:
        raw = f.read()
    assert "\ufeff" not in raw, "config.json не должен содержать BOM"
    cfg = json.loads(raw)
    from core.secrets import decrypt_config
    dec = decrypt_config(cfg)
    assert isinstance(dec.get("web_token"), str) and len(dec["web_token"]) >= 16, \
        "web_token должен расшифровываться в нормальный токен"


# ---------- HTTP-интеграция ----------

def _json_get(port, path, token=None):
    hdr = {}
    if token:
        hdr["X-Auth"] = token
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=hdr)
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def _json_post(port, path, body, token=None):
    hdr = {"Content-Type": "application/json"}
    if token:
        hdr["X-Auth"] = token
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=json.dumps(body).encode("utf-8"),
        headers=hdr, method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def test_allowlist_http_block():
    """При включённом allowlist и чужом IP авторизация недостижима (403 раньше айки)."""
    import copy, threading, time
    import netpulse.server as srv
    from netpulse.server import reset_auth_state, build_server, BackupManager
    tmp = tempfile.mkdtemp()
    os.chdir(tmp)
    try:
        cfg = load_config()
        cfg["ip_allowlist"] = {"enabled": True,
                               "networks": ["10.255.0.0/8"]}  # не наш 127.x
        class FakeService:
            def get_snapshot(self): return {}
            def get_history(self, *a, **k): return []
        srvmod = srv
        svc = FakeService()
        # build_server требует cfg и BackupManager
        httpd = build_server(svc, cfg, BackupManager(cfg), port=0)
        httpd.svc = svc
        port = httpd.server_address[1]
        th = threading.Thread(target=httpd.serve_forever,
                              kwargs={"poll_interval": 0.2}, daemon=True)
        th.start()
        try:
            # без токена, наш IP -> 401 (auth требует токен, IP подходит)
            code, _ = _json_get(port, "/api/state")
            # 127.0.0.1 НЕ в 10.255.0.0/8 => allowlist запрещает ещё на входе
            assert code == 403, f"ожидался 403 (вне allowlist), получен {code}"
        finally:
            httpd.shutdown()
    finally:
        reset_auth_state()


def test_p2p_nodes_functions_loaded():
    """Маршруты меш-API существуют в build_server (нет 404)."""
    import threading
    from netpulse.server import reset_auth_state, build_server, BackupManager
    tmp = tempfile.mkdtemp()
    os.chdir(tmp)
    cfg = load_config()
    class FakeService:
        def get_snapshot(self): return {}
        def get_history(self, *a, **k): return []
    httpd = build_server(FakeService(), cfg, BackupManager(cfg), port=0)
    port = httpd.server_address[1]
    th = threading.Thread(target=httpd.serve_forever,
                          kwargs={"poll_interval": 0.2}, daemon=True)
    th.start()
    try:
        for ep in ("/api/p2pstatus", "/api/p2pnodes", "/api/p2pservices"):
            code, body = _json_get(port, ep, token="x")
            # 200 в public-режиме, 401 если auth включен, 503 если mesh не создан
            assert code in (200, 401, 503), f"{ep}: {code}"
        # p2pcall — POST-only
        code, body = _json_post(port, "/api/p2pcall", {"service": "x"}, token="x")
        assert code in (200, 401, 503), f"/api/p2pcall: {code}"
    finally:
        httpd.shutdown()
        reset_auth_state()


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
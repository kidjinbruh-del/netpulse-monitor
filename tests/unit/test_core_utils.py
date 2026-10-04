"""Unit: core utils/tracer/secrets (без сети, без DPAPI-записи)."""
import subprocess

from core import utils as U
from core.secrets import (
    decrypt_config, encrypt_config, is_encrypted,
)
from core.tracer import Tracer


def test_decode_process_output():
    assert U.decode_process_output("already str") == "already str"
    assert U.decode_process_output("привет".encode("utf-8")) == "привет"
    # cp866 (OEM): "Привет" в OEM-байтах
    oem = "Привет".encode("cp866")
    assert U.decode_process_output(oem) == "Привет"


def test_parse_ping_output():
    ms, loss = U.parse_ping_output("Ответ от 8.8.8.8: время=25мс")
    assert (ms, loss) == (25.0, False)
    ms, loss = U.parse_ping_output("Reply from x: time<1ms")
    assert (ms, loss) == (1.0, False)
    ms, loss = U.parse_ping_output("Превышен интервал ожидания")
    assert (ms, loss) == (0.0, True)
    ms, loss = U.parse_ping_output("time=12,5ms")
    assert (ms, loss) == (12.5, False)


def test_parse_trace_output():
    ip, ms = U.parse_trace_output("  1    <1 мс  192.168.1.1", target="8.8.8.8")
    assert ip == "192.168.1.1"
    ip, ms = U.parse_trace_output("Trace to 8.8.8.8", target="8.8.8.8")
    assert ip == "8.8.8.8"  # только цель → конец маршрута


def test_safe_kill_none():
    U.safe_kill_process(None)  # не падает


def test_safe_kill_process(monkeypatch):
    killed = []
    started = []

    class FakeProc:
        pid = 1234

        def terminate(self):
            started.append(1)

        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired("x", 1)

        def kill(self):
            killed.append(1)

    import sys
    if sys.platform == "win32":
        monkeypatch.setattr(subprocess, "run",
                            lambda *a, **k: (_ for _ in ()).throw(
                                RuntimeError("no taskkill")))
    U.safe_kill_process(FakeProc(), timeout=0)
    assert killed == [1]


def test_tracer_empty_result_shape():
    t = Tracer()
    t.stop()  # сразу отмена
    res = t.trace("127.0.0.1", max_hops=1)
    assert res["target"] == "127.0.0.1"
    assert res["avg_ms"] == 999.0
    assert res["total_hops"] == 0


def test_tracer_localhost_live():
    res = Tracer().trace("127.0.0.1", max_hops=2)
    assert res["total_hops"] >= 1
    assert res["hops"][0]["ip"] == "127.0.0.1"
    assert res["avg_ms"] < 999.0


def test_secrets_roundtrip():
    assert is_encrypted("dpapi:abc") is True
    assert is_encrypted("plain") is False
    assert is_encrypted("") is False
    cfg = {"web_token": "dpapi:xxx", "nested": {"token": "plain"},
           "other": "value"}
    # битый dpapi → остаётся как есть, остальное не трогаем
    out = decrypt_config(cfg)
    assert out["web_token"] == "dpapi:xxx"
    assert out["nested"]["token"] == "plain"
    assert out["other"] == "value"


def test_encrypt_config_selective(monkeypatch):
    from core import secrets as S
    monkeypatch.setattr(S, "encrypt_value", lambda s: "dpapi:ENC")
    out = encrypt_config({"web_token": "abc", "port": 1,
                          "admins": [{"token": "t"}]})
    assert out["web_token"] == "dpapi:ENC"
    assert out["port"] == 1
    assert out["admins"][0]["token"] == "dpapi:ENC"
    # повторное шифрование уже шифрованного — пропускаем
    out2 = encrypt_config({"web_token": "dpapi:ENC"})
    assert out2["web_token"] == "dpapi:ENC"

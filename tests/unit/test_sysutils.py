"""Unit: sysutils (парсинг netsh, команды firewall, zip-бэкап)."""
import os
import subprocess
import zipfile

from netpulse.sysutils import BackupManager, FirewallCtl


RU_SAMPLE = """Имя правила:                   NetPulse_IP_1.2.3.4_out
Включено:                        Да
Удаленный IP-адрес:              1.2.3.4
Имя правила:                   SomeOther
Включено:                        Да
"""

EN_SAMPLE = """Rule Name:                       NetPulse_APP_ab12cd_in
Enabled:                         Yes
Program:                         C:\\Tools\\app.exe
"""


def test_parse_rules_ru_filters_prefix():
    rules = FirewallCtl.parse_rules(RU_SAMPLE)
    assert len(rules) == 1
    assert rules[0]["name"] == "NetPulse_IP_1.2.3.4_out"
    assert rules[0]["remoteip"] == "1.2.3.4"


def test_parse_rules_en_program():
    rules = FirewallCtl.parse_rules(EN_SAMPLE)
    assert len(rules) == 1
    assert rules[0]["program"] == "C:\\Tools\\app.exe"
    assert rules[0]["enabled"] == "Yes"


def test_parse_rules_empty():
    assert FirewallCtl.parse_rules("") == []
    assert FirewallCtl.parse_rules("Rule Name: Other\nEnabled: Yes\n") == []


def test_run_ok_markers(monkeypatch):
    calls = []

    class FakeProc:
        returncode = 0
        stdout = "Ok.".encode()
        stderr = b""

    def fake_run(*a, **k):
        calls.append(a[0])
        return FakeProc()

    monkeypatch.setattr(subprocess, "run", fake_run)
    ok, msg = FirewallCtl._run(["delete", "rule", "name=X"])
    assert ok is True and msg == "Ok."
    assert calls[0][:3] == ["netsh", "advfirewall", "firewall"]


def test_run_failure_rc():
    class FakeProc:
        returncode = 1
        stdout = "Ok.".encode()
        stderr = b""

    import subprocess as sp
    orig = sp.run
    sp.run = lambda *a, **k: FakeProc()
    try:
        ok, _ = FirewallCtl._run(["x"])
        assert ok is False
    finally:
        sp.run = orig


def test_block_ip_builds_both_dirs(monkeypatch):
    seen = []
    monkeypatch.setattr(
        FirewallCtl, "_run",
        staticmethod(lambda args: (seen.append(args) or (True, "Ok."))),
    )
    res = FirewallCtl.block_ip("1.2.3.4")
    assert res["ok"] is True
    assert len(seen) == 2
    assert any("dir=out" in a or "dir=out" in str(a) for a in seen)


def test_block_app_missing_file():
    res = FirewallCtl.block_app("C:\\definitely\\not\\here.exe")
    assert res == {"ok": False, "error": "файл не найден"}


def test_unblock_prefix_guard():
    from netpulse.services.firewall import FirewallService
    from netpulse.config import Config
    svc = FirewallService(Config())
    res = svc.unblock("SomeoneElse_rule")
    assert res["ok"] is False


def test_backup_zip_roundtrip(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "a.txt").write_text("hello", encoding="utf-8")
    (src / "sub" / "b.txt").write_text("world", encoding="utf-8")
    (src / "__pycache__").mkdir()
    (src / "__pycache__" / "x.pyc").write_text("junk", encoding="utf-8")

    mgr = BackupManager({"backup": {"dir": str(tmp_path / "bk")}},
                        source_dir=str(src))
    # Форсируем zip-путь (без зависимости от установленного WinRAR).
    monkeypatch.setattr(BackupManager, "_find_rar", classmethod(lambda cls: None))
    res = mgr.run_backup_now()
    assert res["ok"] is True
    names = zipfile.ZipFile(res["archive"]).namelist()
    assert "a.txt" in names and "sub/b.txt" in names
    assert not any("__pycache__" in n for n in names)


def test_backup_rotate(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    d = tmp_path / "bk"
    d.mkdir()
    for i in range(5):
        (d / f"netpulse_auto_2024010{i}.zip").write_text("x", encoding="utf-8")
    mgr = BackupManager({"backup": {"dir": str(d)}})
    mgr.rotate(keep=2)
    left = sorted(os.listdir(d))
    assert left == ["netpulse_auto_20240103.zip", "netpulse_auto_20240104.zip"]

"""Unit: config/store (merge, backup, save roundtrip на копии)."""
import json
import os

from netpulse.config.store import backup_config, merge_updates, save_legacy_config


def test_merge_updates_deep():
    cfg = {"a": 1, "nested": {"x": 1, "y": 2}}
    out = merge_updates(cfg, {"nested": {"y": 5, "z": 6}, "b": 2})
    assert out is cfg  # in-place
    assert cfg == {"a": 1, "b": 2, "nested": {"x": 1, "y": 5, "z": 6}}


def test_save_roundtrip_on_copy(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    src = {"web_port": 8771, "nested": {"k": "v"}}
    (tmp_path / "config.json").write_text(json.dumps(src), encoding="utf-8")
    cfg = dict(src)
    merge_updates(cfg, {"web_port": 9999})
    assert save_legacy_config(cfg, "config.json") is True
    saved = json.loads((tmp_path / "config.json").read_text(encoding="utf-8"))
    assert saved["web_port"] == 9999
    assert saved["nested"] == {"k": "v"}
    backups = os.listdir(tmp_path / "backups" / "config")
    assert len(backups) == 1 and backups[0].startswith("config.backup_")


def test_backup_config_missing_file_no_crash(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    backup_config("nonexistent.json")  # не должно падать

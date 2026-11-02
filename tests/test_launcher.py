import importlib.util
import json
from pathlib import Path
import pytest

spec = importlib.util.spec_from_file_location('netpulse_launcher', Path(__file__).resolve().parents[1] / 'tools' / 'launch_netpulse.py')
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


def test_existing_server_reused_without_starting_process(tmp_path, monkeypatch):
    monkeypatch.setattr(launcher, 'ROOT', tmp_path)
    monkeypatch.setattr(launcher, 'LOGS', tmp_path / 'logs')
    monkeypatch.setattr(launcher, 'health', lambda url: True)
    monkeypatch.setattr(launcher.subprocess, 'Popen', lambda *a, **k: pytest.fail('duplicate server'))
    opened = []
    monkeypatch.setattr(launcher.webbrowser, 'open', lambda url, **kwargs: opened.append(url))
    assert launcher.launch() == 'http://127.0.0.1:8770'
    assert opened == ['http://127.0.0.1:8770/#operations']


def test_foreign_port_owner_is_not_stopped(tmp_path, monkeypatch):
    monkeypatch.setattr(launcher, 'ROOT', tmp_path)
    monkeypatch.setattr(launcher, 'LOGS', tmp_path / 'logs')
    monkeypatch.setattr(launcher, 'health', lambda url: False)
    monkeypatch.setattr(launcher, 'occupied', lambda url: True)
    monkeypatch.setattr(launcher.subprocess, 'Popen', lambda *a, **k: pytest.fail('foreign port'))
    with pytest.raises(RuntimeError, match='occupied'):
        launcher.launch(False)


def test_invalid_port_and_tls_not_silently_downgraded(tmp_path, monkeypatch):
    monkeypatch.setattr(launcher, 'ROOT', tmp_path)
    config = tmp_path / 'config.json'
    config.write_text(json.dumps({'web_port': True}))
    with pytest.raises(ValueError):launcher.endpoint()
    config.write_text(json.dumps({'web_tls': {'enabled': True}}))
    with pytest.raises(ValueError, match='HTTPS'):launcher.endpoint()

"""Регрессии --check: env-файлы лаунчера и реальные причины провала.

``--check`` должен видеть те же ``netpulse.env`` / ``.env``, что и
``open_netpulse.sh``. Иначе исправная установка с MikroTik получает
ложный «mikrotik: fail» только потому, что пароль лежит в файле,
а не в унаследованном окружении.
"""
import datetime
import json
import os
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from netpulse import doctor
from netpulse.config import load_env_files

PASSWORD_ENV = "NP_TEST_ROUTER_PASSWORD"


def _self_signed_ca(path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "netpulse-test-ca")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def _config(tmp_path, ca):
    cfg = {
        "mikrotik": {
            "enabled": True,
            "devices": [{
                "id": "router-1",
                "name": "Router 1",
                "url": "https://192.0.2.1:443",
                "transport": "rest",
                "username": "admin",
                "password_env": PASSWORD_ENV,
                "ca_file": str(ca),
                "timeout_sec": 5,
                "tables": [],
            }],
        }
    }
    path = tmp_path / "config.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return path


def _mikrotik_check(checks):
    return next(item for item in checks if item["name"] == "mikrotik")


def test_check_reads_password_from_env_file(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv(PASSWORD_ENV, raising=False)
    ca = _self_signed_ca(tmp_path / "ca.pem")
    config = _config(tmp_path, ca)
    env = tmp_path / "netpulse.env"
    env.write_text(f"{PASSWORD_ENV}=secret\n", encoding="utf-8")
    monkeypatch.setenv("NETPULSE_ENV_FILE", str(env))

    checks = doctor.check(str(config))

    assert _mikrotik_check(checks)["ok"], checks
    assert os.environ[PASSWORD_ENV] == "secret"


def test_check_reports_missing_password(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv(PASSWORD_ENV, raising=False)
    monkeypatch.setenv("NETPULSE_ENV_FILE", str(tmp_path / "missing.env"))
    ca = _self_signed_ca(tmp_path / "ca.pem")
    config = _config(tmp_path, ca)

    checks = doctor.check(str(config))

    assert not _mikrotik_check(checks)["ok"], checks


def test_existing_environment_wins_over_file(tmp_path, monkeypatch):
    monkeypatch.setenv(PASSWORD_ENV, "from-process")
    env = tmp_path / "netpulse.env"
    env.write_text(f"{PASSWORD_ENV}=from-file\n", encoding="utf-8")
    monkeypatch.setenv("NETPULSE_ENV_FILE", str(env))

    loaded = load_env_files(str(tmp_path / "config.json"))

    assert str(env) in loaded
    assert os.environ[PASSWORD_ENV] == "from-process"


def test_export_and_quotes_are_accepted(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv(PASSWORD_ENV, raising=False)
    env = tmp_path / "netpulse.env"
    env.write_text(f'export {PASSWORD_ENV}="quoted secret"\n', encoding="utf-8")
    monkeypatch.setenv("NETPULSE_ENV_FILE", str(env))

    load_env_files(str(tmp_path / "config.json"))

    assert os.environ[PASSWORD_ENV] == "quoted secret"

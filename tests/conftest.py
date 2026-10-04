"""Общие фикстуры для unit/integration тестов v3."""
import pytest

from netpulse.config import Config


@pytest.fixture()
def isolated_config(tmp_path):
    """Изолированный Config: временные БД/логи, выключенный P2P, тестовый токен."""
    return Config(
        web={"host": "127.0.0.1", "port": 8771, "auth_enabled": True,
             "token": "test-token"},
        database={"path": str(tmp_path / "test.db")},
        logging={"level": "WARNING", "file": str(tmp_path / "test.log")},
        p2p={"enabled": False},
        backup={"enabled": False},
        proxmox={"enabled": False},
        ai={"enabled": False},
    )


@pytest.fixture()
def auth_headers():
    return {"X-Auth": "test-token"}

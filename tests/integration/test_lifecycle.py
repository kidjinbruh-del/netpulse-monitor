"""Integration: AppContext startup/shutdown + FastAPI lifespan + audit."""
from fastapi.testclient import TestClient

from netpulse.context import AppContext
from netpulse.server.main import create_app
from netpulse.services.base import BaseService

CALLS = []


class FakeA(BaseService):
    name = "fake_a"
    dependencies = []

    def _on_start(self):
        CALLS.append("start_a")

    def _on_stop(self):
        CALLS.append("stop_a")


class FakeB(BaseService):
    name = "fake_b"
    dependencies = ["fake_a"]

    def _on_start(self):
        CALLS.append("start_b")

    def _on_stop(self):
        CALLS.append("stop_b")


def _ctx_with_fakes(isolated_config, monkeypatch):
    def _register(self):
        self.registry.register(FakeA(self.config))
        self.registry.register(FakeB(self.config))

    monkeypatch.setattr(AppContext, "_register_services", _register)
    return AppContext(isolated_config)


def test_startup_shutdown_order(isolated_config, monkeypatch):
    CALLS.clear()
    ctx = _ctx_with_fakes(isolated_config, monkeypatch)
    with ctx:
        assert ctx.started is True
        assert [s.name for s in ctx.registry.startup_order()] == ["fake_a", "fake_b"]
        health = ctx.health_check()
        assert health["overall"] is True
    assert ctx.started is False
    assert CALLS == ["start_a", "start_b", "stop_b", "stop_a"]


def test_http_lifespan_and_audit(isolated_config, monkeypatch, auth_headers):
    CALLS.clear()
    ctx = _ctx_with_fakes(isolated_config, monkeypatch)
    app = create_app(isolated_config, ctx)

    with TestClient(app) as client:
        # Публичный эндпоинт без токена
        r = client.get("/api/whoami")
        assert r.status_code == 200
        assert r.json()["user"] == "admin"
        assert "X-Request-ID" in r.headers

        # Приватный без токена → 401
        assert client.get("/api/health").status_code == 401

        # Приватный с токеном → 200
        r = client.get("/api/health", headers=auth_headers)
        assert r.status_code == 200
        assert r.json()["overall"] is True

        # Мутация пишет audit
        r = client.post("/api/alertsack", headers=auth_headers, json={})
        assert r.status_code == 200
        r = client.get("/api/audit?limit=5", headers=auth_headers)
        assert r.status_code == 200
        actions = [e["action"] for e in r.json()["entries"]]
        assert "alertsack" in actions

        # Неизвестный API-путь с токеном → 404
        assert client.get("/api/nope", headers=auth_headers).status_code == 404

    assert ctx.started is False

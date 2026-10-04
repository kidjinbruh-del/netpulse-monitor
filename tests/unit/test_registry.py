"""Unit: ServiceRegistry — порядок, зависимости, циклы."""
import pytest

from netpulse.context import ServiceRegistry
from netpulse.services.base import BaseService
from netpulse.config import Config


def _svc(name, deps=None):
    cfg = Config()
    svc = BaseService.__new__(BaseService)
    BaseService.__init__(svc, cfg)
    svc.name = name
    svc.dependencies = list(deps or [])
    return svc


def test_startup_order_respects_dependencies():
    reg = ServiceRegistry()
    reg.register(_svc("c", ["b"]))
    reg.register(_svc("a"))
    reg.register(_svc("b", ["a"]))
    assert [s.name for s in reg.startup_order()] == ["a", "b", "c"]
    assert [s.name for s in reg.shutdown_order()] == ["c", "b", "a"]


def test_cycle_fallback_no_hang():
    reg = ServiceRegistry()
    reg.register(_svc("x", ["y"]))
    reg.register(_svc("y", ["x"]))
    order = [s.name for s in reg.startup_order()]
    assert sorted(order) == ["x", "y"]


def test_duplicate_registration_raises():
    reg = ServiceRegistry()
    reg.register(_svc("a"))
    with pytest.raises(ValueError):
        reg.register(_svc("a"))


def test_get_unregister_contains_len():
    reg = ServiceRegistry()
    assert len(reg) == 0
    reg.register(_svc("a"))
    assert "a" in reg and len(reg) == 1
    assert reg.get("a").name == "a"
    assert reg.get("missing") is None
    reg.unregister("a")
    assert "a" not in reg

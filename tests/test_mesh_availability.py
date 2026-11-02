"""Unavailable mesh is explicit; remote metrics must not use local CPU/RAM."""
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from netpulse.mesh import MeshError
from netpulse.server import Api


def api_for(mesh):
    api = Api.__new__(Api)
    api.mesh = mesh
    api.p2p_metrics_lock = threading.Lock()
    api.p2p_metrics_hist = {}
    return api


@pytest.mark.parametrize("handler", ["p2p_nodes", "p2p_services", "p2p_metrics", "p2p_call"])
@pytest.mark.parametrize("state,code", [(None, "mesh_not_configured"),
    ({"enabled": False, "connected": False}, "mesh_disabled"),
    ({"enabled": True, "connected": False}, "mesh_disconnected")])
def test_unavailable_mesh_does_not_probe(handler, state, code):
    mesh = SimpleNamespace(**state, call=Mock()) if state else None
    result = getattr(api_for(mesh), handler)({})
    assert result[0] == 503
    assert result[1]["code"] == code
    if mesh:
        mesh.call.assert_not_called()


def test_remote_hub_metrics_are_fetched_from_hub():
    def call(service, method, data, **kwargs):
        if method == "neighbors":
            return {"own": "RemoteHub", "connected": [{"node_id": "Branch"}]}
        return {"cpu": 12 if kwargs["dst"] == "RemoteHub" else 30, "mem_pct": 41}
    mesh = SimpleNamespace(enabled=True, connected=True, target="RemoteHub", call=Mock(side_effect=call))
    api = api_for(mesh)
    result = api.p2p_metrics({})
    assert result["nodes"]["RemoteHub"]["cpu"] == 12
    assert result["nodes"]["Branch"]["cpu"] == 30
    assert mesh.call.call_count == 3
    assert "host" not in result["nodes"]["RemoteHub"]


def test_failed_topology_never_fabricates_local_node_metrics():
    mesh = SimpleNamespace(enabled=True, connected=True, target="RemoteHub", call=Mock(side_effect=MeshError("offline")))
    result = api_for(mesh).p2p_metrics({})
    assert result[0] == 502
    assert result[1]["code"] == "mesh_topology_failed"
    mesh.call.assert_called_once()

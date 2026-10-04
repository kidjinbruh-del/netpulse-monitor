"""Unit: legacy_adapter, to_legacy_dict, ConfigLoader."""
from netpulse.config import (
    Config, ConfigLoader, adapt_legacy, load_config_dict,
)
from netpulse.config.legacy_export import legacy_p2p_client_cfg, to_legacy_dict


def test_adapt_legacy_flat_keys():
    out = adapt_legacy({
        "web_host": "0.0.0.0",
        "web_port": 9999,
        "web_token": "abc",
        "ping_interval_sec": 5,
        "ping_target": "1.1.1.1",
    })
    assert out["web"]["host"] == "0.0.0.0"
    assert out["web"]["port"] == 9999
    assert out["web"]["token"] == "abc"
    assert out["ping"]["interval_sec"] == 5
    assert out["ping"]["targets"] == ["1.1.1.1"]


def test_adapt_legacy_web_tls_and_mtr_target():
    out = adapt_legacy({
        "web_tls": {"enabled": True, "cert": "c.pem", "key": "k.pem"},
        "mtr": {"target": "8.8.8.8"},
        "speedtest": {"bytes": 1000},
    })
    assert out["web"]["tls_enabled"] is True
    assert out["web"]["tls_cert"] == "c.pem"
    assert out["mtr"]["targets"] == ["8.8.8.8"]
    assert out["speedtest"]["bytes_down"] == 1000


def test_p2p_targets_coercion():
    cfg = Config(p2p={"targets": [
        {"node_id": "node0", "port": 9000},
        "node1:9001",
    ]})
    assert cfg.p2p.targets == ["node0:9000", "node1:9001"]


def test_to_legacy_dict_roundtrip(isolated_config):
    legacy = to_legacy_dict(isolated_config)
    assert legacy["web_port"] == 8771
    assert legacy["web_token"] == "test-token"
    assert legacy["ping_target"] in legacy.get("ping_targets", [legacy["ping_target"]])
    assert isinstance(legacy["ai"], dict)
    assert isinstance(legacy["backup"], dict)


def test_legacy_p2p_client_cfg_shape(isolated_config):
    cfg = legacy_p2p_client_cfg(isolated_config)
    assert isinstance(cfg["targets"], list)
    assert "node_id" in cfg and "port" in cfg and "secret" in cfg


def test_loader_update_protects_auth(tmp_path):
    path = tmp_path / "cfg.json"
    path.write_text("{}", encoding="utf-8")
    loader = ConfigLoader(str(path))
    loader.load()
    updated = loader.update({"web_auth_enabled": False, "web": {"port": 1234}})
    assert updated.web.auth_enabled is True  # protected
    assert updated.web.port == 1234


def test_real_config_json_loads():
    raw = load_config_dict("config.json")
    assert isinstance(raw, dict)
    assert "web_port" in raw

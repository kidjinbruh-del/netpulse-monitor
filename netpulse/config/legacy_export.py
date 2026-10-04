"""Экспорт v3 Config в flat-dict монитора (для MonitorService-бэкендов).

Приоритет: сырой legacy_raw (все неизвестные v3 секции: lan, quality,
email, webhook, ...) + поверх v3-значения (приоритет у v3).
"""
from copy import deepcopy
from typing import Any, Dict

from .defaults import Config


def to_legacy_dict(config: Config) -> Dict[str, Any]:
    raw = deepcopy(config.legacy_raw) if config.legacy_raw else {}
    out: Dict[str, Any] = dict(raw)
    web = config.web

    # --- плоские web-* ключи ---
    out["web_host"] = web.host
    out["web_port"] = web.port
    out["web_auth_enabled"] = web.auth_enabled
    out["web_token"] = web.token
    out["web_admins"] = [dict(a) for a in (web.admins or [])]
    out["web_users"] = [dict(u) for u in (web.users or [])]
    out["web_cors_origins"] = list(web.cors_origins or [])
    out["web_tls"] = {"enabled": web.tls_enabled, "cert": web.tls_cert, "key": web.tls_key}

    # --- ping ---
    out["ping_interval_sec"] = config.ping.interval_sec
    if config.ping.targets:
        out["ping_target"] = config.ping.targets[0]
        out["ping_targets"] = list(config.ping.targets)

    # --- вложенные секции v3 (перезаписывают legacy) ---
    out["mtr"] = config.mtr.model_dump(mode="json")
    if not out["mtr"].get("targets") and config.mtr.model_dump().get("targets"):
        pass
    out["speedtest"] = config.speedtest.model_dump(mode="json")
    out["speedtest"]["bytes"] = config.speedtest.bytes_down
    out["diagnostics"] = config.diagnostics.model_dump(mode="json")
    out["ids"] = config.ids.model_dump(mode="json")
    out["ai"] = config.ai.model_dump(mode="json")
    out["quota"] = config.quota.model_dump(mode="json")
    out["backup"] = config.backup.model_dump(mode="json")
    out["backupwatch"] = config.backupwatch.model_dump(mode="json")
    out["planner"] = config.planner.model_dump(mode="json")
    out["infra"] = config.infra.model_dump(mode="json")
    out["cve"] = config.cve.model_dump(mode="json")
    out["proxmox"] = config.proxmox.model_dump(mode="json")
    out["p2p"] = _legacy_p2p(config)
    out["security"] = config.security.model_dump(mode="json")
    out["telegram"] = config.telegram.model_dump(mode="json")
    out["ip_allowlist"] = config.ip_allowlist.model_dump(mode="json")

    return out


def _legacy_p2p(config: Config) -> Dict[str, Any]:
    """P2P-секция в legacy-формате (targets — список {node_id, port})."""
    p = config.p2p
    raw_targets = (config.legacy_raw.get("p2p") or {}).get("targets") if config.legacy_raw else None
    targets = []
    if isinstance(raw_targets, list) and raw_targets and isinstance(raw_targets[0], dict):
        targets = raw_targets
    else:
        for t in (p.targets or []):
            if isinstance(t, str) and ":" in t:
                node, _, port = t.rpartition(":")
                try:
                    targets.append({"node_id": node or "node", "port": int(port)})
                except ValueError:
                    targets.append({"node_id": t, "port": p.port})
            elif isinstance(t, dict):
                targets.append(t)
    return {
        "enabled": p.enabled,
        "targets": targets,
        "target_node": p.target_node or p.target or (targets[0].get("node_id") if targets else ""),
        "node_id": p.node_id,
        "port": p.port,
        "host": p.host,
        "secret": p.secret,
        "call_timeout": p.call_timeout,
        "reconnect_sec": p.reconnect_sec,
    }


def legacy_p2p_client_cfg(config: Config) -> Dict[str, Any]:
    """Конфиг для MeshClient/MeshHub (legacy p2p-секция)."""
    return _legacy_p2p(config)

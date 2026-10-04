"""Map routes: топология сети, healing, custom checks."""
import asyncio
import socket

from fastapi import APIRouter, Depends

from netpulse.server.dependencies import get_ctx, get_service

router = APIRouter(prefix="/api", tags=["map"])


def _map_layer(kind, online, ip, gw):
    if kind == "router":
        return "wan"
    if kind == "switch":
        return "sw"
    if kind in ("server", "infra"):
        return "srv"
    if kind == "pc":
        return "pc"
    return "offline" if not online else "host"


@router.get("/map")
async def topology_map(infra= get_service("infra"), ctx= Depends(get_ctx)):
    devices = infra.device_list()
    gw = infra.gateway_ip()
    try:
        self_name = socket.gethostname()
    except Exception:
        self_name = "self"
    aliases_by_ip, hostnames_by_ip = {}, {}
    try:
        for r in (ctx.db.execute(
                "SELECT ip, alias, hostname FROM lan_devices", fetch=True) or []):
            if not r.get("ip"):
                continue
            ip = r["ip"]
            alias, hn = r.get("alias"), r.get("hostname")
            if alias and str(alias).strip() and ip not in aliases_by_ip:
                aliases_by_ip[ip] = alias
            if hn and str(hn).strip() and str(hn).strip() != "-" \
                    and ip not in hostnames_by_ip:
                hostnames_by_ip[ip] = hn
    except Exception:
        pass
    self_ip = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect((gw or "8.8.8.8", 80))
        self_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass
    nodes, seen_ip = [], set()
    nodes.append({"name": self_name, "ip": self_ip,
                  "alias": aliases_by_ip.get(self_ip, ""),
                  "hostname": hostnames_by_ip.get(self_ip, ""),
                  "kind": "master", "online": True, "karma": 100,
                  "sys_name": self_name, "sys_descr": "",
                  "uptime_h": None, "snmp": False, "vendor": "",
                  "os": "", "layer": "pc"})
    if self_ip:
        seen_ip.add(self_ip)
    if gw:
        gw_row = next((x for x in devices if x.get("ip") == gw), {})
        nodes.append({"name": "шлюз", "ip": gw,
                      "alias": aliases_by_ip.get(gw, ""),
                      "hostname": hostnames_by_ip.get(gw, ""),
                      "kind": "router", "online": True, "karma": 100,
                      "sys_name": gw_row.get("sys_name") or "",
                      "sys_descr": gw_row.get("sys_descr") or "",
                      "uptime_h": gw_row.get("uptime_h"),
                      "snmp": bool(gw_row.get("snmp_at")),
                      "vendor": gw_row.get("vendor") or "",
                      "os": gw_row.get("os") or "",
                      "layer": "wan"})
        seen_ip.add(gw)
    for h in devices:
        ip = h.get("ip") or ""
        if not ip or ip in seen_ip:
            continue
        kind = h.get("dtype") or ("router" if ip == gw else "host")
        online = bool(h.get("online"))
        node = {
            "name": h.get("name"), "ip": ip,
            "alias": aliases_by_ip.get(ip, ""),
            "hostname": hostnames_by_ip.get(ip, ""),
            "kind": kind, "online": online,
            "karma": h.get("health_score", 100),
            "sys_name": h.get("sys_name") or "",
            "sys_descr": h.get("sys_descr") or "",
            "uptime_h": h.get("uptime_h"),
            "snmp": bool(h.get("snmp_at")),
            "vendor": h.get("vendor") or "",
            "os": h.get("os") or "",
        }
        node["layer"] = _map_layer(kind, online, ip, gw)
        nodes.append(node)
        seen_ip.add(ip)
    return {"nodes": nodes, "self_ip": self_ip, "gateway": gw}


@router.get("/healing")
async def healing_status(healing= get_service("healing")):
    return healing.status_list()


@router.get("/customchecks")
async def customchecks(customchecks= get_service("customchecks")):
    return customchecks.results()


@router.post("/customchecksrun")
async def customchecks_run(customchecks= get_service("customchecks")):
    return await asyncio.to_thread(customchecks.run_all, True)

"""P2P routes: мост в решётку, узлы, сервисы, метрики."""
import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from netpulse.mesh import MeshError
from netpulse.server.dependencies import get_config, get_service

router = APIRouter(prefix="/api", tags=["p2p"])


class P2PCallBody(BaseModel):
    service: str = ""
    method: str = ""
    data: dict = {}
    node: str = ""
    dst: str = ""


@router.get("/p2pstatus")
async def p2p_status(mesh= get_service("mesh")):
    if mesh._mesh is None:
        return {"ok": False, "error": "P2P-мост не создан"}
    return {"ok": True, **mesh.status_dict}


@router.get("/p2pnodes")
async def p2p_nodes(mesh= get_service("mesh")):
    return await mesh.nodes_info()


@router.get("/p2pservices")
async def p2p_services(node: str = Query(""), mesh= get_service("mesh")):
    return await mesh.services_info(node or None)


@router.get("/p2pmetrics")
async def p2p_metrics(mesh= get_service("mesh"), config= Depends(get_config)):
    return await mesh.metrics_snapshot(web_port=config.web.port)


@router.post("/p2pcall")
async def p2p_call(body: P2PCallBody, mesh= get_service("mesh")):
    service = (body.service or "").strip()
    method = (body.method or "").strip()
    if not service or not method:
        raise HTTPException(400, "нужны service и method")
    dst = body.node or body.dst or mesh.target
    if not dst:
        raise HTTPException(503, "P2P-мост не создан")
    try:
        result = await asyncio.to_thread(
            mesh.call, service, method, body.data or {}, dst)
        return {"ok": True, "result": result}
    except RuntimeError as e:
        raise HTTPException(503, str(e))
    except MeshError as e:
        raise HTTPException(502, str(e))

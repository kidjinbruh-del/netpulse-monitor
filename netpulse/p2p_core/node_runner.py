"""Универсальный запускатель узлов P2P_Core из единого кода netpulse.p2p_core.

Используется node0/node1 вместо локальных копий src/. Запуск:
    python -m netpulse.p2p_core.node_runner --workdir <каталог_узла>
"""

import asyncio
import logging
import os
import sys
import traceback
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent if not getattr(sys, 'frozen', False) else Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parent))


def _normalize_path(p):
    if isinstance(p, Path):
        return str(p)
    return str(Path(p))


def main():
    nodes_dir = None
    for i, a in enumerate(sys.argv):
        if a == '--workdir' and i + 1 < len(sys.argv):
            nodes_dir = sys.argv[i + 1]
    if not nodes_dir:
        nodes_dir = os.environ.get('NETPULSE_NODE_DIR')
    if not nodes_dir:
        # по умолчанию — текущий каталог (там config.yaml у запускаемого узла)
        nodes_dir = os.getcwd()

    nodes_dir = Path(nodes_dir).resolve()
    if not nodes_dir.exists():
        print(f'Нет каталога узла: {nodes_dir}', file=sys.stderr)
        return 1

    # рабочий каталог узла — чтобы config.yaml и services/ находились рядом
    os.chdir(nodes_dir)

    import netpulse.p2p_core.internal_modules.config as cfgmod
    cfg = cfgmod.load_config(nodes_dir / 'config.yaml')
    node_name = cfg.cfg.node

    try:
        # перенаправляем вывод логов в файлы узла (если настроено)
        from netpulse.p2p_core.internal_modules.config import LoggingConfig
        logs_cfg = cfg.cfg.logging
        log_file = logs_cfg.log_file if hasattr(logs_cfg, 'log_file') else None
    except Exception:
        log_file = None

    import colorama
    colorama.init()

    from netpulse.p2p_core.internal_modules.context import AppContext, app_lifespan
    from netpulse.p2p_core.internal_modules.memory import MemoryModule
    from netpulse.p2p_core.internal_modules.setup_logging import setup_logging
    from netpulse.p2p_core.internal_modules.spawner import Spawner
    from netpulse.p2p_core.internal_modules.updater import Updater
    from netpulse.p2p_core.networking.network import NetworkModule
    from netpulse.p2p_core.networking.node_connector import NodeConnector
    from netpulse.p2p_core.services.loader import ServiceLoader
    from netpulse.p2p_core.services.rpc import get_rpc_methods

    async def _run():
        ctx = AppContext(cfg.cfg)
        ctx.config_manager = cfg

        ctx.memory = ctx.register(MemoryModule(name='memory', context=ctx))
        ctx.network = ctx.register(NetworkModule(
            name='network', context=ctx,
            host=cfg.cfg.network.host, port=cfg.cfg.network.port,
        ))
        ctx.spawn = ctx.register(Spawner(name='spawner', context=ctx))
        ctx.services.register_service(ctx.spawn)
        ctx.services.register_method(ctx.spawn, 'spawn', ctx.spawn.spawn)
        ctx.services.register_method(ctx.spawn, 'list_generators', ctx.spawn.list_generators)

        ctx.updater = ctx.register(Updater(name='updater', context=ctx))
        ctx.services.register_service(ctx.updater)
        for _mname, _m in get_rpc_methods(ctx.updater).items():
            ctx.services.register_method(ctx.updater, _mname, _m)

        ctx.network.app.state.ctx = ctx

        # единый каталог сервисов — netpulse.p2p_core.services
        services_dir = Path(__file__).resolve().parent / 'services'
        loader = None
        if services_dir.exists():
            loader = ServiceLoader(
                services_path=services_dir,
                context=ctx,
                services_manager=ctx.services,
            )
            loader.scan()
            try:
                loader.watch()
            except Exception:
                pass

        for peer in cfg.cfg.local.peers:
            ctx.register(NodeConnector(
                name=f'Connector_{peer.node_id}',
                context=ctx,
                peer_node_id=peer.node_id,
                target_uri=f'{peer.uri}{ctx.NODE}',
            ))

        try:
            async with app_lifespan(ctx):
                await asyncio.Event().wait()
        finally:
            if loader:
                try:
                    loader.stop_watch()
                except Exception:
                    pass

    try:
        asyncio.run(_run())
        return 0
    except KeyboardInterrupt:
        return 0
    except Exception:
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
import asyncio
import logging
import os
import sys
import time
from pathlib import Path

import colorama
import psutil

colorama.init()

# Updater: _update.exe самозапуск — замена бинарника с watchdog.
# Должен быть ДО любых инициализаций (mutex, логи), чтобы не мешать старой версии.
if '--updater' in sys.argv:
    try:
        from netpulse.p2p_core.internal_modules.update import updater_main
        sys.exit(updater_main())
    except SystemExit:
        raise
    except Exception as e:
        try:
            import traceback
            traceback.print_exc()
        except Exception:
            pass
        sys.exit(1)

# ConfigUpdater: рестарт по конфигу (копия технологии updater)
if '--config-restart' in sys.argv:
    try:
        from netpulse.p2p_core.internal_modules.config_update import config_updater_main
        sys.exit(config_updater_main())
    except SystemExit:
        raise
    except Exception as e:
        try:
            import traceback
            traceback.print_exc()
        except Exception:
            pass
        sys.exit(1)

# update-failed — диагностический флаг после неудачного отката (показывает сообщение)
if '--update-failed' in sys.argv:
    print("[Updater] update failed — rolled back to previous version", file=sys.stderr)

# EyeSauron: хелпер захвата экрана запускается ЭТИМ ЖЕ exe в сессии
# пользователя (WTS-инъекция из сервиса eyesauron). Перехватываем argv до
# инициализации узла: процесс работает как лёгкий захватчик и завершается.
if '--eye-sauron-helper' in sys.argv:
    try:
        from netpulse.p2p_core.services.eyesauron._session_helper import main as _eye_helper_main
        _eye_helper_main()
        sys.exit(0)
    except Exception:
        sys.exit(0)
# ВАЖНО: Ставим перехват на самый верх файла, ДО инициализации Click/Typer/Asyncio
# Проверяем, есть ли ключевые слова запуска Streamlit в аргументах
if "-m" in sys.argv and "streamlit" in sys.argv:
    import streamlit.web.cli as stcli

    # Находим, где именно в массиве стоят эти маркеры, и вырезаем их
    try:
        m_index = sys.argv.index("-m")
        # Вырезаем '-m' и следующий за ним 'streamlit'
        if m_index + 1 < len(sys.argv) and sys.argv[m_index + 1] == "streamlit":
            del sys.argv[m_index:m_index + 2]
    except ValueError:
        pass

    # На всякий случай выводим в консоль, что перехват сработал (для теста)
    # print("[DEBUG] Streamlit-перехват сработал! Аргументы для cli:", sys.argv)

    # Запускаем Streamlit и намертво гасим процесс для Click/Typer

    sys.exit(stcli.main())

from netpulse.p2p_core.services.loader import ServiceLoader
from netpulse.p2p_core.services.rpc import get_rpc_methods
from netpulse.p2p_core.internal_modules.config import load_config
from netpulse.p2p_core.internal_modules.context import AppContext, app_lifespan
from netpulse.p2p_core.internal_modules.memory import MemoryModule
from netpulse.p2p_core.internal_modules.setup_logging import setup_logging
from netpulse.p2p_core.internal_modules.spawner import Spawner
from netpulse.p2p_core.internal_modules.updater import Updater
from netpulse.p2p_core.networking.network import NetworkModule
from netpulse.p2p_core.networking.node_connector import NodeConnector

# Каталог развёртывания. У frozen-узла — каталог exe: планировщик
# (особенно /SC ONSTART под SYSTEM) запускает процесс с cwd=System32,
# и привязка к cwd унесла бы config.yaml/services в Windows-каталоги.
if getattr(sys, 'frozen', False):
    BASE_DIR = Path(sys.executable).parent
else:
    BASE_DIR = Path(__file__).resolve().parent

# хендл мьютекса единственной инстанции — держим ссылку, иначе GC
# освободит мьютекс и защита исчезнет
_single_instance_handle = None


def acquire_single_instance(node_name: str) -> bool:
    """Запрет второй инстанции узла на хосте через именованный mutex.

    Задача планировщика (SYSTEM) и ключ реестра Run (пользователь) срабатывают
    оба — без защиты второй процесс становился зомби без сети (порт занят,
    а uvicorn гасит свой serve-таск изнутри через sys.exit).
    Global\\ — один namespace на все сессии, включая session 0 SYSTEM'а.
    """
    global _single_instance_handle
    import ctypes

    handle = ctypes.windll.kernel32.CreateMutexW(
        None, False, f'Global\\P2P_Core_{node_name}')
    if not handle:
        # мьютекс создать не удалось — безопаснее не стартовать вовсе
        logging.error(f'CreateMutexW failed: {ctypes.GetLastError()}')
        return False
    _single_instance_handle = handle
    ERROR_ALREADY_EXISTS = 183
    exists = ctypes.windll.kernel32.GetLastError() == ERROR_ALREADY_EXISTS
    if exists:
        logging.warning(
            f'Узел "{node_name}" уже запущен на этой машине — '
            f'второй инстанс не стартует')
        return False
    return True



logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logging.getLogger("uvicorn").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
logging.getLogger("fastapi").setLevel(logging.WARNING)


async def main():
    cfg_manager = load_config(BASE_DIR / 'config.yaml')
    cfg = cfg_manager.cfg

    # единственная инстанция на хосте (двойной автозапуск: планировщик + реестр)
    if not acquire_single_instance(cfg.local.name):
        return
    setup_logging(cfg.logging)

    ctx = AppContext(cfg)
    ctx.config_manager = cfg_manager

    # порядок вызовов = порядок загрузки
    ctx.memory = ctx.register(MemoryModule(name='memory', context=ctx))
    ctx.network = ctx.register(NetworkModule(name='network',
                                             context=ctx,
                                             host=cfg.network.host,
                                             port=cfg.network.port, ))

    # Spawner — не в services/, регистрируем вручную
    ctx.spawn = ctx.register(Spawner(name='spawner', context=ctx))
    ctx.services.register_service(ctx.spawn)
    ctx.services.register_method(ctx.spawn, 'spawn', ctx.spawn.spawn)
    ctx.services.register_method(ctx.spawn, 'list_generators', ctx.spawn.list_generators)

    # Updater — ядерный модуль (перенесен из services/updater)
    ctx.updater = ctx.register(Updater(name='updater', context=ctx))
    ctx.services.register_service(ctx.updater)
    for _mname, _m in get_rpc_methods(ctx.updater).items():
        ctx.services.register_method(ctx.updater, _mname, _m)

    # пробрасываем ctx в роуты FastAPI
    ctx.network.app.state.ctx = ctx

    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        SERVICES_DIR = Path(sys._MEIPASS) / 'services'
        frozen_loader = ServiceLoader(
            services_path=SERVICES_DIR,
            context=ctx,
            services_manager=ctx.services,
        )
        frozen_loader.scan()
    except Exception as e:
        SERVICES_DIR = os.path.abspath("./services")
        print('Frozen services path not found:', e)

    if not os.path.exists(SERVICES_DIR):
        os.makedirs(SERVICES_DIR)

    loader = None
    if os.path.exists(BASE_DIR / 'services'):
        # автозагрузка всех сервисов из ./services/ (live editing available)
        loader = ServiceLoader(
            services_path=BASE_DIR / 'services',
            context=ctx,
            services_manager=ctx.services,
        )
        loader.scan()
        loader.watch()  # hot reload local services

    # автозагрузка всех сервисов из MEI_/services/

    for peer in cfg.local.peers:
        connector = ctx.register(NodeConnector(
            name=f'Connector_{peer.node_id}',
            context=ctx,
            peer_node_id=peer.node_id,
            target_uri=f'{peer.uri}{ctx.NODE}',
        ))

    try:
        async with app_lifespan(ctx):
            # всё поднято — основной цикл
            await asyncio.Event().wait()  # бесконечное ожидание
    finally:
        # watchdog обязан останавливаться при shutdown (иначе поток Observer
        # не даёт процессу завершиться)
        if loader:
            loader.stop_watch()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass

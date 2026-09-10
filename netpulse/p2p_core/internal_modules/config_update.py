# src/internal_modules/config_update.py — ядро рестарта по конфигу
#
# Копия технологии updater: ждёт завершения старой ноды, освобождения портов
# из config.yaml, пауза на файловые дескрипторы, старт ноды заново, watchdog
# config_confirm_sec, лог в updater.log.
# Запускается как frozen копия _update.exe с ключом --config-restart.

import argparse
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

from netpulse.p2p_core.internal_modules.restart_core import (
    POLL_SEC,
    collect_ports_from_config,
    is_process_alive as _is_process_alive,
    kill_streamlit_processes as _kill_streamlit_processes,
    launch_new_version as _launch_new_version,
    wait_old_process_gone as _wait_old_process_gone,
    wait_ports_free,
)

CONFIG_RESTART_FLAG = "--config-restart"

log = logging.getLogger("ConfigUpdater")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument(CONFIG_RESTART_FLAG, action="store_true")
    p.add_argument("--old-pid", type=int, required=True)
    p.add_argument("--old-exe", type=str, required=True)
    p.add_argument("--work-dir", type=str, default=".")
    p.add_argument("--config-path", type=str, default="config.yaml")
    p.add_argument("--health-confirm-sec", type=int, default=15)
    return p.parse_args(argv)


def is_config_restart_mode(argv: list[str] | None = None) -> bool:
    a = argv if argv is not None else sys.argv
    return CONFIG_RESTART_FLAG in a


def _load_ports_from_config_file(cfg_path: Path) -> list[int]:
    """Попытаться загрузить Config из файла и собрать порты. Fallback 9000+8501."""
    try:
        from netpulse.p2p_core.internal_modules.config import ConfigManager
        # ConfigManager ожидает путь к config.yaml
        cm = ConfigManager(cfg_path)
        return collect_ports_from_config(cm.cfg)
    except Exception as e:
        log.warning(f"collect ports from {cfg_path} failed: {e}, fallback [9000,8501]")
        return [9000, 8501]


def config_updater_main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        args = _parse_args(argv if CONFIG_RESTART_FLAG in argv else [CONFIG_RESTART_FLAG] + argv)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 1
    except Exception as e:
        print(f"config updater arg parse failed: {e}", file=sys.stderr)
        return 1

    work_dir = Path(args.work_dir) if args.work_dir else Path(".")
    cfg_path = Path(args.config_path) if args.config_path else work_dir / "config.yaml"

    # логирование — тот же файл что и у updater
    try:
        work_dir.mkdir(parents=True, exist_ok=True)
        log_dir = work_dir / "updates"
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_dir / "updater.log", encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s"))
        stream = sys.stdout if sys.stdout else sys.stderr
        sh = logging.StreamHandler(stream) if stream else logging.StreamHandler()
        sh.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(levelname)s: %(message)s"))
        root = logging.getLogger()
        for h in list(root.handlers):
            try:
                root.removeHandler(h)
            except Exception:
                pass
        root.addHandler(fh)
        root.addHandler(sh)
        root.setLevel(logging.INFO)
    except Exception:
        pass

    old_exe = Path(args.old_exe)
    updater_exe = Path(sys.executable) if getattr(sys, "frozen", False) else Path(__file__).resolve()

    log.info(f"ConfigUpdater started: old_pid={args.old_pid} old_exe={old_exe} cfg={cfg_path} health={args.health_confirm_sec}")

    # 1. ждать завершения старой ноды
    log.info(f"Waiting for old process {args.old_pid} ({old_exe.name}) to exit...")
    ok = _wait_old_process_gone(args.old_pid, old_exe.name, timeout=30)
    if not ok:
        log.warning(f"Old pid {args.old_pid} still alive after 30s — continue anyway")
        time.sleep(2)

    # 2. убить streamlit
    killed = _kill_streamlit_processes()
    if killed:
        log.info(f"Killed {killed} streamlit processes")

    # 3. ждать освобождения портов из конфига + пауза на дескрипторы
    ports = _load_ports_from_config_file(cfg_path)
    log.info(f"Waiting for ports {ports} to free...")
    freed = wait_ports_free(ports, timeout=15)
    if not freed:
        log.warning(f"Ports {ports} not freed after 15s — continue anyway")
    # пауза на файловые дескрипторы
    time.sleep(2)

    # 4. старт ноды заново
    # dev: old_exe — python, нужно запустить main.py
    if not getattr(sys, 'frozen', False) or 'python' in old_exe.name.lower():
        try:
            creationflags = 0
            if os.name == "nt":
                creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)
            # main.py — в корне проекта / рядом с config.yaml
            main_py = work_dir / "main.py"
            if not main_py.is_file():
                # fallback: рядом с helper'ом (project root)
                main_py = Path(__file__).resolve().parents[2] / "main.py"
            proc = subprocess.Popen(
                [str(old_exe), str(main_py)],
                cwd=str(work_dir),
                creationflags=creationflags,
                close_fds=False,
            )
            new_pid = proc.pid
        except OSError as e:
            log.error(f"Failed to launch dev version: {e}")
            new_pid = None
    else:
        new_pid = _launch_new_version(old_exe, work_dir)
    if new_pid is None:
        log.error("Failed to launch new version after config restart")
        return 3

    log.info(f"Launched new version pid={new_pid}, waiting {args.health_confirm_sec}s health...")

    deadline = time.time() + max(5, int(args.health_confirm_sec))
    failed = False
    while time.time() < deadline:
        if not _is_process_alive(new_pid):
            log.error(f"New process {new_pid} died before health confirm ({args.health_confirm_sec}s)")
            failed = True
            break
        time.sleep(POLL_SEC)

    if not failed and not _is_process_alive(new_pid):
        failed = True
        log.error("New process not alive at health deadline")

    if failed:
        log.error("Config restart failed: node died during health check")
        return 4

    log.info(f"Config restart success: pid={new_pid} alive after {args.health_confirm_sec}s")
    return 0

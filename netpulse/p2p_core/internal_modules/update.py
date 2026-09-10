# src/internal_modules/update.py — ядро обновления (watchdog + замена бинарника)
#
# Выделено из services/updater чтобы работать до инициализации узла.
# Запускается как frozen копия _update.exe с ключами (--updater ...).
# Отвечает за: ожидание завершения старого процесса, убийство streamlit,
# атомарную замену exe, запуск новой версии, watchdog health_confirm_sec,
# откат копированием себя при неудаче.

import argparse
import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import netpulse.p2p_core.internal_modules.restart_core as _rc
from netpulse.p2p_core.internal_modules.restart_core import POLL_SEC, _sha256

try:
    import psutil as _psutil_mod
    psutil = _psutil_mod
except ImportError:
    psutil = None  # type: ignore


def _wait_old_process_gone(old_pid: int, old_exe_name: str, timeout: float = 30) -> bool:
    orig = _rc.psutil
    _rc.psutil = psutil
    try:
        return _rc.wait_old_process_gone(old_pid, old_exe_name, timeout)
    finally:
        _rc.psutil = orig


def _kill_streamlit_processes() -> int:
    orig = _rc.psutil
    _rc.psutil = psutil
    try:
        return _rc.kill_streamlit_processes()
    finally:
        _rc.psutil = orig


def _launch_new_version(exe_path: Path, work_dir: Path) -> int | None:
    return _rc.launch_new_version(exe_path, work_dir)


def _is_process_alive(pid: int) -> bool:
    orig = _rc.psutil
    _rc.psutil = psutil
    try:
        return _rc.is_process_alive(pid)
    finally:
        _rc.psutil = orig

UPDATER_SUFFIX = "_update.exe"
UPDATER_FLAG = "--updater"

log = logging.getLogger("UpdaterCore")


def _parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument(UPDATER_FLAG, action="store_true")
    p.add_argument("--old-pid", type=int, required=True)
    p.add_argument("--old-exe", type=str, required=True, help="путь к старому exe (цель замены)")
    p.add_argument("--staged", type=str, required=True, help="путь к новому скачанному exe")
    p.add_argument("--work-dir", type=str, default=".")
    p.add_argument("--health-confirm-sec", type=int, default=90)
    p.add_argument("--from-version", type=str, default="")
    p.add_argument("--to-version", type=str, default="")
    return p.parse_args(argv)


def is_updater_mode(argv: list[str] | None = None) -> bool:
    a = argv if argv is not None else sys.argv
    return UPDATER_FLAG in a


def _replace_binary(old_exe: Path, staged: Path, updater_exe: Path) -> tuple[bool, str]:
    """Атомарно заменить old_exe на staged. updater_exe — наша копия (старая версия)."""
    try:
        if not staged.is_file():
            return False, f"staged не найден: {staged}"
        old_old = old_exe.with_name(old_exe.name + ".old")
        try:
            old_old.unlink(missing_ok=True)
        except OSError:
            pass
        if old_exe.is_file():
            try:
                os.replace(old_exe, old_old)
            except OSError as e:
                return False, f"не удалось переименовать старый exe: {e}"
        try:
            shutil.copyfile(staged, old_exe)
        except OSError as e:
            try:
                if old_old.is_file() and not old_exe.is_file():
                    os.replace(old_old, old_exe)
            except OSError:
                pass
            return False, f"copy staged -> exe failed: {e}"
        try:
            if _sha256(old_exe) != _sha256(staged):
                try:
                    os.replace(old_old, old_exe)
                except OSError:
                    pass
                return False, "sha256 нового exe не совпал после копирования"
        except OSError as e:
            return False, f"sha256 check failed: {e}"
        return True, ""
    except Exception as e:
        return False, str(e)


def _rollback(updater_exe: Path, target_exe: Path, work_dir: Path) -> bool:
    try:
        shutil.copyfile(updater_exe, target_exe)
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)
        subprocess.Popen(
            [str(target_exe), "--update-failed"],
            cwd=str(work_dir),
            creationflags=creationflags,
            close_fds=False,
        )
        return True
    except Exception as e:
        log.error(f"rollback failed: {e}")
        return False


def updater_main(argv: list[str] | None = None) -> int:
    """Точка входа _update.exe. Возвращает код выхода."""
    if argv is None:
        argv = sys.argv[1:]
    try:
        args = _parse_args(argv if UPDATER_FLAG in argv else [UPDATER_FLAG] + argv)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 1
    except Exception as e:
        print(f"updater arg parse failed: {e}", file=sys.stderr)
        return 1

    work_dir = Path(args.work_dir) if args.work_dir else Path(".")
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
    staged = Path(args.staged)
    updater_exe = Path(sys.executable) if getattr(sys, "frozen", False) else Path(__file__).resolve()

    log.info(f"Updater started: old_pid={args.old_pid} old_exe={old_exe} staged={staged} updater={updater_exe} health={args.health_confirm_sec}")

    log.info(f"Waiting for old process {args.old_pid} ({old_exe.name}) to exit...")
    ok = _wait_old_process_gone(args.old_pid, old_exe.name, timeout=30)
    if not ok:
        log.warning(f"Old pid {args.old_pid} still alive after 30s — forcing? Continue anyway")
        time.sleep(2)

    killed = _kill_streamlit_processes()
    if killed:
        log.info(f"Killed {killed} streamlit processes")

    ok, err = _replace_binary(old_exe, staged, updater_exe)
    if not ok:
        log.error(f"Replace failed: {err}")
        return 2

    log.info(f"Binary replaced: {old_exe} <- {staged}")

    new_pid = _launch_new_version(old_exe, work_dir)
    if new_pid is None:
        log.error("Failed to launch new version — rollback")
        _rollback(updater_exe, old_exe, work_dir)
        return 3

    log.info(f"Launched new version pid={new_pid}, waiting {args.health_confirm_sec}s health...")

    deadline = time.time() + max(5, int(args.health_confirm_sec))
    failed = False
    while time.time() < deadline:
        if not _is_process_alive(new_pid):
            log.error(f"New process {new_pid} died before health confirm — rollback")
            failed = True
            break
        time.sleep(POLL_SEC)

    if not failed:
        if not _is_process_alive(new_pid):
            failed = True
            log.error("New process not alive at health deadline — rollback")

    if failed:
        _rollback(updater_exe, old_exe, work_dir)
        log.info("Rollback launched")
        return 4

    log.info(f"Update success: {args.from_version} -> {args.to_version} pid={new_pid} alive")
    try:
        if os.name == "nt":
            creationflags = getattr(subprocess, "DETACHED_PROCESS", 0) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            creationflags |= 0x08000000
            subprocess.Popen(
                ["cmd", "/c", f'timeout /t 2 /nobreak >nul & del /f /q "{updater_exe}"'],
                creationflags=creationflags,
                close_fds=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
    except Exception:
        pass

    try:
        import json
        state_path = work_dir / "update_state.json"
        if state_path.is_file():
            st = json.loads(state_path.read_text(encoding="utf-8"))
            st["boot_ok"] = True
            st["confirmed_at"] = time.time()
            state_path.write_text(json.dumps(st, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception:
        pass

    return 0


def get_updater_exe_path(current_exe: Path) -> Path:
    """Путь к _update.exe рядом с текущим exe."""
    return current_exe.with_name(current_exe.stem + UPDATER_SUFFIX) if current_exe.suffix else Path(str(current_exe) + UPDATER_SUFFIX)

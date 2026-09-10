# src/internal_modules/restart_core.py — общие примитивы перезапуска узла
#
# Выделено из src/internal_modules/update.py для переиспользования
# updater'ом и config-рестартом (вариант B).
# Содержит: ожидание завершения старого процесса, убийство streamlit,
# ожидание освобождения портов, запуск новой версии, проверку живости.

import logging
import os
import socket
import subprocess
import time
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore

log = logging.getLogger("RestartCore")

POLL_SEC = 0.5
KILL_TIMEOUT_SEC = 3


def _sha256(path: Path) -> str:
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def wait_old_process_gone(old_pid: int, old_exe_name: str, timeout: float = 30) -> bool:
    """Ждать исчезновения старого процесса по pid и имени. True если ушёл."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        gone = True
        if psutil is not None:
            try:
                if psutil.pid_exists(old_pid):
                    try:
                        proc = psutil.Process(old_pid)
                        name = proc.name().lower() if proc.name() else ""
                        if old_exe_name.lower() in name.lower() or name == "":
                            gone = False
                        else:
                            gone = True
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        gone = True
                if gone:
                    cur_pid = os.getpid()
                    for proc in psutil.process_iter(["pid", "name", "exe"]):
                        try:
                            if proc.info["pid"] in (cur_pid, old_pid):
                                continue
                            n = (proc.info.get("name") or "").lower()
                            exe = (proc.info.get("exe") or "").lower()
                            if old_exe_name.lower() == n.lower() or old_exe_name.lower() in exe:
                                gone = False
                                break
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            continue
            except Exception:
                gone = not psutil.pid_exists(old_pid)
        else:
            try:
                import ctypes
                handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, old_pid)
                if handle:
                    ctypes.windll.kernel32.CloseHandle(handle)
                    gone = False
                else:
                    gone = True
            except Exception:
                gone = True
        if gone:
            return True
        time.sleep(POLL_SEC)
    return False


def kill_streamlit_processes() -> int:
    """Найти и убить streamlit-дочки. Возвращает число убитых."""
    killed = 0
    if psutil is None:
        return 0
    try:
        cur_pid = os.getpid()
        for proc in psutil.process_iter(["pid", "cmdline", "name"]):
            try:
                if proc.info["pid"] == cur_pid:
                    continue
                cmd = proc.info.get("cmdline") or []
                cmd_s = " ".join(cmd).lower() if isinstance(cmd, list) else str(cmd).lower()
                if "streamlit" in cmd_s:
                    proc.terminate()
                    killed += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.laddr and getattr(conn.laddr, "port", None) == 8501 and conn.pid:
                    if conn.pid == cur_pid:
                        continue
                    try:
                        p = psutil.Process(conn.pid)
                        p.terminate()
                        killed += 1
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
        except (psutil.AccessDenied, NotImplementedError):
            pass
        deadline = time.time() + KILL_TIMEOUT_SEC
        while time.time() < deadline:
            alive = 0
            for proc in psutil.process_iter(["pid", "cmdline"]):
                try:
                    cmd = proc.info.get("cmdline") or []
                    cmd_s = " ".join(cmd).lower() if isinstance(cmd, list) else str(cmd).lower()
                    if "streamlit" in cmd_s and proc.info["pid"] != cur_pid and proc.is_running():
                        alive += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            if alive == 0:
                break
            time.sleep(POLL_SEC)
        for proc in psutil.process_iter(["pid", "cmdline"]):
            try:
                cmd = proc.info.get("cmdline") or []
                cmd_s = " ".join(cmd).lower() if isinstance(cmd, list) else str(cmd).lower()
                if "streamlit" in cmd_s and proc.info["pid"] != cur_pid:
                    try:
                        if proc.is_running():
                            proc.kill()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        log.warning(f"kill streamlit failed: {e}")
    return killed


def collect_ports_from_config(cfg) -> list[int]:
    """Собрать все порты из Config для ожидания освобождения.

    Сканирует все секции Config на поля с именем port / *_port / содержащим port.
    Всегда добавляет streamlit 8501.
    """
    ports: set[int] = set()
    try:
        # явные известные секции
        for sec_name in ("network",):
            sec = getattr(cfg, sec_name, None)
            if sec is not None:
                for k in dir(sec):
                    if "port" in k.lower():
                        try:
                            v = getattr(sec, k)
                            if isinstance(v, int) and 1 <= v <= 65535:
                                ports.add(v)
                        except Exception:
                            continue
        # общий обход всех полей Config на случай кастомных секций
        for fname in getattr(cfg, "model_fields", {}).keys():
            try:
                val = getattr(cfg, fname)
                # если сама секция — уже обработана, иначе скаляр порт
                if isinstance(val, int) and "port" in fname.lower() and 1 <= val <= 65535:
                    ports.add(val)
                elif hasattr(val, "__dict__") or hasattr(val, "model_fields"):
                    fields = getattr(val, "model_fields", None)
                    if fields:
                        for sub in fields:
                            if "port" in sub.lower():
                                try:
                                    pv = getattr(val, sub)
                                    if isinstance(pv, int) and 1 <= pv <= 65535:
                                        ports.add(pv)
                                except Exception:
                                    continue
            except Exception:
                continue
    except Exception:
        pass
    # streamlit всегда
    ports.add(8501)
    return sorted(ports)


def wait_ports_free(ports: list[int], timeout: float = 15) -> bool:
    """Ждать освобождения указанных TCP-портов. True если освободились."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        all_free = True
        for port in ports:
            # 1. psutil: занят ли порт кем-то
            if psutil is not None:
                try:
                    busy = False
                    for conn in psutil.net_connections(kind="inet"):
                        if conn.laddr and getattr(conn.laddr, "port", None) == port:
                            # LISTEN или ESTABLISHED — считаем занятым
                            busy = True
                            break
                    if busy:
                        all_free = False
                        break
                except (psutil.AccessDenied, NotImplementedError):
                    pass
            # 2. пробный bind — точный тест
            if all_free:
                s = None
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(("0.0.0.0", port))
                except OSError:
                    all_free = False
                    break
                finally:
                    if s is not None:
                        try:
                            s.close()
                        except Exception:
                            pass
        if all_free:
            return True
        time.sleep(POLL_SEC)
    return False


def launch_new_version(exe_path: Path, work_dir: Path) -> int | None:
    """Запустить новую версию. Возвращает pid или None."""
    try:
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NEW_CONSOLE", 0x10) | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)
        proc = subprocess.Popen(
            [str(exe_path)],
            cwd=str(work_dir),
            creationflags=creationflags,
            close_fds=False,
        )
        return proc.pid
    except OSError as e:
        log.error(f"launch new version failed: {e}")
        return None


def is_process_alive(pid: int) -> bool:
    if psutil is not None:
        try:
            return psutil.pid_exists(pid) and psutil.Process(pid).is_running()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    else:
        try:
            import ctypes
            handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, pid)
            if handle:
                exit_code = ctypes.c_ulong()
                ctypes.windll.kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code))
                ctypes.windll.kernel32.CloseHandle(handle)
                return exit_code.value == 259  # STILL_ACTIVE
            return False
        except Exception:
            return False

# services/purge/service.py — аварийное удаление узла со всеми данными с хоста
#
# Сценарий: узел нужно полностью снять с машины (автозапуск, конфиг, данные,
# исполняемый файл, процесс). По умолчанию сервис ВЫКЛЮЧЕН — включается явно
# в config.yaml (purge.enabled: true), т.к. операция необратима.
#
# Безопасность:
#   - purge() принимает ТОЛЬКО id пунктов из plan() — пути снаружи не
#     приходят никогда (никаких произвольных путей от сети);
#   - обязателен confirm: true;
#   - защита от опасных целей: корень диска / Windows / Program Files;
#   - в dev-режиме (не frozen) образ exe не удаляется;
#   - работающий exe нельзя удалить → rename-trick + detached cmd-стартер
#     удаляет переименованный образ и пустой каталог после нашего exit.

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import winreg
except ImportError:
    winreg = None

from netpulse.p2p_core.services.rpc import rpc
from netpulse.p2p_core.internal_modules.base import ModuleGeneric

EXIT_DELAY_SEC = 3          # пауза перед os._exit — дать уйти RESPONSE
PURGE_SUFFIX = '.purging'   # суффикс переименованного перед удалением образа

# порядок выполнения: сначала «бумага», потом данные, потом программа
_EXEC_ORDER = ['autorun_task', 'autorun_registry', 'config',
               'work_dir', 'update_leftovers', 'exe']

_PROTECTED_DIRS = {'windows', 'program files', 'program files (x86)',
                   'programdata', '$recycle.bin'}


def _danger_reason(p: Path) -> str | None:
    """Причина отказа на удаление каталога (или None)."""
    try:
        rp = p.resolve()
    except OSError:
        return 'путь не резолвится'
    if rp == Path(rp.anchor):
        return 'корень диска'
    parts = {s.lower() for s in rp.parts}
    hit = parts & _PROTECTED_DIRS
    if hit:
        return f'системный каталог: {", ".join(sorted(hit))}'
    return None


def _dir_size(p: Path) -> int:
    total = 0
    for root, _dirs, files in os.walk(p, onerror=lambda e: None):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total


class Purge(ModuleGeneric):
    def __init__(self, name, context):
        super().__init__(name, context)
        self._renamed_exe: Path | None = None   # образ после rename-trick'а

    # ------------------------------------------------------------------ #
    #  План удаления
    # ------------------------------------------------------------------ #

    def _items(self) -> list[dict]:
        local = self.ctx.config.local
        exe = Path(local.full_path)
        work_dir = Path(local.work_dir)
        cfg_path = self.ctx.config_manager.config_path
        items = []

        task_present = subprocess.call(
            f'schtasks /Query /TN "{local.name}"',
            shell=True, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL) == 0
        items.append({
            'id': 'autorun_task', 'group': 'Автозапуск',
            'title': 'Задача планировщика',
            'detail': f'schtasks /TN "{local.name}"',
            'present': task_present,
        })

        reg_present = False
        if winreg is not None:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                    0, winreg.KEY_READ)
                winreg.QueryValueEx(key, local.name)
                winreg.CloseKey(key)
                reg_present = True
            except OSError:
                pass
        items.append({
            'id': 'autorun_registry', 'group': 'Автозапуск',
            'title': 'Ключ реестра Run [legacy]',
            'detail': r'HKCU\...\CurrentVersion\Run → ' + local.name,
            'present': reg_present,
            'note': 'реестровый автозапуск упразднён; зачистка остатков '
                    'старых версий',
        })

        items.append({
            'id': 'config', 'group': 'Конфигурация',
            'title': 'config.yaml',
            'path': str(cfg_path),
            'size_bytes': cfg_path.stat().st_size if cfg_path.is_file() else 0,
            'present': cfg_path.is_file(),
        })

        wd_danger = _danger_reason(work_dir)
        items.append({
            'id': 'work_dir', 'group': 'Данные',
            'title': 'Каталог данных узла (весь)',
            'path': str(work_dir),
            'size_bytes': _dir_size(work_dir) if work_dir.is_dir() else 0,
            'present': work_dir.is_dir(),
            'note': 'запущенный exe пропускается — удалит стартер'
                    + (f'; ОТКАЗ: {wd_danger}' if wd_danger else ''),
        })

        leftovers = [
            p for p in exe.parent.glob(exe.name + '.*')
            if p.suffix in ('.old', '.failed', PURGE_SUFFIX)
        ]
        items.append({
            'id': 'update_leftovers', 'group': 'Данные',
            'title': 'Остатки обновлений (.old/.failed/staging)',
            'path': ', '.join(str(p) for p in leftovers) or str(exe.parent),
            'size_bytes': sum(p.stat().st_size for p in leftovers
                              if p.is_file()),
            'present': bool(leftovers),
        })

        items.append({
            'id': 'exe', 'group': 'Программа',
            'title': 'Исполняемый файл узла',
            'path': str(exe),
            'size_bytes': exe.stat().st_size if exe.is_file() else 0,
            'present': exe.is_file(),
            'note': 'удаление влечёт остановку процесса; в dev-режиме пропуск',
        })

        items.append({
            'id': 'process', 'group': 'Программа',
            'title': 'Остановка процесса узла',
            'detail': f'PID {os.getpid()}',
            'present': True,
            'note': 'веб-панель потеряет связь с узлом',
        })
        return items

    @rpc
    def plan(self, data: dict = None):
        """Сухой прогон аварийного удаления: перечень целей с размерами.

        purge() принимает только id из этого списка — пути от клиента
        не используются вовсе.
        """
        return {
            'ok': True,
            'node': self.ctx.NODE,
            'enabled': bool(getattr(self.ctx.config, 'purge', None)
                            and self.ctx.config.purge.enabled),
            'frozen': bool(getattr(sys, 'frozen', False)),
            'pid': os.getpid(),
            'items': self._items(),
        }

    # ------------------------------------------------------------------ #
    #  Исполнение
    # ------------------------------------------------------------------ #

    @rpc
    async def purge(self, data: dict):
        """Аварийно удалить узел по выбранным пунктам плана.

        data: {items: ['autorun_task', 'work_dir', ...], confirm: true}

        Выбор 'exe' или 'process' останавливает узел (~3с после ответа).
        """
        pcfg = getattr(self.ctx.config, 'purge', None)
        if not pcfg or not pcfg.enabled:
            return {'ok': False,
                    'error': 'сервис отключён на узле '
                             '(config.yaml → purge.enabled: true)'}

        wanted = data.get('items') or []
        if data.get('confirm') is not True:
            return {'ok': False, 'error': 'требуется подтверждение (confirm: true)'}

        valid_ids = {i['id'] for i in self._items()}
        unknown = [x for x in wanted if x not in valid_ids]
        if unknown:
            return {'ok': False,
                    'error': f'неизвестные пункты: {unknown} '
                             f'(допустимо только из purge.plan)'}

        results = {}
        for item_id in _EXEC_ORDER:
            if item_id in wanted:
                try:
                    results[item_id] = self._exec_item(item_id)
                except Exception as e:
                    results[item_id] = f'ОШИБКА: {e}'
                    self.log.error(f'purge[{item_id}]: {e}')

        self.log.critical(f'PURGE на {self.ctx.NODE}: {results}')

        if 'exe' in wanted or 'process' in wanted:
            self._schedule_self_destruct(delete_exe='exe' in wanted)

            async def _exit_later():
                await asyncio.sleep(EXIT_DELAY_SEC)
                os._exit(0)

            asyncio.create_task(_exit_later())
            return {'ok': True, 'results': results,
                    'note': f'узел завершится через ~{EXIT_DELAY_SEC}с'}

        return {'ok': True, 'results': results}

    # ------------------------------------------------------------------ #
    #  Исполнители отдельных пунктов
    # ------------------------------------------------------------------ #

    def _exec_item(self, item_id: str) -> str:
        local = self.ctx.config.local
        exe = Path(local.full_path)

        if item_id == 'autorun_task':
            subprocess.call(
                f'schtasks /Delete /F /TN "{local.name}"',
                shell=True, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            return 'задача планировщика удалена (или отсутствовала)'

        if item_id == 'autorun_registry':
            if winreg is None:
                return 'winreg недоступен (не Windows)'
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_SET_VALUE)
            try:
                winreg.DeleteValue(key, local.name)
                return 'ключ реестра удалён'
            except FileNotFoundError:
                return 'ключ реестра отсутствовал'
            finally:
                winreg.CloseKey(key)

        if item_id == 'config':
            p = self.ctx.config_manager.config_path
            if p.is_file():
                p.unlink()
                return f'удалён {p.name}'
            return 'файл конфига отсутствовал'

        if item_id == 'work_dir':
            wd = Path(local.work_dir).resolve()
            danger = _danger_reason(wd)
            if danger:
                return f'ОТКАЗ: опасная цель ({danger})'
            removed = skipped = 0
            if wd.is_dir():
                for child in list(wd.iterdir()):
                    try:
                        if child.resolve() == exe.resolve():
                            skipped += 1     # живой образ — удел стартера
                            continue
                        if child.is_dir():
                            shutil.rmtree(child)
                        else:
                            child.unlink()
                        removed += 1
                    except OSError as e:
                        skipped += 1
                        self.log.warning(f'purge[work_dir]: {child}: {e}')
            return f'каталог очищен: удалено {removed}, пропущено {skipped}'

        if item_id == 'update_leftovers':
            n = 0
            for suffix in ('.old', '.failed', PURGE_SUFFIX):
                for p in exe.parent.glob(exe.name + suffix):
                    p.unlink(missing_ok=True)
                    n += 1
            staging = Path(local.work_dir) / 'updates'
            if staging.is_dir():
                shutil.rmtree(staging, ignore_errors=True)
                n += 1
            return f'удалено объектов: {n}'

        if item_id == 'exe':
            if not getattr(sys, 'frozen', False):
                return 'ПРОПУСК: dev-режим — образ не является нашим файлом'
            target = exe.with_name(exe.name + PURGE_SUFFIX)
            os.replace(exe, target)      # запущенный образ можно переименовать
            self._renamed_exe = target
            return f'образ переименован → {target.name} (удалит стартер)'

        raise ValueError(f'нет исполнителя для {item_id!r}')

    def _schedule_self_destruct(self, delete_exe: bool):
        """Detached cmd: дождаться нашего exit, стереть образ и пустой каталог."""
        local = self.ctx.config.local
        exe = Path(local.full_path)
        wd = Path(local.work_dir).resolve()

        cmds = [f'timeout /t {EXIT_DELAY_SEC} /nobreak >nul']
        victim = self._renamed_exe or exe
        cmds.append(f'del /f /q "{victim}"')
        # rd без /s удаляет только ПУСТОЙ каталог — ничего лишнего не заденет
        cmds.append(f'rd /q "{wd}"')

        subprocess.Popen(
            ['cmd', '/c', ' & '.join(cmds)],
            cwd=str(wd) if wd.is_dir() else str(exe.parent),
            creationflags=subprocess.DETACHED_PROCESS
            | subprocess.CREATE_NEW_PROCESS_GROUP,
            close_fds=True,
        )

# services/config/service.py — удалённое редактирование config.yaml узла
#
# Головной узел (headless) не имеет локального UI — конфиг правится из
# веб-панели через mesh-RPC. Сервис всегда включён, отдельного флага нет.
#
# Семантика применения (вариант B+):
#   - сохранение = валидация → бэкап → атомарная запись → инплейс-синк
#     живых объектов (ctx.config и config_manager.cfg) → горячее
#     применение того, что применимо без рестарта (уровни логирования);
#   - «Сохранить и перезапустить» дополнительно поднимает detached-стартер
#     (как в updater): frozen — тот же exe, dev — python main.py.
#
# Безопасность:
#   - валидация Config(**parsed) ДО записи — битый конфиг на диск не попадает;
#   - конфликт по mtime: если файл меняли с момента чтения — отказ;
#   - local.secret маскируется при выдаче (SECRET_PLACEHOLDER), при записи
#     подставляется реальное значение; удаление строки секрета не стирает
#     секрет молча — только осознанной правкой значения;
#   - restore принимает ТОЛЬКО имена из backups() — никаких путей от сети;
#   - перед каждой записью — автоматический бэкап с ротацией.

import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import yaml
from pydantic import ValidationError

from netpulse.p2p_core.services.rpc import rpc
from netpulse.p2p_core.internal_modules.base import ModuleGeneric
from netpulse.p2p_core.internal_modules.config import Config as ConfigModel

SECRET_PLACEHOLDER = '__MASKED_SECRET__'
BACKUP_NAME_RE = re.compile(r'^config_\d{8}-\d{6}(_\d+)?\.yaml$')
MAX_BACKUPS = 10              # ротация резервных копий
EXIT_DELAY_SEC = 1            # сколько живём после запуска _update helper'а

# секции, применяемые на горячую (без рестарта)
HOT_SECTIONS = {'logging', 'logs', 'update'}

_SECRET_LINE_RE = re.compile(
    r'(?m)^(?P<indent>[ \t]+)secret:[ \t]*(?P<val>\S.*?)[ \t]*$')


class Config(ModuleGeneric):
    """Редактирование config.yaml узла: чтение/запись/бэкапы/рестарт."""

    def __init__(self, name, context):
        super().__init__(name, context)

    async def start(self):
        self.log.info(f'Config service started: {self._cfg_path()}')

    async def stop(self):
        pass

    # ------------------------------------------------------------------ #
    #  Пути
    # ------------------------------------------------------------------ #

    def _cfg_path(self) -> Path:
        return Path(self.ctx.config_manager.config_path)

    def _backups_dir(self) -> Path:
        p = self._cfg_path()
        return p.parent / (p.name + '.backups')

    @staticmethod
    def _is_frozen() -> bool:
        return getattr(sys, 'frozen', False)

    # ------------------------------------------------------------------ #
    #  RPC: чтение / список бэкапов / текст бэкапа
    # ------------------------------------------------------------------ #

    @rpc
    def get(self, data: dict = None) -> dict:
        """Текущий config.yaml для редактора.

        Ответ несёт text с замаскированным local.secret
        ({SECRET_PLACEHOLDER}) — при save() подставится реальное значение.
        """
        path = self._cfg_path()
        try:
            text = path.read_text(encoding='utf-8')
            mtime = path.stat().st_mtime
        except OSError as e:
            return {'ok': False, 'error': f'config.yaml не читается: {e}'}
        return {
            'ok': True,
            'node': self.ctx.NODE,
            'path': str(path),
            'text': self._mask_secret(text),
            'mtime': mtime,
            'frozen': self._is_frozen(),
            'backups': self._backups(),
        }

    @rpc
    def backups(self, data: dict = None) -> dict:
        """Список резервных копий (новые сверху)."""
        return {'ok': True, 'backups': self._backups()}

    @rpc
    def read_backup(self, data: dict) -> dict:
        """Текст бэкапа по имени из backups() (секрет замаскирован)."""
        path = self._backup_path((data or {}).get('name'))
        if path is None:
            return {'ok': False, 'error': 'неизвестное имя бэкапа'}
        try:
            text = path.read_text(encoding='utf-8')
        except OSError as e:
            return {'ok': False, 'error': f'бэкап не читается: {e}'}
        return {'ok': True, 'name': path.name,
                'text': self._mask_secret(text)}

    # ------------------------------------------------------------------ #
    #  RPC: сохранение / восстановление
    # ------------------------------------------------------------------ #

    @rpc
    async def save(self, data: dict) -> dict:
        """Валидировать и сохранить config.yaml.

        data: {text, base_mtime?, restart?: bool}
          base_mtime — mtime из get(): если файл с тех пор менялся — отказ
          (conflict). restart=true — после записи перезапустить узел.

        Горячо применяются logging.* (уровни логгеров) и logs.*
        (панель подхватит при следующем подключении); остальные секции
        полностью вступают в силу после рестарта.
        """
        text = (data or {}).get('text')
        if not isinstance(text, str) or not text.strip():
            return {'ok': False, 'error': 'пустой текст конфига'}
        return await self._commit(
            text, base_mtime=(data or {}).get('base_mtime'),
            restart=bool((data or {}).get('restart')))

    @rpc
    async def restore(self, data: dict) -> dict:
        """Восстановить бэкап по имени из backups() (пути не принимаются)."""
        name = (data or {}).get('name')
        path = self._backup_path(name)
        if path is None:
            return {'ok': False, 'error': f'неизвестное имя бэкапа: {name!r}'}
        try:
            text = path.read_text(encoding='utf-8')
        except OSError as e:
            return {'ok': False, 'error': f'бэкап не читается: {e}'}
        res = await self._commit(text, base_mtime=None,
                                 restart=bool((data or {}).get('restart')))
        if res.get('ok'):
            res['restored'] = name
        return res

    # ------------------------------------------------------------------ #
    #  Общий конвейер записи
    # ------------------------------------------------------------------ #

    async def _commit(self, edited_text: str, base_mtime=None,
                      restart: bool = False) -> dict:
        path = self._cfg_path()

        # 1. parse
        try:
            parsed = yaml.safe_load(edited_text)
        except yaml.YAMLError as e:
            return {'ok': False, 'error': f'YAML не парсится: {e}'}
        if not isinstance(parsed, dict):
            return {'ok': False, 'error': 'корень YAML должен быть словарём'}

        warnings = []
        unknown = [k for k in parsed if k not in ConfigModel.model_fields]
        if unknown:
            warnings.append(f'неизвестные секции (сохранены как есть): '
                            f'{", ".join(map(str, unknown))}')

        # 2. unmask secret
        real_secret = getattr(self.ctx.config.local, 'secret', None)
        local_d = parsed.get('local')
        placeholder_used = (isinstance(local_d, dict)
                            and local_d.get('secret') == SECRET_PLACEHOLDER)
        if placeholder_used:
            if real_secret:
                local_d['secret'] = real_secret
            else:
                return {'ok': False,
                        'error': 'в тексте маска секрета, но на узле секрет '
                                 'пуст — задайте значение явно или уберите '
                                 'строку secret'}

        # 3. validate (dry-run, диск не трогаем)
        new_cfg, errors = self._validate(parsed)
        if new_cfg is None:
            return {'ok': False, 'errors': errors}

        if new_cfg.node != self.ctx.NODE:
            warnings.append(f'имя узла "{new_cfg.node}" вступит в силу '
                            f'только после рестарта')

        # 4. conflict check по mtime
        try:
            cur_mtime = await asyncio.to_thread(
                lambda: path.stat().st_mtime)
        except OSError as e:
            return {'ok': False, 'error': f'config.yaml недоступен: {e}'}
        if base_mtime is not None and abs(cur_mtime - float(base_mtime)) > 0.001:
            return {
                'ok': False, 'conflict': True,
                'error': 'конфликт: config.yaml изменён с момента загрузки. '
                         'Перечитайте конфиг и повторите правку.'}

        # 5. снимок старого → бэкап → атомарная запись
        old_cfg = self.ctx.config.model_copy(deep=True)
        final_text = (self._unmask_secret(edited_text, real_secret)
                      if placeholder_used else edited_text)
        try:
            await asyncio.to_thread(self._backup_and_write, path, final_text)
        except (OSError, yaml.YAMLError) as e:
            return {'ok': False, 'error': f'запись не удалась: {e}'}

        # 6. diff → инплейс-синк живых объектов → hot apply
        changed = [f for f in ConfigModel.model_fields
                   if f not in HOT_SECTIONS
                   and getattr(old_cfg, f) != getattr(new_cfg, f)]
        self._sync_live(new_cfg)
        applied_hot = self._apply_hot(new_cfg, old_cfg)

        res = {
            'ok': True,
            'path': str(path),
            'mtime': path.stat().st_mtime,
            'warnings': warnings,
            'applied_hot': applied_hot,
            'restart_required_sections': changed,
            'restart_required': bool(changed),
        }
        self.log.info(f'config.yaml saved (restart_required={bool(changed)}), '
                      f'hot={applied_hot}, changed={changed}')

        # 7. опциональный рестарт
        if restart:
            err = self._schedule_restart()
            if err:
                res['note'] = f'сохранено, но рестарт не запущен: {err}'
            else:
                res['note'] = (f'сохранено; узел перезапустится автоматически '
                               f'(связь прервётся на несколько секунд)')
        return res

    # ------------------------------------------------------------------ #
    #  Валидация
    # ------------------------------------------------------------------ #

    @staticmethod
    def _validate(parsed: dict) -> tuple['ConfigModel | None', list[str]]:
        """(Config | None, список ошибок). Диск не трогаем."""
        try:
            return ConfigModel(**parsed), []
        except ValidationError as e:
            errors = []
            for err in e.errors():
                loc = '.'.join(str(x) for x in err.get('loc', ())) or '<корень>'
                errors.append(f'{loc}: {err.get("msg")}')
            return None, errors

    # ------------------------------------------------------------------ #
    #  Секрет: маскирование при выдаче, подстановка при записи
    # ------------------------------------------------------------------ #

    def _mask_secret(self, text: str) -> str:
        real = getattr(self.ctx.config.local, 'secret', None)
        if not real:
            return text

        def sub(m):
            val = m.group('val').strip().strip('"\'')
            if val in ('null', '~', '') or SECRET_PLACEHOLDER in val:
                return m.group(0)
            return f"{m.group('indent')}secret: {SECRET_PLACEHOLDER}"

        return _SECRET_LINE_RE.sub(sub, text)

    @staticmethod
    def _yaml_scalar(value) -> str:
        """Скаляр в YAML-совместимом виде (json-строка — валидный YAML)."""
        if value is None:
            return 'null'
        if isinstance(value, bool):
            return 'true' if value else 'false'
        if isinstance(value, (int, float)):
            return repr(value)
        return json.dumps(str(value), ensure_ascii=False)

    @classmethod
    def _unmask_secret(cls, text: str, real) -> str:
        scalar = cls._yaml_scalar(real)
        return _SECRET_LINE_RE.sub(
            lambda m: f"{m.group('indent')}secret: {scalar}", text)

    # ------------------------------------------------------------------ #
    #  Бэкапы
    # ------------------------------------------------------------------ #

    def _backups(self) -> list[dict]:
        bdir = self._backups_dir()
        items = []
        for p in sorted(bdir.glob('config_*.yaml'), reverse=True):
            try:
                st = p.stat()
                items.append({'name': p.name, 'ts': st.st_mtime,
                              'size': st.st_size})
            except OSError:
                continue
        return items

    def _backup_path(self, name) -> Path | None:
        """Путь к бэкапу строго по имени из backups() — без путей извне."""
        if not isinstance(name, str) or not BACKUP_NAME_RE.match(name):
            return None
        p = self._backups_dir() / name
        return p if p.is_file() else None

    def _backup_and_write(self, path: Path, text: str):
        bdir = self._backups_dir()
        bdir.mkdir(parents=True, exist_ok=True)

        if path.is_file():
            content = path.read_bytes()
            stamp = time.strftime('%Y%m%d-%H%M%S')
            target = bdir / f'config_{stamp}.yaml'
            n = 1
            while target.exists():      # несколько записей за секунду
                target = bdir / f'config_{stamp}_{n}.yaml'
                n += 1
            latest = next(iter(sorted(bdir.glob('config_*.yaml'),
                                      key=lambda x: x.stat().st_mtime,
                                      reverse=True)), None)
            same = False
            if latest is not None:
                try:
                    same = latest.read_bytes() == content
                except OSError:
                    same = False
            if not same:
                target.write_bytes(content)

            # ротация
            all_backups = sorted(bdir.glob('config_*.yaml'),
                                 key=lambda x: x.stat().st_mtime,
                                 reverse=True)
            for old in all_backups[MAX_BACKUPS:]:
                old.unlink(missing_ok=True)

        tmp = path.parent / (path.name + '.tmp')
        tmp.write_text(text, encoding='utf-8')
        os.replace(tmp, path)

    # ------------------------------------------------------------------ #
    #  Горячее применение и синк живых объектов
    # ------------------------------------------------------------------ #

    def _sync_live(self, new_cfg: ConfigModel):
        """Инплейс-замена секций в ctx.config и config_manager.cfg.

        Идентичность объектов сохраняется — ссылки вида self.ctx.config
        остаются валидными; заменяются сами секции. Сервисы, кэширующие
        ссылки НА секции (например cfg = ctx.config.files), увидят новые
        значения после рестарта.
        """
        cm = getattr(self.ctx, 'config_manager', None)
        targets, seen = [], set()
        for obj in (self.ctx.config, getattr(cm, 'cfg', None)):
            if obj is not None and id(obj) not in seen:
                seen.add(id(obj))
                targets.append(obj)
        for obj in targets:
            for fname in ConfigModel.model_fields:
                setattr(obj, fname, getattr(new_cfg, fname))

    def _apply_hot(self, new_cfg: ConfigModel, old_cfg: ConfigModel) -> list[str]:
        applied = []
        lg_new, lg_old = new_cfg.logging, old_cfg.logging

        if lg_new.level != lg_old.level:
            lvl = getattr(logging, str(lg_new.level).upper(), None)
            if isinstance(lvl, int):
                logging.root.setLevel(lvl)
                applied.append(f'logging.level → {lg_new.level}')
            else:
                applied.append(f'logging.level={lg_new.level}: неизвестный '
                               f'уровень, вступит после рестарта')

        if lg_new.websockets_level != lg_old.websockets_level:
            ws = getattr(logging, str(lg_new.websockets_level).upper(), None)
            if isinstance(ws, int):
                for lname in ('websockets', 'websockets.client',
                              'websockets.server'):
                    logging.getLogger(lname).setLevel(ws)
                applied.append('logging.websockets_level → '
                               f'{lg_new.websockets_level}')
            else:
                applied.append(f'logging.websockets_level='
                               f'{lg_new.websockets_level}: вступит после '
                               f'рестарта')

        if new_cfg.logs != old_cfg.logs:
            applied.append('logs.* подхватывается веб-панелью при следующем '
                           'подключении')
        return applied

    # ------------------------------------------------------------------ #
    #  Рестарт (механика updater: копия _update.exe + helper)
    # ------------------------------------------------------------------ #

    def _schedule_restart(self) -> str | None:
        """Запустить _update helper и запланировать свой exit.

        Копирует текущий exe в _update.exe с заменой существующего (чтобы не
        запустить старую версию после обновления), запускает helper
        --config-restart, который дождётся завершения ноды, освобождения портов
        из config.yaml, паузы на дескрипторы и стартует ноду заново с
        watchdog config_confirm_sec.

        Возвращает None при успехе или текст ошибки (файл уже сохранён).
        """
        cfg_path = self._cfg_path()
        work_dir = cfg_path.parent
        health_sec = int(getattr(self.ctx.config, 'config_confirm_sec', 15))
        try:
            if self._is_frozen():
                exe = Path(sys.executable)
                from netpulse.p2p_core.internal_modules.update import get_updater_exe_path
                helper = get_updater_exe_path(exe)
                # перезаписать существующий _update.exe свежей копией
                try:
                    import shutil
                    shutil.copyfile(exe, helper)
                except OSError as e:
                    self.log.error(f'copy to _update.exe failed: {e}')
                    return str(e)
                args = [
                    str(helper),
                    '--config-restart',
                    '--old-pid', str(os.getpid()),
                    '--old-exe', str(exe),
                    '--work-dir', str(work_dir),
                    '--config-path', str(cfg_path),
                    '--health-confirm-sec', str(health_sec),
                ]
                creationflags = 0
                if os.name == 'nt':
                    creationflags = getattr(subprocess, 'DETACHED_PROCESS', 0) | getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
                    creationflags |= 0x08000000  # CREATE_NO_WINDOW
                subprocess.Popen(
                    args,
                    cwd=str(work_dir),
                    creationflags=creationflags,
                    close_fds=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                )
            else:
                # dev: запуск helper'а через python
                py = Path(sys.executable)
                args = [
                    str(py), '-m', 'src.internal_modules.config_update',
                    '--config-restart',
                    '--old-pid', str(os.getpid()),
                    '--old-exe', str(py),
                    '--work-dir', str(work_dir),
                    '--config-path', str(cfg_path),
                    '--health-confirm-sec', str(health_sec),
                ]
                creationflags = 0
                if os.name == 'nt':
                    creationflags = getattr(subprocess, 'DETACHED_PROCESS', 0) | getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
                    creationflags |= 0x08000000
                subprocess.Popen(
                    args,
                    cwd=str(work_dir),
                    creationflags=creationflags,
                    close_fds=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                )
        except OSError as e:
            self.log.error(f'restart helper failed: {e}')
            return str(e)

        self.log.warning(f'RESTART: узел завершится через {EXIT_DELAY_SEC}с '
                         f'и будет поднят helper-ом (health={health_sec}с)')

        async def _exit_later():
            await asyncio.sleep(EXIT_DELAY_SEC)
            os._exit(0)

        asyncio.create_task(_exit_later())
        return None

"""Consistent SQLite snapshots and bounded, non-overwriting recovery bundles."""
import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import threading
import time
import uuid
import zipfile
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from . import __version__

MAX_BYTES = 2 * 1024**3
MAX_CONFIG = 4 * 1024**2
LOCK = threading.Lock()
PAYLOADS = {'config.json', 'network_stats.db'}


class RecoveryError(ValueError):
    pass


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def connect_readonly(path):
    con = sqlite3.connect(path.resolve().as_uri() + '?mode=ro', uri=True, timeout=5)
    con.execute('PRAGMA trusted_schema=OFF')
    return con


def check_database(path):
    with closing(connect_readonly(path)) as con:
        deadline = time.monotonic() + 60
        con.set_progress_handler(lambda: int(time.monotonic() > deadline), 10000)
        result = con.execute('PRAGMA integrity_check').fetchall()
        if result != [('ok',)]:
            raise RecoveryError('Нарушена целостность базы данных')
        return con.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]


def check_config(path):
    if path.stat().st_size > MAX_CONFIG:
        raise RecoveryError('Конфигурация слишком велика')
    try:
        config = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(config, dict):
            raise ValueError()
    except (UnicodeError, ValueError, RecursionError):
        raise RecoveryError('Некорректный config.json') from None
    def encrypted(node):
        if isinstance(node, dict):
            return sum(encrypted(value) for value in node.values())
        if isinstance(node, list):
            return sum(encrypted(value) for value in node)
        return int(isinstance(node, str) and node.startswith('dpapi:'))
    return encrypted(config)


def create(data_dir, destination):
    """Archive exactly the persisted config and a live SQLite backup, no sources."""
    source, destination = Path(data_dir).resolve(), Path(destination).resolve()
    if not LOCK.acquire(blocking=False):
        raise RecoveryError('Резервное копирование уже выполняется')
    try:
        config, database = source / 'config.json', source / 'network_stats.db'
        if not config.is_file() or not database.is_file():
            raise RecoveryError('В каталоге данных нужны config.json и network_stats.db')
        if config.stat().st_size > MAX_CONFIG or database.stat().st_size > MAX_BYTES:
            raise RecoveryError('Превышен размер исходных данных')
        destination.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='.netpulse-backup-', dir=destination) as stage:
            stage = Path(stage)
            shutil.copyfile(config, stage / 'config.json')
            dpapi = check_config(stage / 'config.json')
            deadline = time.monotonic() + 60
            page_size = 4096
            def progress(status, remaining, total):
                if time.monotonic() > deadline or total * page_size > MAX_BYTES:
                    raise RecoveryError('Превышен лимит времени или размера снимка')
            with closing(connect_readonly(database)) as src:
                page_size = src.execute('PRAGMA page_size').fetchone()[0]
                with closing(sqlite3.connect(stage / 'network_stats.db')) as target:
                    src.backup(target, pages=128, progress=progress, sleep=.01)
            tables = check_database(stage / 'network_stats.db')
            files = {name: {'size': (stage / name).stat().st_size,
                            'sha256': digest(stage / name)} for name in sorted(PAYLOADS)}
            if sum(item['size'] for item in files.values()) > MAX_BYTES:
                raise RecoveryError('Превышен размер архива')
            manifest = {'format': 'netpulse-recovery', 'schema': 1, 'version': __version__,
                        'created': datetime.now(timezone.utc).isoformat(), 'files': files,
                        'tables': tables, 'dpapi_values': dpapi}
            (stage / 'manifest.json').write_text(json.dumps(manifest), encoding='utf-8')
            temporary = stage / 'archive.zip'
            with zipfile.ZipFile(temporary, 'w', zipfile.ZIP_DEFLATED) as archive:
                for name in sorted(PAYLOADS | {'manifest.json'}):
                    archive.write(stage / name, name)
            os.chmod(temporary, 0o600)
            name = 'netpulse_auto_' + datetime.now().strftime('%Y%m%d_%H%M%S_') + uuid.uuid4().hex[:8] + '.zip'
            output = destination / name
            os.replace(temporary, output)
        return {'ok': True, 'archive': str(output), 'tables': tables, 'dpapi_values': dpapi}
    finally:
        LOCK.release()


def unpack_verified(path, stage):
    """Copy only the fixed payload names; never use ZipFile.extract/all."""
    path, stage = Path(path), Path(stage)
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise RecoveryError('Архив отсутствует или слишком велик')
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) != 3 or {item.filename for item in entries} != PAYLOADS | {'manifest.json'}:
                raise RecoveryError('Неизвестный формат или лишние файлы в архиве')
            if sum(item.file_size for item in entries) > MAX_BYTES:
                raise RecoveryError('Превышен размер распакованных данных')
            if archive.getinfo('manifest.json').file_size > 16384:
                raise RecoveryError('Манифест слишком велик')
            manifest = json.loads(archive.read('manifest.json'))
            if not isinstance(manifest, dict) or manifest.get('format') != 'netpulse-recovery' or manifest.get('schema') != 1:
                raise RecoveryError('Неподдерживаемый формат архива')
            files = manifest.get('files')
            if not isinstance(files, dict) or set(files) != PAYLOADS:
                raise RecoveryError('Некорректный перечень файлов')
            for name in sorted(PAYLOADS):
                entry = files[name]
                if not isinstance(entry, dict) or entry.get('size') != archive.getinfo(name).file_size:
                    raise RecoveryError('Размер файла не соответствует манифесту')
                limit = MAX_CONFIG if name == 'config.json' else MAX_BYTES
                size = 0
                with archive.open(name) as src, (stage / name).open('xb') as dst:
                    os.chmod(stage / name, 0o600)
                    while block := src.read(1024 * 1024):
                        size += len(block)
                        if size > limit:
                            raise RecoveryError('Превышен лимит файла')
                        dst.write(block)
                if digest(stage / name) != entry.get('sha256'):
                    raise RecoveryError('Контрольная сумма не совпадает')
        tables = check_database(stage / 'network_stats.db')
        dpapi = check_config(stage / 'config.json')
        return {'ok': True, 'format': manifest['format'], 'schema': 1,
                'version': manifest.get('version'), 'created': manifest.get('created'),
                'files': files, 'tables': tables, 'dpapi_values': dpapi,
                'warning': 'Архив содержит конфигурацию и данные. DPAPI привязан к исходному профилю Windows. Переменные окружения, сертификаты и ключи меша не включены.'}
    except (zipfile.BadZipFile, RuntimeError, KeyError, UnicodeError, sqlite3.Error, json.JSONDecodeError, RecursionError):
        raise RecoveryError('Архив повреждён или его данные не прошли проверку') from None


def inspect(path):
    with tempfile.TemporaryDirectory(prefix='netpulse-verify-') as stage:
        return unpack_verified(path, stage)


def restore(path, destination):
    """Restore to a newly created directory, never overwrite any existing target."""
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise RecoveryError('Каталог восстановления уже существует; выберите новый путь')
    if not destination.parent.is_dir():
        raise RecoveryError('Родительский каталог восстановления должен существовать')
    with tempfile.TemporaryDirectory(prefix='.netpulse-restore-', dir=destination.parent) as stage:
        stage = Path(stage)
        result = unpack_verified(path, stage)
        # mkdir is exclusive even if another process creates the target after validation.
        destination.mkdir(mode=0o700)
        try:
            for name in sorted(PAYLOADS):
                # Exclusive creation prevents replacing a concurrently created file/symlink.
                with (destination / name).open('xb') as dst, (stage / name).open('rb') as src:
                    os.chmod(destination / name, 0o600)
                    shutil.copyfileobj(src, dst)
        except Exception:
            # Preserve any partial result for diagnosis. Never delete a user directory.
            raise RecoveryError('Восстановление не завершено; проверьте новый каталог') from None
    result['destination'] = str(destination)
    return result

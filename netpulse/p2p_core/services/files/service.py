# services/files/service.py
# =============================================================================
#  Файловый транспорт: передача файлов между узлами через mesh-стриминг.
#
#  Архитектура (push поверх проверенного механизма Dispatcher/PipeTransport,
#  как в demo/compute_full — работает через промежуточные узлы, с ACK):
#
#    Получатель B                          Источник A (владелец файла)
#    ------------                          ---------------------------
#    files.download({dst:'A', ref})  -----> (нет — см. ниже, два RPC)
#      1) RPC files.stat   -> манифест {id=sha256, size, share, path}
#      2) RPC files.serve  -> на A поднимается pipe+dispatcher,
#                             генератор читает файл чанками;
#                             label задаёт B
#    <== STREAM_OPEN(method='file_in') === A пушит чанки к B
#    @stream_consumer('file_in'):
#      пишет в <final>.part, prefetch-ACK, по EOF — сверка размера и
#      sha256, атомарный os.replace(.part -> final)
#
#  Безопасность:
#    * path traversal закрыт (_safe_join: только относительные пути
#      внутри корня шары);
#    * ACL шары: allow = список node_id (пусто = всем); проверяется по
#      reply_to, который передаёт вызывающий. До появления аутентификации
#      узлов это защита от ошибок, а не от злонамеренных узлов;
#    * наружу отдаются только имена шар и относительные пути, никогда —
#      локальные абсолютные пути узла.
#
#  Адресация файла:
#    ref  = {'share': имя, 'path': относительный путь}   — человеко-режим
#    id   = sha256 содержимого                            — content-addressed
#  Хеш считается лениво (первый stat/serve) и кэшируется по (size, mtime_ns).
# =============================================================================

import asyncio
import fnmatch
import hashlib
import os
import shutil
import time
import uuid
from collections import deque
from pathlib import Path

from netpulse.p2p_core.internal_modules.base import ModuleGeneric
from netpulse.p2p_core.internal_modules.memory import Pipe
from netpulse.p2p_core.networking.protocol import MsgPack
from netpulse.p2p_core.services.rpc import rpc, stream_wrapper, stream_consumer

STREAM_NAME = 'file_in'   # имя стрима-приёмника (@stream_wrapper/consumer)
DEFAULT_BUFF = 8          # чанков в полёте (pipe buff)
SPEED_WINDOW = 10         # сек — окно расчёта скорости


def _canon(s: str) -> str:
    return s.strip().lower() if isinstance(s, str) else s


# ------------------------------------------------------------------ #
#  Чистые функции (покрываются юнит-тестами)
# ------------------------------------------------------------------ #

def _safe_join(root: Path, rel: str) -> Path | None:
    """Путь rel строго внутри root; иначе None (traversal/absolute)."""
    if not rel or Path(rel).is_absolute() or '..' in Path(rel).parts:
        return None
    p = (root / rel).resolve()
    try:
        p.relative_to(root.resolve())
    except ValueError:
        return None
    return p


def _chunk_file(path: Path, offset: int, chunk_size: int):
    """Sync-генератор чтения с offset — продюсер Dispatcher'а (поток)."""
    with open(path, 'rb') as f:
        f.seek(offset)
        while True:
            block = f.read(chunk_size)
            if not block:
                break
            yield block


def _sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def _human(n: float) -> str:
    for unit in ('Б', 'КБ', 'МБ', 'ГБ', 'ТБ'):
        if n < 1024 or unit == 'ТБ':
            return f"{n:.0f} {unit}" if unit == 'Б' else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ТБ"


class Files(ModuleGeneric):
    """Файловый транспорт mesh-сети.

    Раздача настраивается в config.yaml → files.shares:
        files:
          download_dir: downloads       # куда складывать полученное
          shares:
            - name: media               # публичное имя шары
              path: D:\\NAS\\movies     # локальный каталог
              allow: []                 # [] = всем подключенным узлам
              chunk_size: 262144
    """

    def __init__(self, name, context):
        super().__init__(name, context)
        self._downloads: dict[str, dict] = {}     # label -> state приёма
        self._serves: dict[str, dict] = {}        # label -> раздача
        self._hash_cache: dict[str, tuple[tuple, str]] = {}  # abs -> ((size,mtime_ns), sha)

    # ------------------------------------------------------------------ #
    #  Lifecycle
    # ------------------------------------------------------------------ #

    async def start(self):
        dl = self._download_dir()
        dl.mkdir(parents=True, exist_ok=True)
        shares = self._shares()
        self.log.info(
            f"Files service started: {len(shares)} share(s), "
            f"download_dir={dl}"
        )
        for s in shares:
            self.log.info(f"  share {s.name!r} → {s.path} "
                          f"(allow={s.allow or 'все'})")

    async def stop(self):
        for label, srv in list(self._serves.items()):
            try:
                srv['dispatcher'].stop()
            except Exception:
                pass
            self._serves.pop(label, None)
        self.log.info('Files service stopped')

    # ------------------------------------------------------------------ #
    #  Внутренности: шары, индекс, хеши
    # ------------------------------------------------------------------ #

    def _cfg(self):
        cm = getattr(self.ctx, 'config_manager', None)
        root = getattr(cm, 'cfg', None) if cm else None
        # менеджер конфига первичен: update() создаёт новый объект,
        # и ctx.config может отставать (подстраховка — см. _persist_shares)
        return getattr(root or self.ctx.config, 'files', None)

    def _download_dir(self) -> Path:
        cfg = self._cfg()
        raw = Path(getattr(cfg, 'download_dir', 'downloads') or 'downloads')
        if raw.is_absolute():
            return raw
        work = getattr(self.ctx.config.local, 'work_dir', None)
        return (Path(work) / raw) if work else raw

    def _shares(self):
        return list(getattr(self._cfg(), 'shares', []) or [])

    def _share_by_name(self, name: str):
        for s in self._shares():
            if s.name == name:
                return s
        return None

    def _scan(self, share) -> list[dict]:
        """Файлы шары: [{path(отн.), size, mtime}] — без каталогов."""
        root = Path(share.path)
        out = []
        if not root.is_dir():
            return out
        for dirpath, _dirs, files in os.walk(root):
            for fname in files:
                ap = Path(dirpath) / fname
                try:
                    stt = ap.stat()
                except OSError:
                    continue
                out.append({
                    'path': ap.relative_to(root).as_posix(),
                    'size': stt.st_size,
                    'mtime': int(stt.st_mtime),
                })
        out.sort(key=lambda e: e['path'])
        return out

    def _ensure_id(self, abs_path: Path) -> str:
        """sha256 содержимого с кэшем по (size, mtime_ns)."""
        stt = abs_path.stat()
        key = (stt.st_size, stt.st_mtime_ns)
        cached = self._hash_cache.get(str(abs_path))
        if cached and cached[0] == key:
            return cached[1]
        digest = _sha256_of(abs_path)
        self._hash_cache[str(abs_path)] = (key, digest)
        return digest

    def _resolve_ref(self, data: dict):
        """{share,path} или {id} → (share_cfg, abs_path) | (None, error)."""
        cfg = self._cfg()
        max_chunk = int(getattr(cfg, 'max_chunk', 4 * 1024 * 1024))

        share_name = data.get('share')
        rel = data.get('path') or ''
        fid = data.get('id')

        if fid and not share_name:
            found = self._find_by_id(fid)
            if not found:
                return None, f'файл с id={fid[:12]}… не найден в шарах'
            share_name, rel = found

        share = self._share_by_name(share_name or '')
        if share is None:
            return None, f'шара {share_name!r} не найдена'
        abspath = _safe_join(Path(share.path), rel)
        if abspath is None or not abspath.is_file():
            return None, f'файл не найден: {share_name}/{rel}'
        return share, abspath

    def _find_by_id(self, fid: str):
        """id → (share_name, rel_path): ленивый скан с кэшем хешей."""
        for share in self._shares():
            for entry in self._scan(share):
                ap = _safe_join(Path(share.path), entry['path'])
                if ap is None:
                    continue
                if self._ensure_id(ap) == fid:
                    return share.name, entry['path']
        return None

    def _acl_ok(self, share, node_id: str) -> bool:
        allow = [_canon(a) for a in list(getattr(share, 'allow', []) or [])]
        return not allow or _canon(node_id) in allow

    def _manifest(self, share, abspath: Path, chunk_size: int) -> dict:
        stt = abspath.stat()
        return {
            'id': self._ensure_id(abspath),
            'share': share.name,
            'path': abspath.relative_to(Path(share.path).resolve()).as_posix(),
            'size': stt.st_size,
            'mtime': int(stt.st_mtime),
            'chunk_size': chunk_size,
        }

    # ------------------------------------------------------------------ #
    #  RPC: каталог
    # ------------------------------------------------------------------ #

    @rpc
    def ping(self, data: dict) -> dict:
        return {'ok': True, 'service': 'files', 'node': self.ctx.NODE}

    @rpc
    def list_shares(self, data: dict) -> dict:
        """Шары этого узла (имена и объём; локальных путей нет)."""
        out = []
        for s in self._shares():
            entries = self._scan(s)
            out.append({
                'name': s.name,
                'files': len(entries),
                'bytes': sum(e['size'] for e in entries),
            })
        return {'ok': True, 'shares': out}

    @rpc
    async def find(self, data: dict) -> dict:
        """Поиск файлов по шаре(-ам): {share?, pattern?} → записи каталога.

        ФС-обход в отдельном потоке — не блокирует event loop узла
        (медленные/сетевые каталоги).
        """
        return await asyncio.to_thread(self._find_sync, data or {})

    def _find_sync(self, data: dict) -> dict:
        pattern = data.get('pattern') or '*'
        want_share = data.get('share')
        rows = []
        for s in self._shares():
            if want_share and s.name != want_share:
                continue
            for e in self._scan(s):
                if not fnmatch.fnmatch(e['path'], pattern):
                    continue
                rows.append({'share': s.name, **e})
                if len(rows) >= int(data.get('limit') or 500):
                    return {'ok': True, 'entries': rows, 'truncated': True}
        return {'ok': True, 'entries': rows}

    @rpc
    async def stat(self, data: dict) -> dict:
        """Манифест файла: {id, share, path, size, mtime, chunk_size}.

        Хеширование (может быть долго для больших файлов) — в потоке.
        """
        return await asyncio.to_thread(self._stat_impl, data or {})

    def _stat_impl(self, data: dict) -> dict:
        share, abspath = self._resolve_ref(data)
        if share is None:
            return {'ok': False, 'error': abspath}
        cs = min(int(data.get('chunk_size') or share.chunk_size),
                 int(getattr(self._cfg(), 'max_chunk', 4 * 1024 * 1024)))
        return {'ok': True, 'manifest': self._manifest(share, abspath, cs)}

    @rpc
    async def read(self, data: dict) -> dict:
        """Прочитать маленький файл целиком (манифесты релизов, конфиги).

        data: {share,path} | {id}; limit? — байт (дефолт 256КБ, потолок 1МБ).
        Ответ: {ok, data: bytes, size}. Чтение в потоке.
        """
        return await asyncio.to_thread(self._read_impl, data or {})

    def _read_impl(self, data: dict) -> dict:
        limit = min(max(int(data.pop('limit', 0) or 262144), 1), 1024 * 1024)
        share, abspath = self._resolve_ref(data)
        if share is None:
            return {'ok': False, 'error': abspath}
        size = abspath.stat().st_size
        if size > limit:
            return {'ok': False,
                    'error': f'файл больше лимита: {size} > {limit} байт'}
        return {'ok': True, 'data': abspath.read_bytes(), 'size': size}

    # ------------------------------------------------------------------ #
    #  RPC: управление шарами (расшаривание из UI)
    # ------------------------------------------------------------------ #

    @rpc
    async def list_local_dirs(self, data: dict) -> dict:
        """Абсолютные пути подкаталогов — для браузера расшаривания в UI.

        {path: ''} → корневые точки (диски Windows / корень ФС).
        Вся ФС-работа — в отдельном потоке: перебор каталогов и тем более
        опрос дисков может быть медленным, синхронный вариант блокировал
        event loop узла до таймаута RPC.

        ВНИМАНИЕ: доступно любому подключенному узлу (до появления
        аутентификации узлов mesh считается доверенной сетью).
        """
        return await asyncio.to_thread(self._list_dirs_sync,
                                       (data or {}).get('path') or '')

    @staticmethod
    def _win_drives() -> list[str]:
        """Логические диски через GetLogicalDrives — мгновенно, без I/O
        (Path.exists() на отключенных сетевых дисках вешает секунды)."""
        try:
            import ctypes
            mask = ctypes.windll.kernel32.GetLogicalDrives()
        except (ImportError, AttributeError):
            return []
        out = []
        for i in range(26):
            if mask >> i & 1:
                out.append(f'{chr(65 + i)}:\\')
        return out

    def _list_dirs_sync(self, raw: str) -> dict:
        try:
            if not raw:
                if os.name == 'nt':
                    roots = self._win_drives()
                    if not roots:                      # winapi недоступен
                        roots = [str(Path(d).resolve())
                                 for d in ('C:\\', '/')
                                 if Path(d).exists()]
                else:
                    roots = ['/']
                return {'ok': True, 'path': '', 'parent': None,
                        'dirs': sorted(roots)}
            p = Path(raw)
            if not p.is_dir():
                return {'ok': False, 'error': f'каталог не найден: {raw}'}
            dirs = sorted(str(d) for d in p.iterdir() if d.is_dir())
            if p.parent == p:
                # корень ФС — для Windows это корень диска (C:\): Вверх должен вести к списку дисков ('')
                parent = '' if os.name == 'nt' else None
            else:
                parent = str(p.parent)
            return {'ok': True, 'path': str(p), 'parent': parent, 'dirs': dirs}
        except (OSError, ValueError) as e:
            return {'ok': False, 'error': str(e)}

    def _persist_shares(self, entries: list[dict]) -> bool:
        """Записать список шар в конфиг и свести обе ссылки на него.

        ConfigManager.update() создаёт НОВЫЙ объект cfg — после него
        ctx.config может указывать на устаревший экземпляр, поэтому
        синхронизируем files.shares на месте у обоих.
        """
        cm = getattr(self.ctx, 'config_manager', None)
        if cm is None:
            self.log.error('config_manager недоступен — шару не сохранить')
            return False
        try:
            cm.update(**{'files__shares': entries})
        except Exception as e:
            self.log.error(f'ошибка записи конфига: {e}')
            return False
        try:
            self.ctx.config.files.shares = list(cm.cfg.files.shares)
        except Exception:
            pass
        return True

    @rpc
    async def add_share(self, data: dict) -> dict:
        """Расшарить каталог этого узла.

        data: {path: абсолютный путь каталога, name?: имя шары
               (по умолчанию — имя папки), allow?: [node_id],
               chunk_size?: байт}
        """
        raw_path = (data or {}).get('path') or ''
        if not raw_path:
            return {'ok': False, 'error': 'укажите path'}
        p = Path(raw_path)
        try:
            real = p.resolve()
        except OSError:
            real = p
        if not real.is_dir():
            return {'ok': False, 'error': f'каталог не найден: {raw_path}'}

        name = ((data.get('name') or '').strip() or real.name)
        if '/' in name or '\\' in name:
            return {'ok': False, 'error': 'имя шары не должно содержать / и \\'}
        allow = [str(x) for x in (data.get('allow') or [])]
        max_chunk = int(getattr(self._cfg(), 'max_chunk', 4 * 1024 * 1024))
        cs = max(1024, min(int(data.get('chunk_size') or 262144), max_chunk))

        current = self._shares()
        if any(s.name == name for s in current):
            return {'ok': False, 'error': f'шара с именем {name!r} уже есть'}
        for s in current:
            try:
                if Path(s.path).resolve() == real:
                    return {'ok': False,
                            'error': f'{real} уже расшарена как {s.name!r}'}
            except OSError:
                pass

        entry = {'name': name, 'path': str(real),
                 'allow': allow, 'chunk_size': cs}
        new_list = [s.model_dump() for s in current] + [entry]
        if not self._persist_shares(new_list):
            return {'ok': False, 'error': 'не удалось записать конфиг'}
        self.log.info(f'share added: {name!r} → {real} (allow={allow or "все"})')
        return {'ok': True, 'share': entry}

    @rpc
    async def remove_share(self, data: dict) -> dict:
        """Убрать шару по имени: {name}."""
        name = (data or {}).get('name')
        current = self._shares()
        new_list = [s.model_dump() for s in current if s.name != name]
        if len(new_list) == len(current):
            return {'ok': False, 'error': f'шара {name!r} не найдена'}
        if not self._persist_shares(new_list):
            return {'ok': False, 'error': 'не удалось записать конфиг'}
        self.log.info(f'share removed: {name!r}')
        return {'ok': True}

    # ------------------------------------------------------------------ #
    #  RPC: передача (источник)
    # ------------------------------------------------------------------ #

    @rpc
    async def serve(self, data: dict) -> dict:
        """Поднять push-стрим файла к запрашивающему узлу.

        data: {label, reply_to, share|path|id, offset=0, save_name?,
               buff=?, chunk_size=?}
        Вызывается методом download() удалённого получателя; label — его.
        """
        label = data.get('label')
        peer = data.get('reply_to')
        if not label or not peer:
            return {'ok': False, 'error': 'нужны label и reply_to'}
        if label in self._serves:
            return {'ok': False, 'error': 'label уже раздаётся'}

        share, abspath = self._resolve_ref(data)
        if share is None:
            return {'ok': False, 'error': abspath}
        if not self._acl_ok(share, peer):
            self.log.warning(f'ACL deny: {peer} → share {share.name!r}')
            return {'ok': False, 'error': f'доступ к шаре {share.name!r} запрещён'}

        cfg = self._cfg()
        cs = min(int(data.get('chunk_size') or share.chunk_size),
                 int(getattr(cfg, 'max_chunk', 4 * 1024 * 1024)))
        offset = max(0, int(data.get('offset') or 0))
        size = abspath.stat().st_size

        manifest = self._manifest(share, abspath, cs)
        manifest['offset'] = offset

        buff = max(2, min(int(data.get('buff') or DEFAULT_BUFF), 64))
        pipe = self.ctx.memory.create_pipe(buff=buff)
        dispatcher = self.ctx.memory.create_dispatcher([pipe])
        template = MsgPack(
            source=self.ctx.NODE,
            dst=peer,
            service='files',
            method=STREAM_NAME,
            label=label,
            data={'label': label, 'manifest': manifest},
        )
        self.ctx.memory.attach_transport(pipe, template, self.ctx.network.router)

        self._serves[label] = {
            'dispatcher': dispatcher, 'peer': peer,
            'share': share.name, 'path': manifest['path'], 'size': size,
            'offset': offset, 'started_at': time.time(),
        }
        dispatcher.start(lambda: self._tracked_read(label, abspath, offset, cs))
        self.log.info(f'serve [{label[:8]}] {manifest["path"]} '
                      f'({size} байт, offset={offset}) → {peer}')
        return {'ok': True, 'label': label, 'size': size,
                'chunk_size': cs, 'manifest': manifest}

    def _tracked_read(self, label: str, path: Path, offset: int, cs: int):
        """Обёртка генератора: чистит _serves по завершении/ошибке."""
        try:
            yield from _chunk_file(path, offset, cs)
        except Exception as e:
            self.log.error(f'serve [{label[:8]}] producer failed: {e}')
            raise
        finally:
            self._serves.pop(label, None)

    # ------------------------------------------------------------------ #
    #  RPC: приём (получатель)
    # ------------------------------------------------------------------ #

    @rpc
    async def download(self, data: dict) -> dict:
        """Скачать файл с указанного узла на ЭТОТ узел.

        data: {dst: узел-источник, ref: {share, path} | {id},
               save_as?: имя на диске, resume?: bool=true}
        Возвращает {ok, label} — статус дальше через RPC downloads().
        """
        dst = data.get('dst')
        if not dst:
            return {'ok': False, 'error': 'укажите dst — узел-источник'}

        # поддержка обоих форматов: плоский {share,path} и вложенный {ref:{...}}
        ref_src = data.get('ref') if isinstance(data.get('ref'), dict) else data
        ref = {k: v for k, v in ref_src.items()
               if k in ('share', 'path', 'id') and v}
        # fallback: если ref вложенный пустой, попробовать плоский
        if not ref and isinstance(data.get('ref'), dict):
            ref = {k: v for k, v in data.items()
                   if k in ('share', 'path', 'id') and v}
        if not ref:
            return {'ok': False, 'error': 'укажите ref: share+path или id'}

        # 1) манифест (размер + sha256 для верификации)
        res = await self.ctx.network.call(dst=dst, service='files',
                                          method='stat', data=ref, timeout=15)
        if not isinstance(res, dict) or not res.get('ok'):
            err = (res or {}).get('error', 'stat failed') \
                if isinstance(res, dict) else 'stat failed'
            return {'ok': False, 'error': err}
        man = res['manifest']

        final = self._target_path(data.get('save_as') or man['path'])
        tmp = final.with_name(final.name + '.part')

        # уже скачан и цел?
        if final.is_file() and _sha256_of(final) == man['id']:
            return {'ok': True, 'label': '', 'done': True, 'path': str(final)}

        resume = bool(data.get('resume', True))
        offset = tmp.stat().st_size if (resume and tmp.is_file()) else 0
        if offset > man['size']:
            offset = 0

        label = str(uuid.uuid4())
        self._downloads[label] = {
            'label': label, 'src': dst, 'name': final.name,
            'path': str(final), 'tmp': str(tmp),
            'id': man['id'], 'size': man['size'],
            'received': offset, 'resumed_from': offset,
            'status': 'running', 'error': '',
            'started_at': time.time(), 'finished_at': 0,
        }
        # окно скорости: (ts, received) — deque живёт только на узле-приёмнике
        self._downloads[label]['speed_win'] = deque(maxlen=64)
        self._downloads[label]['speed_win'].append((time.time(), offset))

        # локальный шорткат: файл уже на этом узле — просто скопировать
        if dst == self.ctx.NODE:
            _, abspath = self._resolve_ref(ref)
            if abspath is None:
                self._fail(label, 'локальный файл не найден')
            else:
                try:
                    shutil.copyfile(abspath, tmp)
                    self._finalize(label, tmp)
                except Exception as e:
                    self._fail(label, str(e))
            return {'ok': True, 'label': label, 'local': True}

        # 2) попросить источник толкать поток
        try:
            served = await self.ctx.network.call(
                dst=dst, service='files', method='serve',
                data={
                    'label': label, 'reply_to': self.ctx.NODE,
                    **ref, 'offset': offset,
                    'save_name': final.name,
                },
                timeout=15,
            )
        except Exception as e:
            self._fail(label, f'serve недоступен: {e}')
            return {'ok': False, 'label': label, 'error': str(e)}

        if not isinstance(served, dict) or not served.get('ok'):
            err = (served or {}).get('error', 'serve failed')
            self._fail(label, err)
            return {'ok': False, 'label': label, 'error': err}
        return {'ok': True, 'label': label, 'size': man['size']}

    def _target_path(self, save_as: str) -> Path:
        name = Path(save_as.replace('\\', '/')).name or 'unnamed'
        return self._download_dir() / name

    def _fail(self, label: str, error: str):
        st = self._downloads.get(label)
        if not st:
            return
        st['status'] = 'error'
        st['error'] = error
        st['finished_at'] = time.time()
        self.log.warning(f'download [{label[:8]}] failed: {error}')

    def _finalize(self, label: str, tmp: Path):
        """Сверить размер и hash, атомарно переименовать .part → final."""
        st = self._downloads[label]
        try:
            if tmp.stat().st_size != st['size']:
                self._fail(label, f"размер не сошёлся: {tmp.stat().st_size} != {st['size']}")
                tmp.unlink(missing_ok=True)
                return
            if _sha256_of(tmp) != st['id']:
                self._fail(label, 'sha256 не совпал')
                tmp.unlink(missing_ok=True)
                return
            os.replace(tmp, st['path'])
            st['status'] = 'done'
            st['received'] = st['size']
            st['finished_at'] = time.time()
            self.log.info(f'download [{label[:8]}] done → {st["path"]}')
        except FileNotFoundError:
            self._fail(label, '.part исчез до завершения')
        except Exception as e:
            self._fail(label, str(e))

    @rpc
    def cancel_download(self, data: dict) -> dict:
        label = data.get('label')
        st = self._downloads.pop(label, None)
        if not st:
            return {'ok': False, 'error': 'загрузка не найдена'}
        try:
            Path(st['tmp']).unlink(missing_ok=True)
        except OSError:
            pass
        self.log.info(f'download [{label[:8]}] cancelled')
        return {'ok': True}

    @rpc
    def downloads(self, data: dict = None) -> dict:
        """Статусы приёмок для UI (свежие сверху) + текущая скорость.

        speed_bps — байт/с по скользящему окну SPEED_WINDOW секунд.
        """
        now = time.time()
        rows = sorted(self._downloads.values(),
                      key=lambda d: d['started_at'], reverse=True)
        out = []
        for d in rows:
            pct = round(100 * d['received'] / d['size']) if d['size'] else 0

            speed_bps = 0
            if d['status'] == 'running':
                win = [s for s in d.get('speed_win', ())
                       if now - s[0] <= SPEED_WINDOW]
                if len(win) >= 2:
                    dt = win[-1][0] - win[0][0]
                    if dt > 0:
                        speed_bps = max(0, (win[-1][1] - win[0][1]) / dt)

            row = {k: v for k, v in d.items() if k != 'speed_win'}
            row.update(pct=min(pct, 100), speed_bps=round(speed_bps))
            out.append(row)
        return {'ok': True, 'downloads': out}

    # ------------------------------------------------------------------ #
    #  Приём push-стрима (STREAM_OPEN method='file_in' приходит сюда)
    # ------------------------------------------------------------------ #
    #  ВАЖНО: имена методов БЕЗ ведущего '_' — get_stream_handlers()
    #  игнорирует приватные имена, и стрим не регистрировался бы.

    @stream_wrapper(STREAM_NAME)
    async def prepare_file_in(self, data: dict) -> dict:
        """STREAM_OPEN: найти состояние загрузки по label из template.data."""
        info = (data or {})
        st = self._downloads.get(info.get('label'))
        if st is None:
            self.log.warning(
                f'incoming file_in для неизвестного label '
                f'{info.get("label", "?")[:8]} — буфер будет сброшен'
            )
        return {'st': st, 'buff': DEFAULT_BUFF}

    @stream_consumer(STREAM_NAME)
    async def consume_file_in(self, pipe: Pipe, ctx: dict):
        router = self.ctx.network.router
        label = ctx.get('label')
        st = ctx.get('st')

        if st is None:
            # неизвестная загрузка: осушаем буфер без ACK —
            # источник сам остановится по таймауту ACK
            async for _chunk in pipe:
                pass
            return

        buff = int(ctx.get('buff') or DEFAULT_BUFF)
        if label:
            await router.send_stream_ack(label, buff)

        tmp = Path(st['tmp'])
        tmp.parent.mkdir(parents=True, exist_ok=True)
        mode = 'ab' if st.get('resumed_from') else 'wb'
        received = st.get('resumed_from', 0)

        with open(tmp, mode) as fh:
            async for chunk in pipe:
                if st['status'] != 'running':
                    break                      # отменена: перестаём ACK-ать
                fh.write(chunk)
                received += len(chunk)
                st['received'] = received
                st['speed_win'].append((time.time(), received))
                if label and pipe.size < buff:
                    await router.send_stream_ack(label, buff)

        if st['status'] != 'running':
            return
        if received != st['size']:
            self._fail(label, f'передача оборвана: {received}/{st["size"]}')
            return
        self._finalize(label, tmp)


# ------------------------------------------------------------------ #
#  Пример (код другого сервиса / ручной вызов):
#
#    res = await ctx.network.call(dst='NodeNAS', service='files',
#                                 method='find', data={'pattern': '*.mp4'})
#    dl  = await ctx.network.call(dst=self.ctx.NODE, service='files',
#                                 method='download',
#                                 data={'dst': 'NodeNAS',
#                                       'share': 'media',
#                                       'path': res['entries'][0]['path']})
#    # статус: rpc files.downloads()
# ------------------------------------------------------------------ #

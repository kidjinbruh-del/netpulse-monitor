# services/system/service.py — управление системой: подключение к узлам, диагностика

import asyncio
import inspect
import subprocess
from pathlib import Path

from pydantic import BaseModel

from netpulse.p2p_core.services.rpc import rpc
from netpulse.p2p_core.internal_modules.base import ModuleGeneric

try:
    import winreg
except ImportError:
    winreg = None


def _canon(s: str) -> str:
    """A2 канонизация — lower + trim. Регистр alias — зло."""
    return s.strip().lower() if isinstance(s, str) else s


# ------------------------------------------------------------------ #
#  Карта контекста приложения (для разработчика сервисов)
#  Описание атрибутов AppContext — см. src/internal_modules/context.py
# ------------------------------------------------------------------ #

CTX_ATTR_DOCS = {
    'NODE':            'Имя этого узла в mesh-сети (config.yaml → node)',
    'config':          'Config — pydantic-модель конфигурации: .network.port, .local.peers, .local.full_path, ...',
    'config_manager':  'ConfigManager — управление конфигом: .cfg, .config_path, .update(...), .add_peer(node_id, uri), .list_peers()',
    'peers':           'Список пиров из config.yaml → local.peers (автоподключение при старте)',
    'services':        'ServiceManager — реестр локальных сервисов и их RPC-методов',
    'certs_index':     'CertsIndex — сводка сертификатов всей сети (обмен CERT_SYNC)',
    '_modules':        'Зарегистрированные модули; порядок в списке = порядок start()',
    'network':         'NetworkModule — WS-сервер узла, mesh-RPC и стримы, топология',
    'memory':          'MemoryModule — фабрика стримов: create_pipe(), create_dispatcher(), attach_transport()',
    'spawn':           'Spawner — распределённые вычисления: раздаёт @generator удалённым воркерам',
}

# Вложенные объекты уровня 2, которые полезно показать отдельно
CTX_CHILD_DOCS = {
    ('network', 'router'):         'Router — маршрутизация всех пакетов: RPC, стримы, кэш маршрутов',
    ('network', 'neighbor_table'): 'NeighborTable — кто в сети: .connected(), .known(), .find_by_service(name)',
    ('network', 'nodes_manager'):  'NodesManager — прямые WS-подключения других узлов к этому',
}

# Простой тип → показываем значение вместо списка методов
_SIMPLE_TYPES = (str, int, float, bool)


class System(ModuleGeneric):
    def __init__(self, name, context):
        super().__init__(name, context)

    @rpc
    async def connect_to_node(self, data: dict):
        """Инициировать исходящее подключение к удалённому узлу.

        Подключение разрешено, если удалённый узел НЕ подключен к локальному
        (по NeighborTable) И соблюдено лексикографическое правило
        (пару dialит только больший узел — см. NodeConnector.start()).
        При успехе — сохраняет пира в config.yaml
        (секция local.peers) для автоматического переподключения при рестарте.

        data: {host, port, node_id}
        """
        host = data.get('host', '')
        port = data.get('port', 9000)
        node_id = _canon(data.get('node_id', ''))

        if not host or not node_id:
            return {'ok': False, 'error': 'host и node_id обязательны'}

        nt = self.ctx.network.neighbor_table
        # канонизированный поиск — без учёта регистра
        existing = nt.get(node_id)
        if existing is None:
            # fallback case-insensitive поиск по таблице
            for n in nt.all():
                if _canon(n.node_id) == node_id and n.status.value == 'connected':
                    existing = n
                    break
        if existing and existing.status.value == 'connected':
            return {'ok': False, 'error': f'Узел {node_id} уже подключен'}

        # Reverse-HELLO: HELLO уходит всегда, lex проверяется на принимающей
        # стороне (NetworkModule.websocket_endpoint). Если сервер больше — он
        # отвечает HELLO_REJECT lex_rule и сам dial'ит обратно по host/port
        # из HELLO.data. Здесь hard-block снят.
        uri = f'ws://{host}:{port}/ws/{self.ctx.NODE}'
        config_uri = f'ws://{host}:{port}/ws/'

        try:
            await self.ctx.network.connect_to(node_id=node_id, target_uri=uri)
        except Exception as e:
            return {'ok': False, 'error': str(e)}

        # Дождаться подтверждения подключения (до 5 сек)
        connected = False
        for _ in range(10):
            await asyncio.sleep(0.5)
            entry = nt.get(node_id)
            if entry and entry.status.value == 'connected':
                connected = True
                break

        if connected:
            try:
                # верный источник пиров — ConfigManager; поддерживаем оба для совместимости
                mgr = getattr(self.ctx, 'config_manager', None)
                if mgr is not None and hasattr(mgr, 'add_peer'):
                    mgr.add_peer(node_id, config_uri)
                else:
                    self.ctx.config.add_peer(node_id, config_uri)
                self.log.info(f'Peer saved to config: {node_id} → {config_uri}')
            except Exception as e:
                self.log.warning(f'Failed to save peer to config: {e}')
            return {'ok': True, 'node_id': node_id, 'uri': uri, 'saved': True}

        return {'ok': True, 'node_id': node_id, 'uri': uri, 'saved': False,
                'note': 'Подключение в процессе (коннектор будет повторять попытки)'}

    @rpc
    def list_connectors(self):
        """Список активных исходящих коннекторов."""
        result = []
        for mod in self.ctx._modules:
            if 'Connector_' in mod.name:
                result.append({
                    'name': mod.name,
                    'peer': getattr(mod, 'peer_node_id', '?'),
                    'uri': getattr(mod, 'target_uri', '?'),
                })
        return result

    @rpc
    def node_detail(self,):
        """Детальная информация об узле: соседи, сервисы, активные WS."""
        nt = self.ctx.network.neighbor_table
        nm = self.ctx.network.nodes_manager

        connected = [n.model_dump() for n in nt.connected()]
        known = [n.model_dump() for n in nt.known()]

        ws_nodes = list(nm.nodes.keys())

        return {
            'own': self.ctx.NODE,
            'connected': connected,
            'known': known,
            'ws_connections': ws_nodes,
            'services': list(self.ctx.services.services.keys()),
        }

    @rpc
    def config_peers(self):
        """Список пиров из config.yaml (local.peers)."""
        mgr = getattr(self.ctx, 'config_manager', None)
        if mgr is not None and hasattr(mgr, 'list_peers'):
            peers = mgr.list_peers()
        else:
            peers = self.ctx.config.list_peers()
        return [{'node_id': p.node_id, 'uri': p.uri} for p in peers]

    @rpc
    async def remove_peer(self, data: dict):
        """Удалить ожидающий коннектор/пира: из config.yaml и остановить живой Connector_*.

        Принимает любой регистр — канонизирует к lower. Останавливает живой коннектор
        (если есть), чистит _modules и config. Используется когда имя введено с ошибкой
        регистра (lower vs KaKtOTaK) — регистр alias это зло.
        data: {node_id}
        """
        raw_id = (data or {}).get('node_id') or (data or {}).get('peer') or ''
        node_id = _canon(raw_id)
        if not node_id:
            return {'ok': False, 'error': 'node_id обязателен'}

        # 1) config
        mgr = getattr(self.ctx, 'config_manager', None)
        removed_cfg = False
        try:
            if mgr is not None and hasattr(mgr, 'remove_peer'):
                # пробуем точный lower, затем case-insensitive fallback по файлу
                removed_cfg = mgr.remove_peer(node_id)
                if not removed_cfg:
                    # fallback: ищем фактический ключ в файле с учётом регистра
                    from netpulse.p2p_core.internal_modules.config import _load_yaml
                    data_raw = _load_yaml(mgr.config_path)
                    peers_raw = (data_raw.get('local') or {}).get('peers') or []
                    for p in peers_raw:
                        if _canon(p.get('node_id','')) == node_id:
                            removed_cfg = mgr.remove_peer(p.get('node_id'))
                            break
            elif hasattr(self.ctx.config, 'remove_peer'):
                removed_cfg = self.ctx.config.remove_peer(node_id)
        except Exception as e:
            return {'ok': False, 'error': f'ошибка удаления из config: {e}'}

        # 2) живой коннектор(ы) — останавливаем
        stopped = 0
        to_stop = []
        for mod in list(self.ctx._modules):
            if 'Connector_' in getattr(mod, 'name', ''):
                peer = _canon(getattr(mod, 'peer_node_id', ''))
                if peer == node_id or _canon(getattr(mod, 'name', '')) == f"connector_{node_id}":
                    to_stop.append(mod)
        for mod in to_stop:
            try:
                await mod.stop()
            except Exception as e:
                self.log.warning(f'remove_peer stop {mod.name}: {e}')
            try:
                if mod in self.ctx._modules:
                    self.ctx._modules.remove(mod)
            except Exception:
                pass
            stopped += 1
            self.log.info(f'Connector stopped and removed: {mod.name}')

        # 3) если коннектора не было, но запись в config была — считаем успехом
        if removed_cfg or stopped:
            return {'ok': True, 'node_id': node_id, 'removed_config': bool(removed_cfg), 'stopped_connectors': stopped}
        return {'ok': False, 'error': f'пир {node_id} не найден (ни в config, ни среди коннекторов)'}

    @rpc
    async def rename_node(self, data: dict):
        """Переименовать узел (канонизация A2 — lower).

        Меняет Config.node и LocalConfig.alias (отображаемое имя). Требует рестарт
        для полного применения (WS endpoint, NeighborTable, mutex). Обновляет
        config.yaml и in-memory ctx.NODE/cfg.
        data: {new_name} или {node} или {alias}
        """
        raw = (data or {}).get('new_name') or (data or {}).get('node') or (data or {}).get('alias') or (data or {}).get('name') or ''
        new_name = _canon(raw)
        if not new_name:
            return {'ok': False, 'error': 'new_name обязателен'}
        if len(new_name) < 1 or len(new_name) > 64:
            return {'ok': False, 'error': 'имя должно быть 1..64 символов'}
        old_node = getattr(self.ctx, 'NODE', '?')
        old_alias = getattr(getattr(self.ctx, 'config', None), 'local', None)
        old_alias = getattr(old_alias, 'alias', '?') if old_alias else '?'

        mgr = getattr(self.ctx, 'config_manager', None)
        try:
            if mgr is not None:
                # обновляем оба поля — node и local.alias (name — задача планировщика, не трогаем)
                mgr.update(node=new_name, local__alias=new_name)
                # in-memory
                self.ctx.NODE = new_name
                # cfg уже обновлён внутри mgr.update, но продублируем для ctx.config если это разные объекты
                try:
                    if hasattr(self.ctx, 'config') and hasattr(self.ctx.config, 'node'):
                        self.ctx.config.node = new_name
                        if hasattr(self.ctx.config, 'local') and hasattr(self.ctx.config.local, 'alias'):
                            self.ctx.config.local.alias = new_name
                except Exception:
                    pass
            else:
                # fallback: правим напрямую Config
                self.ctx.config.node = new_name
                if hasattr(self.ctx.config, 'local'):
                    self.ctx.config.local.alias = new_name
            self.log.info(f'Node renamed: {old_node} ({old_alias}) → {new_name}')
            return {'ok': True, 'old_node': old_node, 'new_node': new_name, 'need_restart': True,
                    'note': 'Имя изменено в config.yaml, для полного применения перезапустите узел'}
        except Exception as e:
            return {'ok': False, 'error': str(e)}

    @rpc
    def sessions(self, data: dict = None):
        """Все сессии узла — записи NeighborTable любого статуса.

        Сессия выдаётся при HELLO-рукопожатии: сервер генерирует session_id,
        пишет в лог «Node X accepted (session=...)» и возвращает в HELLO_ACK;
        дальше он хранится в NeighborTable.session_id.

        По каждой записи: node_id, host, port, status
        (connected/known/unreachable), session_id, version, services,
        last_ts + age_sec, direction:
          inbound          — входящее WS (принято WS-сервером этого узла)
          outbound         — исходящее (NodeConnector, client-side WS)
          inbound+outbound — есть оба канала
          ''               — живого WS нет (known/unreachable)

        Построение строк — общий источник с netinfo.topology():
        NetworkModule.local_sessions().
        """
        rows = self.ctx.network.local_sessions()

        order = {'connected': 0, 'known': 1, 'unreachable': 2}
        rows.sort(key=lambda r: (order.get(r.get('status'), 3), r.get('node_id', '')))

        counts = {
            'total': len(rows),
            'connected': sum(1 for r in rows if r['status'] == 'connected'),
            'known': sum(1 for r in rows if r['status'] == 'known'),
            'unreachable': sum(1 for r in rows if r['status'] == 'unreachable'),
            'inbound': sum(1 for r in rows if 'inbound' in r['direction']),
            'outbound': sum(1 for r in rows if 'outbound' in r['direction']),
        }
        return {'ok': True, 'own': self.ctx.NODE, 'counts': counts,
                'sessions': rows}

    # ------------------------------------------------------------------ #
    #  Интроспекция AppContext — подсказка разработчику «что доступно»
    # ------------------------------------------------------------------ #

    @rpc
    def ctx_map(self):
        """Карта контекста приложения (self.ctx) для разработчика сервисов.

        По каждому атрибуту AppContext возвращает: тип, назначение,
        публичные методы с сигнатурами. Ключевые подсистемы (router,
        neighbor_table и т.п.) раскрыты на уровень глубже.
        """
        ctx = self.ctx
        entries = []

        # ключи конфига, значения которых маскируются в UI
        _SECRET_KEYS = {'secret', 'password', 'token', 'key'}

        def to_jsonable(obj, key_name=''):
            """Рекурсивно превратить значение в JSON-совместимую структуру.

            pydantic-модели (Config, PeerConfig...) раскрываются в словари
            значений — так в панели видно не только типы, но и текущий config.
            Секретные поля маскируются.
            """
            if isinstance(obj, BaseModel):
                return {k: ('***' if k.lower() in _SECRET_KEYS else to_jsonable(v, k))
                        for k, v in obj}
            if isinstance(obj, _SIMPLE_TYPES) or obj is None:
                return obj
            if isinstance(obj, dict):
                return {str(k): to_jsonable(v, str(k)) for k, v in obj.items()}
            if isinstance(obj, (list, tuple, set)):
                return [to_jsonable(v, key_name) for v in obj]
            if isinstance(obj, Path):
                return str(obj)
            return repr(obj)

        def describe(obj, name, doc=''):
            entry = {
                'name': name,
                'type': type(obj).__name__,
                'doc': doc,
                'value': None,
                'data': None,
                'methods': [],
                'attrs': [],
                'children': [],
            }
            if isinstance(obj, _SIMPLE_TYPES) or obj is None:
                entry['value'] = repr(obj)
                return entry

            # модели/списки/словари (config, peers и т.п.) — показать значениями
            if isinstance(obj, (BaseModel, list, tuple, dict)):
                entry['data'] = to_jsonable(obj)
                return entry

            for attr_name in sorted(dir(obj)):
                if attr_name.startswith('_'):
                    continue
                try:
                    attr = getattr(obj, attr_name)
                except Exception:
                    continue

                if callable(attr):
                    try:
                        sig = str(inspect.signature(attr))
                        sig = f'({sig[1:-1]})' if sig.startswith('(') else sig
                    except (TypeError, ValueError):
                        sig = '(...)'
                    if len(sig) > 140:
                        sig = sig[:137] + '...'
                    entry['methods'].append({'name': attr_name, 'sig': sig})
                elif isinstance(attr, type):
                    entry['attrs'].append(f'{attr_name}: class {attr.__name__}')
                else:
                    entry['attrs'].append(
                        f"{attr_name}: {type(attr).__name__}")

            return entry

        def resolve_rpc_service(obj):
            """Какому сервису из реестра соответствует объект (если соответствует).

            Например self.ctx.spawn — это сервис 'spawner': его методы можно
            вызвать по сети. Router/NeighborTable — внутренние объекты,
            напрямую через RPC их не дёрнешь.
            """
            try:
                for svc_name, bucket in self.ctx.services.services.items():
                    if bucket.get('self') is obj:
                        return svc_name
            except Exception:
                pass
            return None

        # порядок: сначала задокументированные атрибуты, потом остальные
        known = [n for n in CTX_ATTR_DOCS if hasattr(ctx, n)]
        extra = [n for n in dir(ctx)
                 if not n.startswith('_') and n not in CTX_ATTR_DOCS]

        for attr_name in known + extra:
            obj = getattr(ctx, attr_name, None)
            entry = describe(obj, attr_name, CTX_ATTR_DOCS.get(attr_name, ''))
            entry['rpc_service'] = resolve_rpc_service(obj)

            # вложенные подсистемы (например network.router)
            for (parent, child), child_doc in CTX_CHILD_DOCS.items():
                if parent == attr_name and obj is not None:
                    child_obj = getattr(obj, child, None)
                    if child_obj is not None:
                        child_entry = describe(child_obj, f'{attr_name}.{child}',
                                               child_doc)
                        child_entry['rpc_service'] = resolve_rpc_service(child_obj)
                        entry['children'].append(child_entry)

            # ServiceManager — вместо методов показываем реестр сервисов
            if attr_name == 'services':
                registry = {}
                for svc_name, methods in getattr(ctx.services, 'services', {}).items():
                    registry[svc_name] = {
                        'methods': sorted(
                            m for m in methods
                            if m != 'self' and not m.startswith('__gen__')),
                        'generators': sorted(
                            m[len('__gen__'):] for m in methods
                            if m.startswith('__gen__')),
                    }
                entry['registry'] = registry

            entries.append(entry)

        return {'node': ctx.NODE, 'entries': entries}

    def _local_cfg(self):
        """Вернуть LocalConfig независимо от того, где лежит конфиг.

        Поддерживает оба источника из-за исторической путаницы
        ctx.config (Config) vs ctx.config_manager (ConfigManager):
        ConfigManager хранит модель в .cfg, Config — напрямую в .local.
        """
        # 1) Config — pydantic модель (основной путь)
        cfg = getattr(self.ctx, 'config', None)
        if cfg is not None:
            # если это ConfigManager (у него есть .cfg) — берём .cfg.local
            if hasattr(cfg, 'cfg') and hasattr(getattr(cfg, 'cfg', None), 'local'):
                try:
                    return cfg.cfg.local
                except Exception:
                    pass
            if hasattr(cfg, 'local'):
                try:
                    return cfg.local
                except Exception:
                    pass
        # 2) ConfigManager
        mgr = getattr(self.ctx, 'config_manager', None)
        if mgr is not None:
            if hasattr(mgr, 'cfg') and hasattr(getattr(mgr, 'cfg', None), 'local'):
                try:
                    return mgr.cfg.local
                except Exception:
                    pass
            if hasattr(mgr, 'local'):
                try:
                    return mgr.local
                except Exception:
                    pass
        # fallback — пусть упадёт с понятной ошибкой
        return cfg.local  # type: ignore

    def add_to_task_scheduler(self):
        """Задача автозапуска при старте хоста (/SC ONSTART, от SYSTEM).

        Узел не зависит от пользовательской сессии: запускается при
        загрузке машины до чьего-либо логина. Имя задачи = LocalConfig.name.
        Возвращает True при успехе.
        """
        local = self._local_cfg()
        exe_path = local.full_path
        task_name = local.name

        try:
            cmd = (f'schtasks /Create /F /TN "{task_name}" /TR "{exe_path}" '
                   f'/SC ONSTART /RU "NT AUTHORITY\\SYSTEM" '
                   f'/DELAY 0000:30 /rl highest')
            result = subprocess.call(cmd, shell=True,
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
            if result != 0:
                self.log.error(f'Ошибка создания задачи планировщика '
                               f'(код {result}): {cmd}')
                return False
            self.log.info(f'Задача автозапуска (ONSTART, SYSTEM) создана: '
                          f'{task_name}')
            return True
        except Exception as e:
            self.log.error(f'Ошибка создания задачи планировщика: {e}')
            return False

    def remove_from_task_scheduler(self):
        """Удаляет задачу планировщика (имя = LocalConfig.name).

        True = задачи больше нет (удалена или отсутствовала).
        """
        task_name = self._local_cfg().name
        try:
            cmd = f'schtasks /Delete /F /TN "{task_name}"'
            result = subprocess.call(cmd, shell=True,
                                     stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL)
            if result != 0:
                # 0 — удалена; иначе отсутствовала/отказ — различить нельзя,
                # schtasks пишет всё в stderr, который мы глушим
                self.log.info(f'Задача планировщика не удалена '
                              f'(код {result}): возможно, отсутствовала')
                return False
            self.log.info(f'Удалено из планировщика: {task_name}')
            return True
        except Exception as e:
            self.log.error(f'Ошибка удаления задачи планировщика: {e}')
            return False

    def remove_from_registry_startup(self):
        """[legacy] Удаляет ключ автозапуска из HKCU Run.

        Реестровый канал автозапуска упразднён (узел стартует от SYSTEM
        при ONSTART), метод оставлен для зачистки ключей, оставшихся
        от старых версий. True = ключа больше нет.
        """
        if winreg is None:
            return False

        try:
            key_name = self._local_cfg().name

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0,
                winreg.KEY_SET_VALUE
            )

            try:
                winreg.DeleteValue(key, key_name)
                self.log.info(f"Удалён legacy-ключ автозапуска: {key_name}")
            except FileNotFoundError:
                pass
            finally:
                winreg.CloseKey(key)

            return True

        except OSError as e:
            self.log.error(f"Ошибка удаления из реестра: {e}")
            return False

    # ------------------------------------------------------------------ #
    #  Автозапуск узла (отдельная вкладка UI) — RPC-обвязка
    # ------------------------------------------------------------------ #

    def _autorun_task_present(self) -> bool:
        """Есть ли задача schtasks с именем LocalConfig.name."""
        task_name = self._local_cfg().name
        return subprocess.call(
            f'schtasks /Query /TN "{task_name}"',
            shell=True, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL) == 0

    def _autorun_registry_present(self) -> bool:
        """Есть ли legacy-ключ HKCU Run."""
        if winreg is None:
            return False
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_READ)
            try:
                winreg.QueryValueEx(key, self._local_cfg().name)
                return True
            except OSError:
                return False
            finally:
                try:
                    winreg.CloseKey(key)
                except Exception:
                    pass
        except OSError:
            return False

    @rpc
    def autorun_status(self, data: dict = None) -> dict:
        """Статус автозапуска узла.

        Возвращает {ok, enabled(task), registry_present, task_name, exe_path, full_path}.
        enabled=True если задача планировщика ONSTART/SYSTEM присутствует.
        """
        local = self._local_cfg()
        return {
            'ok': True,
            'enabled': self._autorun_task_present(),
            'task_present': self._autorun_task_present(),
            'registry_present': self._autorun_registry_present(),
            'task_name': local.name,
            'exe_path': str(local.full_path),
            'work_dir': str(local.work_dir),
        }

    @rpc
    def autorun_enable(self, data: dict = None) -> dict:
        """Активировать автозапуск (создать задачу ONSTART/SYSTEM).

        Использует существующий backend add_to_task_scheduler().
        """
        ok = self.add_to_task_scheduler()
        return {
            'ok': ok,
            'enabled': self._autorun_task_present(),
            'task_name': self._local_cfg().name,
            'error': None if ok else 'не удалось создать задачу планировщика (см. лог узла)',
        }

    @rpc
    def autorun_disable(self, data: dict = None) -> dict:
        """Отключить автозапуск (удалить задачу + legacy-ключ реестра).

        Логика удаления задачи — как в purge (autorun_task), реестра — как в
        remove_from_registry_startup().
        """
        task_ok = self.remove_from_task_scheduler()
        reg_ok = self.remove_from_registry_startup()
        # для UI считаем «отключено» если задачи нет (удалена или отсутствовала)
        still_present = self._autorun_task_present()
        ok = not still_present
        return {
            'ok': ok,
            'enabled': still_present,
            'task_removed': task_ok,
            'registry_removed': reg_ok,
            'task_name': self._local_cfg().name,
            'error': None if ok else 'задача планировщика не удалена (возможно, отсутствует или отказ)',
        }


# src/internal_modules/config.py

import copy
import logging
import os
import socket
from pathlib import Path
from typing import Optional, Any

import yaml
from pydantic import BaseModel, field_validator

log = logging.getLogger('Config')

_HOSTNAME = socket.gethostname()


def _canon_node(v: Any) -> Any:
    """A2: канонизация идентификатора узла к lower — регистр alias это зло."""
    if isinstance(v, str):
        s = v.strip()
        return s.lower() if s else s
    return v


# ------------------------------------------------------------------ #
#  Модели
# ------------------------------------------------------------------ #

class NetworkConfig(BaseModel):
    host: str = '0.0.0.0'
    port: int = 9000
    ip_ttl_sec: int = 60


class MemoryConfig(BaseModel):
    default_buff: int = 10


class LoggingConfig(BaseModel):
    level: str = 'INFO'
    uvicorn_level: str = 'WARNING'
    websockets_level: str = 'WARNING'


class LogsConfig(BaseModel):
    """Буфер логов для веб-панели (сервис logs)."""
    buffer_size: int = 2000        # ёмкость кольцевого буфера
    max_msg_len: int = 4000        # обрезка одного сообщения
    max_traceback_len: int = 2000  # обрезка traceback (берётся хвост)


class ShareConfig(BaseModel):
    """Раздаваемый каталог файлового транспорта (сервис files)."""
    name: str                       # публичное имя шары в mesh
    path: Path                      # локальный каталог
    allow: list[str] = []           # node_id, кому можно; пусто = всем подключенным
    chunk_size: int = 262144        # размер чанка чтения, байт (256 KB)

    @field_validator('allow', mode='before')
    @classmethod
    def _canon_allow(cls, v):
        if isinstance(v, list):
            return [_canon_node(x) for x in v]
        return v


class FilesConfig(BaseModel):
    """Файловый транспорт (сервис files)."""
    shares: list[ShareConfig] = []
    download_dir: Path = Path('downloads')  # куда класть полученные файлы
    max_chunk: int = 4 * 1024 * 1024        # потолок chunk_size из запросов


class UpdateSource(BaseModel):
    """Узел-источник релизов для сервиса обновлений."""
    node: str                       # имя узла в mesh
    share: str = 'releases'         # имя шары с релизами на этом узле

    @field_validator('node', mode='before')
    @classmethod
    def _canon_node(cls, v):
        return _canon_node(v)


class UpdateConfig(BaseModel):
    """Обновление узла (сервис updater)."""
    enabled: bool = True
    sources: list[UpdateSource] = []
    auto_check: bool = True             # периодический check по расписанию
    check_interval_min: int = 60
    auto_apply: bool = False            # применять без подтверждения из панели
    require_signed: bool = True         # WinVerifyTrust перед применением
    allow_downgrade: bool = False       # понижение версии через apply(force)
    health_confirm_sec: int = 90        # сколько ждать до boot_ok после апдейта


class PurgeConfig(BaseModel):
    """Аварийное удаление узла со всеми данными (сервис purge).

    Включён по умолчанию: headless-узел не имеет локального UI, аварийное
    удаление обязано работать безпредпятственно из веб-панели.
    """
    enabled: bool = True


class EyesauronStoreConfig(BaseModel):
    """Пакованное дедуп-хранилище (спека: docs/eyesauron_storage.md).

    Пока выключено — ingest пишет raw PNG как раньше. При включении кадры
    дедуплицируются тайлами 256×256 в иммутабельные тома .pack (локальный
    staging → seal → одна последовательная заливка на NAS).
    """
    enabled: bool = False
    root: Path = Path(r'\\192.168.53.21\photo\store\packs')  # NAS: готовые тома + манифест
    volume_size_gb: int = 10             # D4: цель seal по размеру
    local_cache_gb: int = 100            # D2: кэш готовых томов локально
    max_age_hours: float = 24.0          # seal полупустого тома по возрасту
    bloom_enabled: bool = False          # D6: поиск по bloom (файлы пишутся всегда)


class EyesauronConfig(BaseModel):
    """Мониторинг экранов EyeSauron (сервис eyesauron).

    По умолчанию ВЫКЛЮЧЕН (enabled: false) — включать осознанно.
    Роли независимы и могут сочетаться на одном узле:
      collect — коллектор: принимает кадры по mesh, пишет raw PNG в store_path;
      capture — агент: захватывает экраны машины (хелпер в сессии пользователя)
                и отправляет их узлу collector_node.
    """
    enabled: bool = False
    collect: bool = True            # роль коллектора (при включённом сервисе)
    capture: bool = False           # роль агента захвата
    store_path: Path = Path(r'\\192.168.53.21\photo\screens')  # raw PNG <host>/<date>/<ts>__<title>.png
    collector_node: str = ''        # узел-коллектор для отправки кадров ('' = копить в spool)

    @field_validator('collector_node', mode='before')
    @classmethod
    def _canon_collector(cls, v):
        return _canon_node(v)
    interval_sec: float = 5.0       # период захвата, сек (как в оригинале — минимум 1с)
    send_delay_sec: float = 0.5     # пауза между отправками кадров (щадит NAS)
    max_spool_mb: int = 500         # потолок офлайн-буфера; переполнение → удаляются старейшие кадры
    store: EyesauronStoreConfig = EyesauronStoreConfig()  # пакованное дедуп-хранилище


class WebPanelAuthConfig(BaseModel):
    """Авторизация веб-панели (services/webpanel).

    Выключена по умолчанию — существующие установки работают без изменений.
    Включение: config.yaml → webpanel.auth.enabled: true + users {login: sha256(password)}.
    Хеш: python -c "import hashlib; print(hashlib.sha256(b'pass').hexdigest())"
    """
    enabled: bool = True
    users: dict[str, str] = {}


class WebPanelConfig(BaseModel):
    """Настройки веб-панели."""
    auth: WebPanelAuthConfig = WebPanelAuthConfig()


class ServicesConfig(BaseModel):
    path: Path = Path('services')


class PeerConfig(BaseModel):
    node_id: str
    uri: str

    @field_validator('node_id', mode='before')
    @classmethod
    def _canon_node_id(cls, v):
        return _canon_node(v)


class LocalConfig(BaseModel):
    alias: str = _HOSTNAME
    name: str = 'Core'
    exe_name: str = 'Node_P2P_Core.exe'
    secret: Optional[str] = None
    work_dir: Path = Path(r'C:\Core')
    os.makedirs(work_dir, exist_ok=True)
    full_path: Path = work_dir / exe_name
    excluded_autoload_services: list = ['webpanel']
    peers: list[PeerConfig] = []

    @field_validator('alias', 'name', mode='before')
    @classmethod
    def _canon_local(cls, v):
        return _canon_node(v)


class Config(BaseModel):
    node: str = _HOSTNAME
    network: NetworkConfig = NetworkConfig()
    memory: MemoryConfig = MemoryConfig()
    logging: LoggingConfig = LoggingConfig()
    logs: LogsConfig = LogsConfig()
    files: FilesConfig = FilesConfig()
    update: UpdateConfig = UpdateConfig()
    purge: PurgeConfig = PurgeConfig()
    eyesauron: EyesauronConfig = EyesauronConfig()
    webpanel: WebPanelConfig = WebPanelConfig()
    services: ServicesConfig = ServicesConfig()
    local: LocalConfig = LocalConfig()
    config_confirm_sec: int = 15

    @field_validator('node', mode='before')
    @classmethod
    def _canon_node_field(cls, v):
        return _canon_node(v)

    @field_validator('node')
    @classmethod
    def node_not_empty(cls, v):
        if not v.strip():
            raise ValueError('node name cannot be empty')
        return v


def _default_config_dict() -> dict:
    """Эталонный dict всех полей конфига с дефолтными значениями."""
    return Config().model_dump(mode='json')


def _deep_fill(target: dict, defaults: dict, prefix: str = '') -> list[str]:
    """Достроить target отсутствующими ключами из defaults (in place).

    Рекурсивно добавляет только отсутствующие ключи; существующие
    значения не перезаписываются. None вместо секции (dict) трактуется как
    отсутствие секции и достраивается. Скалярные None (напр. local.secret)
    считаются присутствующим значением — не добавляются повторно.
    Возвращает список добавленных путей ('network.port') для логирования.
    """
    added: list[str] = []
    for key, dval in defaults.items():
        path = f'{prefix}.{key}' if prefix else key
        if key not in target:
            target[key] = copy.deepcopy(dval)
            added.append(path)
        else:
            cur = target[key]
            if isinstance(dval, dict):
                if cur is None or not isinstance(cur, dict):
                    target[key] = copy.deepcopy(dval)
                    added.append(path)
                else:
                    added.extend(_deep_fill(cur, dval, path))
            # скаляр: уже присутствует (даже если None) — не трогаем
    return added


def _ensure_config(path: Path):
    if not path.exists():
        config_dict = _default_config_dict()

        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, 'w', encoding='utf-8') as f:
            yaml.dump(
                config_dict,
                f,
                sort_keys=False,  # Сохраняет порядок полей из Pydantic-класса
                allow_unicode=True,  # Корректно пишет кириллицу и спецсимволы
                default_flow_style=False  # Генерирует красивый блочный YAML (не инлайн)
            )

        log.info(f'Created default config: {path}')


# ------------------------------------------------------------------ #
#  IO
# ------------------------------------------------------------------ #

def _load_yaml(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, encoding='utf-8') as f:
        return yaml.safe_load(f) or {}


def _save_yaml(path: Path, data: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        yaml.dump(data, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    log.debug(f'Saved config: {path}')


def _set_nested(data: dict, keys: list[str], value: Any):
    d = data
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    d[keys[-1]] = value


def _get_nested(data: dict, keys: list[str]) -> tuple[Any, dict]:
    """(value, parent_dict) для модификации на месте."""
    d = data
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    return d.get(keys[-1]), d


# ------------------------------------------------------------------ #
#  ConfigManager
# ------------------------------------------------------------------ #

class ConfigManager:
    """
    Загрузка, хранение и обновление конфига.
    Один файл — config.yaml. Автосохранение при любой модификации.
    """

    def __init__(self, config_path: Path = Path('config.yaml')):
        self._config_path = config_path
        self.cfg: Config = self._load()

    @property
    def config_path(self) -> Path:
        """Путь к config.yaml (нужен сервису purge для аварийного удаления)."""
        return self._config_path

    # ------------------------------------------------------------------ #
    #  Internal
    # ------------------------------------------------------------------ #

    def _load(self) -> Config:
        _ensure_config(self._config_path)
        raw = _load_yaml(self._config_path)

        added = _deep_fill(raw, _default_config_dict())
        if added:
            _save_yaml(self._config_path, raw)
            log.info(f'Config backfilled with default fields: {", ".join(added)}')

        cfg = Config(**raw)

        # A2: канонизация + дедуп peers по lower node_id (миграция файла если был разный регистр)
        # Validators уже привели всё к lower, но в файле мог остаться верхний регистр и дубли
        _need_migrate = False
        # проверка регистра в файле vs canonical
        _raw_node = raw.get('node', '')
        _raw_alias = (raw.get('local') or {}).get('alias', '')
        _raw_name = (raw.get('local') or {}).get('name', '')
        if isinstance(_raw_node, str) and _raw_node != cfg.node:
            _need_migrate = True
        if isinstance(_raw_alias, str) and _raw_alias != cfg.local.alias:
            _need_migrate = True
        if isinstance(_raw_name, str) and _raw_name != cfg.local.name:
            _need_migrate = True
        # peers: сравнить raw vs canonical + дедуп
        _raw_peers = (raw.get('local') or {}).get('peers') or []
        if len(_raw_peers) != len(cfg.local.peers):
            _need_migrate = True
        else:
            for rp, cp in zip(_raw_peers, cfg.local.peers):
                if rp.get('node_id') != cp.node_id:
                    _need_migrate = True
                    break
        # дедуп peers по lower (если две записи стали одной)
        seen = {}
        uniq = []
        for p in cfg.local.peers:
            low = p.node_id.lower()
            if low not in seen:
                seen[low] = True
                uniq.append(p)
        if len(uniq) != len(cfg.local.peers):
            cfg.local.peers = uniq
            _need_migrate = True
        # allow в шарах тоже канонизируем и сравниваем
        for rp_share, cp_share in zip(_raw_peers, cfg.local.peers):
            pass  # peers уже проверены
        if _need_migrate:
            # перезаписываем файл каноническим дампом
            _save_yaml(self._config_path, cfg.model_dump(mode='json'))
            log.info(f'Config canonicalized to lower case (A2) and saved: node={cfg.node}')

        log.info(
            f'Config loaded: node={cfg.node} '
            f'port={cfg.network.port} '
            f'alias={cfg.local.alias} '
            f'peers={len(cfg.local.peers)}'
        )
        return cfg

    def reload(self):
        """Перечитать файл с диска."""
        self.cfg = self._load()
        log.info('Config reloaded')

    # ------------------------------------------------------------------ #
    #  Обновление конфига
    # ------------------------------------------------------------------ #

    def update(self, **kwargs):
        """
        Обновить любое поле конфига и сохранить config.yaml.
        Вложенность через '__':
            update(network__port=9001, logging__level='INFO')
        """
        data = _load_yaml(self._config_path)
        for key, value in kwargs.items():
            parts = key.split('__')
            _set_nested(data, parts, value)
        _save_yaml(self._config_path, data)
        self.cfg = Config(**data)
        log.info(f'Config updated: {kwargs}')

    # ------------------------------------------------------------------ #
    #  Управление пирами
    # ------------------------------------------------------------------ #

    def add_peer(self, node_id: str, uri: str) -> bool:
        node_id = _canon_node(node_id)
        data = _load_yaml(self._config_path)
        peers_data = data.setdefault('local', {}).setdefault('peers', [])

        if any(_canon_node(p.get('node_id', '')) == node_id for p in peers_data):
            log.warning(f'Peer already exists: {node_id}')
            return False

        peers_data.append({'node_id': node_id, 'uri': uri})
        _save_yaml(self._config_path, data)
        self.cfg.local.peers.append(PeerConfig(node_id=node_id, uri=uri))
        log.info(f'Peer added: {node_id} → {uri}')
        return True

    def remove_peer(self, node_id: str) -> bool:
        node_id = _canon_node(node_id)
        data = _load_yaml(self._config_path)
        peers_data = data.get('local', {}).get('peers', [])
        new_peers = [p for p in peers_data if _canon_node(p.get('node_id', '')) != node_id]

        if len(new_peers) == len(peers_data):
            log.warning(f'Peer not found: {node_id}')
            return False

        data['local']['peers'] = new_peers
        _save_yaml(self._config_path, data)
        self.cfg.local.peers = [
            p for p in self.cfg.local.peers if p.node_id != node_id
        ]
        log.info(f'Peer removed: {node_id}')
        return True

    def list_peers(self) -> list[PeerConfig]:
        return self.cfg.local.peers


# ------------------------------------------------------------------ #
#  Shortcut
# ------------------------------------------------------------------ #

def load_config(config_path: Path = Path('config.yaml')) -> ConfigManager:
    return ConfigManager(config_path)

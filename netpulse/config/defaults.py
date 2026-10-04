from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional, List, Dict, Any
import json


class WebSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_WEB_", extra="ignore")
    
    host: str = "127.0.0.1"
    port: int = 8770
    auth_enabled: bool = True
    token: str = ""
    admins: List[Dict[str, Any]] = Field(default_factory=list)
    users: List[Dict[str, Any]] = Field(default_factory=list)
    cors_origins: List[str] = Field(default_factory=list)
    tls_enabled: bool = False
    tls_cert: str = ""
    tls_key: str = ""
    static_cache: bool = False


class PingSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_PING_", extra="ignore")
    
    enabled: bool = True
    interval_sec: int = 10
    targets: List[str] = Field(default_factory=lambda: ["8.8.8.8", "1.1.1.1"])
    count: int = 3
    timeout_sec: int = 5


class MtrSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_MTR_", extra="ignore")
    
    enabled: bool = True
    interval_sec: int = 300
    targets: List[str] = Field(default_factory=list)
    max_hops: int = 14
    cycle_sec: int = 60


class SpeedtestSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_SPEEDTEST_", extra="ignore")
    
    enabled: bool = True
    interval_sec: int = 3600
    url_down: str = "https://speed.hetzner.de/{bytes}.bin"
    url_up: str = ""
    bytes_down: int = 8_000_000
    bytes_up: int = 2_000_000
    timeout_sec: int = 20


class DiagnosticsSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_DIAG_", extra="ignore")
    
    trace_targets: List[str] = Field(default_factory=list)
    resolve_hosts: List[str] = Field(default_factory=list)


class IdsSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_IDS_", extra="ignore")
    
    enabled: bool = True
    whitelist: List[Dict[str, str]] = Field(default_factory=list)
    suspicious_ports: List[int] = Field(default_factory=lambda: [4444, 5555, 6666, 31337])


class AiSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_AI_", extra="ignore")
    
    enabled: bool = True
    anomaly_threshold: float = 0.6
    forecast_hours: int = 24


class QuotaSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_QUOTA_", extra="ignore")
    
    enabled: bool = True
    daily_limit_mb: int = 10_000
    monthly_limit_mb: int = 100_000


class BackupSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_BACKUP_", extra="ignore")
    
    enabled: bool = False
    time: str = "03:00"
    dir: str = "C:\\Backups"
    keep: int = 7


class BackupWatchSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_BACKUPWATCH_", extra="ignore")
    
    enabled: bool = False
    interval_sec: int = 3600
    targets: List[str] = Field(default_factory=list)


class PlannerSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_PLANNER_", extra="ignore")
    
    enabled: bool = True


class InfraSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_INFRA_", extra="ignore")
    
    enabled: bool = True
    community: str = "public"
    scan_interval_sec: int = 3600


class CveSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_CVE_", extra="ignore")
    
    enabled: bool = False
    api_key: str = ""
    check_interval_sec: int = 86400


class ProxmoxSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_PROXMOX_", extra="ignore")
    
    enabled: bool = False
    host: str = ""
    user: str = ""
    token_name: str = ""
    token_value: str = ""
    verify_ssl: bool = False


class P2PSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_P2P_", extra="ignore")

    enabled: bool = False
    targets: List[str] = Field(default_factory=list)
    node_id: str = ""
    port: int = 9000
    # Совместимость с legacy v2
    target: str = ""
    target_node: str = ""
    host: str = "127.0.0.1"
    secret: str = ""
    call_timeout: int = 15
    reconnect_sec: int = 5

    @field_validator("targets", mode="before")
    @classmethod
    def _coerce_targets(cls, v):
        # Legacy: [{"node_id": "node0", "port": 9000}] → ["node0:9000"]
        if not isinstance(v, list):
            return v
        out = []
        for item in v:
            if isinstance(item, dict):
                host = item.get("host") or item.get("node_id") or "127.0.0.1"
                out.append(f"{host}:{item.get('port', 9000)}")
            else:
                out.append(str(item))
        return out


class SecuritySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_SEC_", extra="ignore")

    brute_force_max_fails: int = 5
    brute_force_block_sec: int = 600
    rate_limit_requests: int = 100
    rate_limit_window_sec: int = 60
    suspicious_ports: List[int] = Field(
        default_factory=lambda: [4444, 5555, 6666, 31337]
    )


class LoggingSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_LOG_", extra="ignore")
    
    level: str = "INFO"
    file: str = "logs/netpulse.log"
    max_bytes: int = 2_000_000
    backup_count: int = 5
    json_format: bool = True


class DatabaseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_DB_", extra="ignore")

    # Один файл с legacy DatabaseManager (core.database), чтобы v3 и legacy
    # видели одни и те же таблицы.
    path: str = "network_stats.db"
    wal_mode: bool = True


class TelegramSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_TG_", extra="ignore")
    
    enabled: bool = False
    token: str = ""
    chat_id: str = ""
    notify_on_alert: bool = True


class IPAllowlistSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NP_ALLOWLIST_", extra="ignore")
    
    enabled: bool = False
    networks: List[str] = Field(default_factory=list)


class Config(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        nested_model_default_partial_update=True,
    )
    
    web: WebSettings = Field(default_factory=WebSettings)
    ping: PingSettings = Field(default_factory=PingSettings)
    mtr: MtrSettings = Field(default_factory=MtrSettings)
    speedtest: SpeedtestSettings = Field(default_factory=SpeedtestSettings)
    diagnostics: DiagnosticsSettings = Field(default_factory=DiagnosticsSettings)
    ids: IdsSettings = Field(default_factory=IdsSettings)
    ai: AiSettings = Field(default_factory=AiSettings)
    quota: QuotaSettings = Field(default_factory=QuotaSettings)
    backup: BackupSettings = Field(default_factory=BackupSettings)
    backupwatch: BackupWatchSettings = Field(default_factory=BackupWatchSettings)
    planner: PlannerSettings = Field(default_factory=PlannerSettings)
    infra: InfraSettings = Field(default_factory=InfraSettings)
    cve: CveSettings = Field(default_factory=CveSettings)
    proxmox: ProxmoxSettings = Field(default_factory=ProxmoxSettings)
    p2p: P2PSettings = Field(default_factory=P2PSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    logging: LoggingSettings = Field(default_factory=LoggingSettings)
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    telegram: TelegramSettings = Field(default_factory=TelegramSettings)
    ip_allowlist: IPAllowlistSettings = Field(default_factory=IPAllowlistSettings)
    
    version: str = "3.0.0"
    # Сырой legacy-словарь из config.json (для to_legacy_dict fidelity).
    legacy_raw: Dict[str, Any] = Field(default_factory=dict, exclude=True)


DEFAULTS_DICT = {
    "web_host": "127.0.0.1",
    "web_port": 8770,
    "web_auth_enabled": True,
    "web_token": "",
    "web_admins": [],
    "web_users": [],
    "web_cors_origins": [],
    "web_tls_enabled": False,
    "web_tls_cert": "",
    "web_tls_key": "",
    "ping_enabled": True,
    "ping_interval_sec": 10,
    "ping_targets": ["8.8.8.8", "1.1.1.1"],
    "ping_count": 3,
    "ping_timeout_sec": 5,
    "mtr_enabled": True,
    "mtr_interval_sec": 300,
    "mtr_targets": [],
    "mtr_max_hops": 14,
    "mtr_cycle_sec": 60,
    "speedtest_enabled": True,
    "speedtest_interval_sec": 3600,
    "speedtest_url_down": "https://speed.hetzner.de/{bytes}.bin",
    "speedtest_url_up": "",
    "speedtest_bytes_down": 8_000_000,
    "speedtest_bytes_up": 2_000_000,
    "speedtest_timeout_sec": 20,
    "diagnostics_trace_targets": [],
    "diagnostics_resolve_hosts": [],
    "ids_enabled": True,
    "ids_whitelist": [],
    "ids_suspicious_ports": [4444, 5555, 6666, 31337],
    "ai_enabled": True,
    "ai_anomaly_threshold": 0.6,
    "ai_forecast_hours": 24,
    "quota_enabled": True,
    "quota_daily_limit_mb": 10_000,
    "quota_monthly_limit_mb": 100_000,
    "backup_enabled": False,
    "backup_time": "03:00",
    "backup_dir": "C:\\Backups",
    "backup_keep": 7,
    "backupwatch_enabled": False,
    "backupwatch_interval_sec": 3600,
    "backupwatch_targets": [],
    "planner_enabled": True,
    "infra_enabled": True,
    "infra_community": "public",
    "infra_scan_interval_sec": 3600,
    "cve_enabled": False,
    "cve_api_key": "",
    "cve_check_interval_sec": 86400,
    "proxmox_enabled": False,
    "proxmox_host": "",
    "proxmox_user": "",
    "proxmox_token_name": "",
    "proxmox_token_value": "",
    "proxmox_verify_ssl": False,
    "p2p_enabled": False,
    "p2p_targets": [],
    "p2p_node_id": "",
    "p2p_port": 9000,
    "security_brute_force_max_fails": 5,
    "security_brute_force_block_sec": 600,
    "security_rate_limit_requests": 100,
    "security_rate_limit_window_sec": 60,
    "logging_level": "INFO",
    "logging_file": "logs/netpulse.log",
    "logging_max_bytes": 2_000_000,
    "logging_backup_count": 5,
    "logging_json_format": True,
    "database_path": "netpulse.db",
    "database_wal_mode": True,
    "telegram_enabled": False,
    "telegram_token": "",
    "telegram_chat_id": "",
    "telegram_notify_on_alert": True,
    "ip_allowlist_enabled": False,
    "ip_allowlist_networks": [],
    "version": "3.0.0",
}

PROTECTED_SETTINGS = {"web_auth_enabled"}


def save_config(config: Dict[str, Any], path: str = "config.json") -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)


def load_config_dict(path: str = "config.json") -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in {path}: {e}")


def merge_configs(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    result = base.copy()
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = merge_configs(result[key], value)
        else:
            result[key] = value
    return result
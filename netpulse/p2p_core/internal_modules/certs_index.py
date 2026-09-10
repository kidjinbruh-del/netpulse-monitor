# src/internal_modules/certs_index.py — индекс сетевых сертификатов
# Хранит {thumbprint → метаданные} для сертификатов, обнаруженных в сети.
# Обновляется из CERT_SYNC рассылок и локального list_certificates.

import logging
import time
from dataclasses import dataclass, field

log = logging.getLogger('CertsIndex')

# TTL записи — если источник не обновлял > N секунд, помечаем stale
_STALE_TTL = 180  # 3 периода CERT_SYNC (по 60с)


@dataclass
class CertEntry:
    thumbprint: str
    subject_cn: str
    valid_to: str = ''
    available_on: list[str] = field(default_factory=list)
    installed_locally: bool = False
    last_updated: float = field(default_factory=time.monotonic)
    sync_version: int = 0

    @property
    def stale(self) -> bool:
        return (time.monotonic() - self.last_updated) > _STALE_TTL


class CertsIndex:
    """
    Индекс сертификатов, обнаруженных в mesh-сети.

    Ключ — thumbprint (уникальный идентификатор сертификата).
    Метаданные — subject_cn, valid_to, список узлов-источников, флаг локальной установки.
    PFX данные НЕ хранятся — запрашиваются по-demand при установке.
    """

    def __init__(self, own_node_id: str):
        self.own_node_id = own_node_id
        self._entries: dict[str, CertEntry] = {}
        self._sync_version: int = 0

    # ------------------------------------------------------------------ #
    #  Обновление из CERT_SYNC (от удалённого узла)
    # ------------------------------------------------------------------ #

    def merge_cert_sync(self, from_node: str, certs_digest: list[dict],
                        sync_version: int = 0):
        """
        Обновить индекс из CERT_SYNC рассылки.

        certs_digest: [{"thumbprint": str, "subject_cn": str, "valid_to": str}, ...]
        """
        now = time.monotonic()

        # Удалить этот узел из available_on для всех записей
        # (пересоздадим из свежего digest)
        for entry in self._entries.values():
            if from_node in entry.available_on:
                entry.available_on.remove(from_node)

        for d in certs_digest:
            tp = d.get('thumbprint', '')
            if not tp:
                continue

            entry = self._entries.get(tp)
            if entry is None:
                entry = CertEntry(
                    thumbprint=tp,
                    subject_cn=d.get('subject_cn', '?'),
                    valid_to=d.get('valid_to', ''),
                    last_updated=now,
                    sync_version=sync_version,
                )
                self._entries[tp] = entry
            else:
                if sync_version > entry.sync_version:
                    entry.subject_cn = d.get('subject_cn', entry.subject_cn)
                    entry.valid_to = d.get('valid_to', entry.valid_to)
                    entry.sync_version = sync_version
                entry.last_updated = now

            if from_node not in entry.available_on:
                entry.available_on.append(from_node)

        self._sync_version = max(self._sync_version, sync_version)
        log.debug(f'Merged CERT_SYNC from {from_node}: {len(certs_digest)} certs')

    # ------------------------------------------------------------------ #
    #  Обновление из локального list_certificates
    # ------------------------------------------------------------------ #

    def update_local(self, certs: dict):
        """
        Обновить флаг installed_locally и метаданные из локального списка.
        certs — результат certstool.list_certificates или get_dashboard_data.
        """
        now = time.monotonic()
        local_thumbprints = set()

        for cert_info in (certs if isinstance(certs, list) else certs.values()):
            if isinstance(cert_info, dict):
                tp = cert_info.get('Thumbprint', '') or cert_info.get('thumbprint', '')
                cn = cert_info.get('Subject_CN', '') or cert_info.get('subject_cn', '?')
                vt = cert_info.get('ValidTo', '') or cert_info.get('valid_to', '') or \
                     cert_info.get('Not valid after', '') or cert_info.get('Действителен до', '')
            else:
                continue

            if not tp:
                continue
            local_thumbprints.add(tp)

            entry = self._entries.get(tp)
            if entry is None:
                entry = CertEntry(
                    thumbprint=tp, subject_cn=cn, valid_to=vt,
                    installed_locally=True, last_updated=now,
                )
                self._entries[tp] = entry
            else:
                entry.installed_locally = True
                entry.last_updated = now

        # Снять флаг только для записей, у которых он был установлен
        for tp, entry in self._entries.items():
            if entry.installed_locally and tp not in local_thumbprints:
                entry.installed_locally = False

        # D3: локальное изменение индекса = новая версия — иначе push-обновления
        # метаданных на удалённых узлах блокировались merge по строгому '>'
        self._sync_version += 1

    # ------------------------------------------------------------------ #
    #  Запросы
    # ------------------------------------------------------------------ #

    def get_network_available(self) -> list[CertEntry]:
        """Сертификаты из сети, не установленные локально (не stale)."""
        return [e for e in self._entries.values()
                if not e.installed_locally and e.available_on and not e.stale]

    def get_by_thumbprint(self, thumbprint: str) -> CertEntry | None:
        return self._entries.get(thumbprint)

    def get_digest_for_sync(self) -> list[dict]:
        """Digest локальных сертификатов для CERT_SYNC рассылки."""
        return [
            {'thumbprint': e.thumbprint, 'subject_cn': e.subject_cn, 'valid_to': e.valid_to}
            for e in self._entries.values()
            if e.installed_locally
        ]

    @property
    def sync_version(self) -> int:
        return self._sync_version

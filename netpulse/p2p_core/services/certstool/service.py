# services/certs_tool/service.py — управление КриптоПро сертификатами
# Переработано из legacy/dist/services/certs_tool под текущую архитектуру:
#   BaseService → ModuleGeneric, @service_method → @rpc, proxy_client → ctx

import asyncio
import base64
import re
import secrets
import tempfile
from datetime import datetime
from pathlib import Path

from netpulse.p2p_core.internal_modules.base import ModuleGeneric
from netpulse.p2p_core.networking.protocol import MsgPack, PackType
from netpulse.p2p_core.services.rpc import rpc


class CertsTool(ModuleGeneric):
    """
    Сервис управления КриптоПро сертификатами (CSP).

    Обеспечивает:
    - Развертывание сертификатов из PFX/CER
    - Экспорт сертификатов в PFX/CER (base64)
    - Поиск и листинг установленных сертификатов
    - Пакетная установка со сменой пароля
    - CERT_SYNC: периодическая рассылка digest в mesh
    - Сетевая установка: экспорт с удалённого узла → импорт локально
    """

    _CARRIER = '\\\\.\\HDIMAGE'

    # Признаки отсутствия КриптоПро в выводе certmgr/csptest
    _CSP_MISSING_MARKERS = (
        'Не удалось получить контекст',
        'Тип поставщика не определен',
    )

    def __init__(self, name: str, context):
        super().__init__(name, context)
        self.csp_path = Path(__file__).parent
        self._cert_sync_task: asyncio.Task | None = None
        self._install_history: list[dict] = []
        self._terminated: bool = False

    async def start(self):
        self._validate_csp_path()
        self._cert_sync_task = asyncio.create_task(self._cert_sync_loop())
        self.log.info(f'CertsTool started (csp_path={self.csp_path})')

    async def stop(self):
        if self._cert_sync_task:
            self._cert_sync_task.cancel()
        self.log.info('CertsTool stopped')

    async def _terminate_no_csp(self):
        """КриптоПро отсутствует на ПК — завершить certstool
        (установка ГОСТ сертификатов не требуется)."""
        if self._terminated:
            return
        self._terminated = True
        self.log.error(
            'CryptoPro CSP not available (provider context error) — '
            'terminating certstool: GOST certificate management is not required'
        )
        if self._cert_sync_task and not self._cert_sync_task.done():
            self._cert_sync_task.cancel()
        try:
            self.ctx.services.remove_service(self)
        except Exception as e:
            self.log.warning(f'Failed to unregister certstool service: {e}')

    # ------------------------------------------------------------------ #
    #  CERT_SYNC — периодическая рассылка digest сертификатов
    # ------------------------------------------------------------------ #

    async def _cert_sync_loop(self):
        """Каждые 60с: обновить CertsIndex из локальных сертификатов,
        рассылать CERT_SYNC всем connected соседям."""
        while True:
            try:
                await asyncio.sleep(60)

                # 1. Обновить локальные сертификаты в индексе
                # (update_local инкрементирует certs_index.sync_version — D3)
                certs = await self.list_certificates({})
                self.ctx.certs_index.update_local(certs)

                # 2. Подготовить digest для рассылки
                digest = self.ctx.certs_index.get_digest_for_sync()
                sync_version = self.ctx.certs_index.sync_version

                # 3. Рассылать CERT_SYNC всем connected соседям
                pack = MsgPack(
                    type=PackType.CERT_SYNC,
                    source=self.ctx.NODE,
                    data={
                        'certs': digest,
                        'sync_version': sync_version,
                    },
                )
                transports = [
                    self.ctx.network.router.get_transport_to(n.node_id)
                    for n in self.ctx.network.neighbor_table.connected()
                    # get_transport_to умеет в server-side И client-side WS
                    # (B8: через nodes_manager.get() client-side соседи
                    # вообще не получали CERT_SYNC)
                ]
                await asyncio.gather(
                    *[t.send(pack) for t in transports if t],
                    return_exceptions=True,
                )

                self.log.debug(f'CERT_SYNC broadcast: {len(digest)} certs, v{sync_version}')

            except asyncio.CancelledError:
                return
            except Exception as e:
                self.log.error(f'CERT_SYNC loop error: {e}')
                await asyncio.sleep(10)

    # ------------------------------------------------------------------ #
    #  Внутренние утилиты
    # ------------------------------------------------------------------ #

    def _validate_csp_path(self):
        if not self.csp_path.exists():
            self.log.warning(f'CSP path not found: {self.csp_path}')
            return
        missing = [t for t in ('certmgr.exe', 'csptest.exe')
                    if not (self.csp_path / t).exists()]
        if missing:
            self.log.warning(f'Missing CSP tools: {missing}')

    async def _run_async(self, command: str) -> str:
        if self._terminated:
            return ''
        try:
            # chcp 1251 в том же shell-контексте, что и основная команда
            full_command = f'chcp 1251 && {command}'
            proc = await asyncio.create_subprocess_shell(
                full_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            try:
                out = stdout.decode('cp1251')
            except UnicodeDecodeError:
                out = stdout.decode('utf-8', errors='ignore')
            if stderr:
                try:
                    err_text = stderr.decode('cp1251')
                except UnicodeDecodeError:
                    err_text = stderr.decode('utf-8', errors='ignore')
                if err_text.strip():
                    if any(m in err_text for m in self._CSP_MISSING_MARKERS):
                        await self._terminate_no_csp()
                        return ''
                    self.log.warning(f'certmgr stderr: {err_text[:500]}')
                    out += '\n' + err_text
            if any(m in out for m in self._CSP_MISSING_MARKERS):
                await self._terminate_no_csp()
                return ''
            return out
        except Exception as e:
            self.log.error(f'Command error: {e}')
            return ''

    @staticmethod
    def _extract_error_code(output: str) -> str:
        for line in output.split('\n'):
            if 'ErrorCode' in line or 'КодОшибки' in line or '[0x' in line:
                parts = line.split(':')
                if len(parts) >= 2:
                    code = parts[-1].strip().replace(']', '').strip()
                    if code.startswith('0x'):
                        return code
        return ''

    @staticmethod
    def _extract_container(output: str) -> str:
        for line in output.split('\n'):
            if 'Container' in line or 'Контейнер' in line:
                parts = line.split(':', 1)
                if len(parts) >= 2:
                    c = parts[1].strip().replace('[', '').replace(']', '').replace('"', '').strip()
                    if c:
                        return c
        return ''

    # Русские → английские имена полей (certmgr с chcp 1251)
    _FIELD_NAME_MAP = {
        'Издатель': 'Issuer',
        'Субъект': 'Subject',
        'Серийный номер': 'Serial',
        'SHA1 отпечаток': 'SHA1 Thumbprint',
        'Идентификатор ключа': 'SubjectKeyID',
        'Алгоритм подписи': 'Signature Algorithm',
        'Алгоритм откр. кл.': 'PublicKey Algorithm',
        'Выдан': 'Not valid before',
        'Истекает': 'Not valid after',
        'Ссылка на ключ': 'PrivateKey Link',
        'Контейнер': 'Container',
        'Имя провайдера': 'Provider Name',
        'Инфо о провайдере': 'Provider Info',
        'Тип идентификации': 'Identification Kind',
        'URL сертификата УЦ': 'CA cert URL',
        'URL списка отзыва': 'CDP',
        'Встроенная лицензия': 'Embedded License',
        'Назначение/EKU': 'Extended Key Usage',
    }

    def _parse_certificate_list(self, output: str) -> dict:
        certificates = {}
        for index, cert_block in enumerate(output.split('-------')):
            if ' : ' not in cert_block or not cert_block.strip():
                continue
            cert_info: dict[str, str] = {}
            for line in cert_block.split('\n'):
                line = re.sub(r'  +', ' ', line.strip())
                if ' : ' in line:
                    key, value = line.split(' : ', 1)
                    key = key.strip()
                    # Нормализация русских имён полей → английские
                    key = self._FIELD_NAME_MAP.get(key, key)
                    cert_info[key] = value.strip()

            # --- CSP v5: Subject может отсутствовать (корневые CA) → взять Issuer ---
            if 'Subject' not in cert_info and 'Issuer' in cert_info:
                cert_info['Subject'] = cert_info['Issuer']

            if 'Subject' in cert_info:
                for part in cert_info['Subject'].split(', '):
                    if '=' in part:
                        k, v = part.split('=', 1)
                        cert_info[f'Subject_{k.strip()}'] = v.strip()

            if 'Issuer' in cert_info:
                for part in cert_info['Issuer'].split(', '):
                    if '=' in part:
                        k, v = part.split('=', 1)
                        cert_info[f'Issuer_{k.strip()}'] = v.strip()

            # --- Нормализация Thumbprint (CSP v5: SHA1 Thumbprint) ---
            for alt in ('SHA1 Thumbprint', 'SHA1 Hash', 'SHA1', 'Hash', 'Отпечаток'):
                if alt in cert_info and 'Thumbprint' not in cert_info:
                    cert_info['Thumbprint'] = cert_info[alt]
                    break

            # --- Нормализация дат (CSP v5: Not valid before/after) ---
            if 'ValidFrom' not in cert_info and 'Not valid before' in cert_info:
                cert_info['ValidFrom'] = cert_info['Not valid before']
            if 'ValidTo' not in cert_info and 'Not valid after' in cert_info:
                cert_info['ValidTo'] = cert_info['Not valid after']

            # --- Нормализация Container (убрать REGISTRY\\, FAT12\, HDIMAGE\\ префиксы) ---
            container = cert_info.get('Container', '')
            if container:
                for prefix in ('REGISTRY\\\\', 'HDIMAGE\\\\'):
                    if container.startswith(prefix):
                        cert_info['Container'] = container[len(prefix):]
                        cert_info['ContainerType'] = prefix.rstrip('\\')
                        break
                else:
                    for prefix in ('FAT12\\',):
                        if container.startswith(prefix):
                            cert_info['ContainerType'] = prefix.rstrip('\\')
                            break

            if cert_info:
                sub_cn = cert_info.get('Subject_CN', '-')
                certificates[f'{index}_{sub_cn}'] = cert_info
        return certificates

    # ------------------------------------------------------------------ #
    #  RPC методы
    # ------------------------------------------------------------------ #

    @rpc
    async def list_certificates(self, data: dict) -> dict:
        """Список установленных сертификатов."""
        cmd = f'"{self.csp_path / "certmgr.exe"}" -list'
        output = await self._run_async(cmd)
        if not output.strip():
            return {}
        return self._parse_certificate_list(output)

    @rpc
    async def find_certificate_by_subject(self, data: dict) -> dict:
        """Найти первый сертификат по паттерну в Subject."""
        pattern = data.get('subject_pattern', '')
        certs = await self.list_certificates({})
        for info in certs.values():
            if 'Subject' in info and pattern.lower() in info['Subject'].lower():
                return info
        return {}

    @rpc
    async def find_certificates_by_subject(self, data: dict) -> list:
        """Найти все сертификаты по паттерну в Subject."""
        pattern = data.get('subject_pattern', '')
        certs = await self.list_certificates({})
        return [info for info in certs.values()
                if 'Subject' in info and pattern.lower() in info['Subject'].lower()]

    @rpc
    async def deploy_certificate(self, data: dict) -> dict:
        """Развернуть сертификат из PFX + CER файлов."""
        pfx_path = data.get('pfx_path', '')
        cer_path = data.get('cer_path', '')
        pin = data.get('pin', '00000000')

        if not Path(pfx_path).exists():
            return {'success': False, 'error': f'PFX not found: {pfx_path}'}
        if not Path(cer_path).exists():
            return {'success': False, 'error': f'CER not found: {cer_path}'}

        result = {'success': False, 'pfx_error': '0x00000000',
                  'cer_error': '0x00000000', 'password_error': '0x00000000',
                  'container': ''}

        # 1. Install PFX
        auto_container = f'{self._CARRIER}\\p2p_{secrets.token_hex(4)}'
        cmd = (f'"{self.csp_path / "certmgr.exe"}" -install -store uMy '
               f'-file "{pfx_path}" -pfx -container "{auto_container}" '
               f'-silent -keep_exportable -pin {pin}')
        output = await self._run_async(cmd)
        result['pfx_error'] = self._extract_error_code(output)
        result['container'] = self._extract_container(output)
        if not result['container'] and result['pfx_error'] == '0x00000000':
            result['container'] = auto_container

        if result['pfx_error'] != '0x00000000':
            return result

        # 2. Install CER
        cmd = (f'"{self.csp_path / "certmgr.exe"}" -install -store uMy '
               f'-file "{cer_path}" -certificate -container "{result["container"]}" '
               f'-silent -inst_to_cont')
        output = await self._run_async(cmd)
        result['cer_error'] = self._extract_error_code(output)

        if result['cer_error'] != '0x00000000':
            return result

        # 3. Change password
        cmd = (f'"{self.csp_path / "csptest.exe"}" -passwd '
               f'-container "{result["container"]}" -change {pin}')
        output = await self._run_async(cmd)
        result['password_error'] = self._extract_error_code(output)

        result['success'] = all(
            result[k] == '0x00000000'
            for k in ('pfx_error', 'cer_error', 'password_error')
        )
        return result

    @rpc
    async def export_certificate_pfx(self, data: dict) -> dict:
        """Экспорт закрытого ключа в PFX (base64)."""
        container = data.get('container_name', '')
        thumbprint = data.get('thumbprint', '')
        password = data.get('password', '00000000')

        with tempfile.NamedTemporaryFile(suffix='.pfx', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            cmd = (f'"{self.csp_path / "certmgr.exe"}" -export '
                   f'-container "{container}" -dest "{tmp_path}" '
                   f'-pfx -keep_exportable -pin {password}')
            output = await self._run_async(cmd)
            error = self._extract_error_code(output)

            self.log.info(f'export_pfx: container={container}, error={error}')
            self.log.info(f'export_pfx certmgr output:\n{output}')

            if error != '0x00000000' or not Path(tmp_path).exists():
                return {'success': False, 'error': f'Export failed: {error}', 'pfx_base64': ''}

            pfx_size = Path(tmp_path).stat().st_size
            self.log.info(f'export_pfx: file size={pfx_size} bytes')

            with open(tmp_path, 'rb') as f:
                b64 = base64.b64encode(f.read()).decode('utf-8')

            return {'success': True, 'pfx_base64': b64, 'error': ''}
        except Exception as e:
            return {'success': False, 'error': str(e), 'pfx_base64': ''}
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    @rpc
    async def export_certificate_cer(self, data: dict) -> dict:
        """Экспорт открытого ключа в CER (base64)."""
        container = data.get('container_name', '')
        thumbprint = data.get('thumbprint', '')

        if not container and not thumbprint:
            return {'success': False, 'error': 'container_name or thumbprint required', 'cer_base64': ''}

        with tempfile.NamedTemporaryFile(suffix='.cer', delete=False) as tmp:
            tmp_path = tmp.name

        try:
            if container:
                cmd = (f'"{self.csp_path / "certmgr.exe"}" -export '
                       f'-container "{container}" -dest "{tmp_path}"')
            else:
                cmd = (f'"{self.csp_path / "certmgr.exe"}" -export '
                       f'-thumbprint "{thumbprint}" -dest "{tmp_path}"')

            output = await self._run_async(cmd)
            error = self._extract_error_code(output)

            if error != '0x00000000' or not Path(tmp_path).exists():
                return {'success': False, 'error': f'Export failed: {error}', 'cer_base64': ''}

            with open(tmp_path, 'rb') as f:
                b64 = base64.b64encode(f.read()).decode('utf-8')

            return {'success': True, 'cer_base64': b64, 'error': ''}
        except Exception as e:
            return {'success': False, 'error': str(e), 'cer_base64': ''}
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    @rpc
    async def export_certificate_by_subject(self, data: dict) -> dict:
        """Найти по Subject и экспортировать PFX + CER (base64)."""
        pattern = data.get('subject_pattern', '')
        password = data.get('password', '00000000')

        cert = await self.find_certificate_by_subject({'subject_pattern': pattern})
        if not cert:
            return {'pfx': {'success': False, 'error': 'Certificate not found', 'pfx_base64': ''},
                    'cer': {'success': False, 'error': 'Certificate not found', 'cer_base64': ''}}

        container = cert.get('Container', '')
        thumbprint = cert.get('Thumbprint', '')

        pfx_result = {'success': False, 'error': 'No container', 'pfx_base64': ''}
        if container:
            pfx_result = await self.export_certificate_pfx(
                {'container_name': container, 'password': password})

        cer_result = await self.export_certificate_cer(
            {'container_name': container, 'thumbprint': thumbprint})

        return {'pfx': pfx_result, 'cer': cer_result}

    @rpc
    async def delete_certificate(self, data: dict) -> dict:
        """Удалить сертификат по thumbprint."""
        thumbprint = data.get('thumbprint', '')
        if not thumbprint:
            return {'success': False, 'error': 'Thumbprint is required'}

        cmd = f'"{self.csp_path / "certmgr.exe"}" -delete -thumbprint "{thumbprint}"'
        output = await self._run_async(cmd)
        error = self._extract_error_code(output)

        if error == '0x00000000':
            return {'success': True}
        return {'success': False, 'error': f'Delete failed: {error}', 'error_code': error}

    @rpc
    async def install_pfx_from_base64(self, data: dict) -> dict:
        """Установка PFX из base64-данных."""
        pfx_b64 = data.get('pfx_base64', '')
        password = data.get('password', '00000000')
        filename = data.get('filename', 'cert.pfx')

        try:
            pfx_bytes = base64.b64decode(pfx_b64)
        except Exception as e:
            return {'success': False, 'error': f'Base64 decode error: {e}'}

        with tempfile.NamedTemporaryFile(suffix='.pfx', delete=False) as tmp:
            tmp.write(pfx_bytes)
            tmp_path = tmp.name

        try:
            # CSP v5: без явного контейнера certmgr может не привязать закрытый ключ.
            # Генерируем имя контейнера, если не задано.
            container_name = data.get('container_name', '')
            if not container_name:
                        container_name = f'{self._CARRIER}\\p2p_{secrets.token_hex(4)}'

            cmd = (f'"{self.csp_path / "certmgr.exe"}" -install -store uMy '
                   f'-file "{tmp_path}" -pfx -container "{container_name}" '
                   f'-silent -keep_exportable -pin {password}')
            output = await self._run_async(cmd)
            error = self._extract_error_code(output)
            container = self._extract_container(output)

            # Если certmgr не вернул контейнер — используем заданное имя
            if not container and error == '0x00000000':
                container = container_name

            self.log.info(f'install_pfx: error={error}, container={container}, output_len={len(output)}')
            self.log.info(f'install_pfx certmgr output:\n{output[:1000]}')

            if error == '0x00000000':
                return {'success': True, 'container': container}

            return {'success': False, 'error': f'Install failed: {error}', 'error_code': error}
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    @rpc
    async def batch_install_pfx_from_bytes(self, data: dict) -> dict:
        """Пакетная установка PFX из base64 со сменой пароля."""
        pfx_list: list[dict[str, str]] = data.get('pfx_list', [])
        current_pwd = data.get('current_password', '00000000')
        new_pwd = data.get('new_password') or current_pwd

        results = []
        ok = 0
        fail = 0

        for idx, item in enumerate(pfx_list):
            pfx_b64 = item.get('pfx_base64', '')
            fname = item.get('filename', f'cert_{idx}.pfx')

            try:
                pfx_bytes = base64.b64decode(pfx_b64)
            except Exception as e:
                results.append({'filename': fname, 'success': False, 'error': str(e)})
                fail += 1
                continue

            with tempfile.NamedTemporaryFile(suffix='.pfx', delete=False) as tmp:
                tmp.write(pfx_bytes)
                tmp_path = tmp.name

            try:
                auto_container = f'{self._CARRIER}\\p2p_{secrets.token_hex(4)}'

                cmd = (f'"{self.csp_path / "certmgr.exe"}" -install -store uMy '
                       f'-file "{tmp_path}" -pfx -container "{auto_container}" '
                       f'-silent -keep_exportable -pin {current_pwd}')
                output = await self._run_async(cmd)
                error = self._extract_error_code(output)
                container = self._extract_container(output)

                if not container and error == '0x00000000':
                    container = auto_container

                if error != '0x00000000':
                    results.append({'filename': fname, 'success': False,
                                    'error': f'Install failed', 'error_code': error})
                    fail += 1
                    continue

                if new_pwd != current_pwd and container:
                    pw_cmd = (f'"{self.csp_path / "csptest.exe"}" -passwd '
                              f'-container "{container}" -change {new_pwd}')
                    await self._run_async(pw_cmd)

                results.append({'filename': fname, 'success': True, 'container': container})
                ok += 1
            finally:
                Path(tmp_path).unlink(missing_ok=True)

        return {
            'success': ok > 0,
            'total': len(pfx_list),
            'success_count': ok,
            'fail_count': fail,
            'results': results,
        }

    @rpc
    async def get_dashboard_data(self, data: dict) -> dict:
        """Данные для веб-панели: список сертификатов с нормализацией полей."""
        try:
            certs = await self.list_certificates({})
            cert_list = []
            for cert_id, info in certs.items():
                valid_from = (info.get('ValidFrom') or info.get('Not valid before') or
                              info.get('Действителен с') or '')
                valid_to = (info.get('ValidTo') or info.get('Not valid after') or
                            info.get('Действителен до') or '')
                cert_list.append({
                    'id': cert_id,
                    'subject': info.get('Subject', 'Unknown'),
                    'subject_cn': info.get('Subject_CN', 'Unknown'),
                    'issuer': info.get('Issuer', 'Unknown'),
                    'issuer_cn': info.get('Issuer_CN', info.get('Issuer', 'Unknown')),
                    'thumbprint': info.get('Thumbprint', ''),
                    'container': info.get('Container', ''),
                    'serial': info.get('Serial', ''),
                    'valid_from': valid_from,
                    'valid_to': valid_to,
                    'raw': info,
                })
            return {
                'total_certificates': len(cert_list),
                'certificates': cert_list,
            }
        except Exception as e:
            self.log.error(f'Dashboard data error: {e}')
            return {'total_certificates': 0, 'certificates': [], 'error': str(e)}

    # ------------------------------------------------------------------ #
    #  Сетевая установка сертификатов (CERT_SYNC)
    # ------------------------------------------------------------------ #

    @rpc
    async def network_certs(self, data: dict) -> dict:
        """Сертификаты из сети, не установленные локально, сгруппированные по subject_cn.

        Возвращает:
          groups: {subject_cn: [entry_dict, ...]}
          total: общее число недостающих сертификатов
        Каждый entry_dict: {thumbprint, subject_cn, valid_to, available_on, sync_version}
        Сортировка: сначала самые свежие (valid_to), CONNECTED узлы приоритетнее.
        """
        available = self.ctx.certs_index.get_network_available()
        connected_ids = {n.node_id for n in self.ctx.network.neighbor_table.connected()}

        groups: dict[str, list[dict]] = {}
        for entry in available:
            entry_dict = {
                'thumbprint': entry.thumbprint,
                'subject_cn': entry.subject_cn,
                'valid_to': entry.valid_to,
                'available_on': entry.available_on,
                'sync_version': entry.sync_version,
            }
            cn = entry.subject_cn or '?'
            groups.setdefault(cn, []).append(entry_dict)

        # Сортировка внутри группы: приоритет по CONNECTED узлам, затем по valid_to
        for cn, entries in groups.items():
            def _sort_key(e):
                has_connected = any(n in connected_ids for n in e['available_on'])
                return (0 if has_connected else 1, e.get('valid_to', ''))
            entries.sort(key=_sort_key)

        return {
            'groups': groups,
            'total': len(available),
        }

    @rpc
    async def install_from_node(self, data: dict) -> dict:
        """Сетевая установка сертификата с удалённого узла.

        Процесс:
        1. RPC к удалённому узлу certstool.export_pfx_to_bytes — экспорт с одноразовым паролем
        2. Локальная установка PFX с этим паролем
        3. Смена пароля контейнера на пользовательский (или дефолтный)

        Параметры:
          thumbprint: str — идентификатор сертификата
          source_node: str — узел-источник (из available_on)
          new_password: str — новый пароль контейнера (default='00000000')

        Возвращает: {success, container, error, source_node, thumbprint}
        """
        thumbprint = data.get('thumbprint', '')
        source_node = data.get('source_node', '')
        new_password = data.get('new_password', '') or '00000000'

        if not thumbprint:
            return {'success': False, 'error': 'thumbprint is required'}
        if not source_node:
            return {'success': False, 'error': 'source_node is required'}

        # Проверить, что сертификат не установлен локально
        entry = self.ctx.certs_index.get_by_thumbprint(thumbprint)
        if entry and entry.installed_locally:
            return {'success': False, 'error': 'Certificate already installed locally'}

        # 1. Найти контейнер по thumbprint на удалённом узле
        try:
            cert_info = await self.ctx.network.call(
                dst=source_node,
                service='certstool',
                method='get_certificate_info',
                data={'thumbprint_lookup': thumbprint},
                timeout=10,
            )
        except Exception as e:
            return {'success': False, 'error': f'Remote lookup failed: {e}'}

        if not cert_info:
            return {'success': False, 'error': 'Certificate not found on source node'}

        container = cert_info.get('Container', '')
        if not container:
            return {'success': False, 'error': 'No container on source node'}

        # 2. Сгенерировать одноразовый пароль для PFX экспорта
        one_time_password = secrets.token_hex(8)

        # 3. Запросить PFX с удалённого узла
        try:
            export_result = await self.ctx.network.call(
                dst=source_node,
                service='certstool',
                method='export_certificate_pfx',
                data={'container_name': container, 'thumbprint': thumbprint, 'password': one_time_password},
                timeout=15,
            )
        except Exception as e:
            return {'success': False, 'error': f'Remote export failed: {e}'}

        if not export_result.get('success'):
            return {'success': False, 'error': f'Remote export error: {export_result.get("error", "?")}'}

        pfx_b64 = export_result.get('pfx_base64', '')
        if not pfx_b64:
            return {'success': False, 'error': 'Empty PFX data from source node'}

        # 4. Установить PFX локально с одноразовым паролем
        install_result = await self.install_pfx_from_base64({
            'pfx_base64': pfx_b64,
            'password': one_time_password,
            'filename': f'{thumbprint[:8]}.pfx',
        })

        if not install_result.get('success'):
            return {
                'success': False,
                'error': f'Local install failed: {install_result.get("error", "?")}',
                'source_node': source_node,
                'thumbprint': thumbprint,
            }

        local_container = install_result.get('container', '')

        # 5. Сменить пароль на пользовательский
        if new_password != one_time_password and local_container:
            pw_cmd = (f'"{self.csp_path / "csptest.exe"}" -passwd '
                      f'-container "{local_container}" -change {new_password}')
            await self._run_async(pw_cmd)

        # 6. Обновить CertsIndex и историю
        self.ctx.certs_index.update_local(await self.list_certificates({}))
        self._add_install_history(thumbprint, source_node)

        self.log.info(
            f'Network install OK: {thumbprint[:8]} from {source_node} → container {local_container}'
        )
        return {
            'success': True,
            'container': local_container,
            'source_node': source_node,
            'thumbprint': thumbprint,
            'error': '',
        }

    @rpc
    async def get_cert_sync_digest(self, data: dict) -> dict:
        """Digest локальных сертификатов для CERT_SYNC (по запросу).

        Используется при подключении нового узла для немедленного обмена.
        """
        digest = self.ctx.certs_index.get_digest_for_sync()
        return {
            'certs': digest,
            'sync_version': self.ctx.certs_index.sync_version,
        }

    @rpc
    async def get_install_history(self, data: dict) -> list:
        """История сетевой установки сертификатов."""
        return self._install_history

    @rpc
    async def get_certificate_info(self, data: dict) -> dict:
        """Детальная информация о сертификате по имени контейнера или thumbprint."""
        container = data.get('container_name', '')
        thumbprint_lookup = data.get('thumbprint_lookup', '')
        certs = await self.list_certificates({})
        for info in certs.values():
            if container and info.get('Container', '') == container:
                return info
            if thumbprint_lookup and info.get('Thumbprint', '').lower() == thumbprint_lookup.lower():
                return info
        return {}

    @rpc
    async def fix_certificate_link(self, data: dict) -> dict:
        """Починить связку сертификата с закрытым ключом.

        Проблема: при ручной установке PFX через КриптоПро, сертификат может
        не связаться с закрытым ключом. Этот метод экспортирует PFX и устанавливает
        его заново с явным указанием контейнера — это создаёт правильную связку.

        Параметры:
          thumbprint: str — идентификатор сертификата
          password: str — текущий пароль контейнера (default='00000000')

        Возвращает: {success, container, error}
        """
        thumbprint = data.get('thumbprint', '')
        password = data.get('password', '00000000')

        if not thumbprint:
            return {'success': False, 'error': 'Thumbprint is required'}

        # 1. Найти сертификат по thumbprint
        certs = await self.list_certificates({})
        cert_info = None
        for info in certs.values():
            if info.get('Thumbprint', '').lower() == thumbprint.lower():
                cert_info = info
                break

        if not cert_info:
            return {'success': False, 'error': 'Certificate not found'}

        container = cert_info.get('Container', '')
        if not container:
            return {'success': False, 'error': 'No container for this certificate'}

        self.log.info(f'Fixing link for {thumbprint[:8]}... (container={container})')

        # 2. Экспортировать PFX с текущим паролем
        export_result = await self.export_certificate_pfx({
            'container_name': container,
            'password': password,
        })

        if not export_result.get('success'):
            return {
                'success': False,
                'error': f'Export failed: {export_result.get("error", "?")}',
            }

        pfx_b64 = export_result.get('pfx_base64', '')
        if not pfx_b64:
            return {'success': False, 'error': 'Empty PFX data'}

        # 3. Удалить старый сертификат
        del_result = await self.delete_certificate({'thumbprint': thumbprint})
        if not del_result.get('success'):
            self.log.warning(f'Delete old cert failed: {del_result.get("error", "?")}')
            # Продолжить установку — может быть дубликат

        # 4. Установить PFX заново с явным контейнером — это создаст связку
        pfx_bytes = base64.b64decode(pfx_b64)

        with tempfile.NamedTemporaryFile(suffix='.pfx', delete=False) as tmp:
            tmp.write(pfx_bytes)
            tmp_path = tmp.name

        try:
            cmd = (f'"{self.csp_path / "certmgr.exe"}" -install -store uMy '
                   f'-file "{tmp_path}" -pfx -container "{container}" '
                   f'-silent -keep_exportable -pin {password}')
            output = await self._run_async(cmd)
            error = self._extract_error_code(output)
            result_container = self._extract_container(output)

            if not result_container:
                result_container = container

            self.log.info(f'Fix link: error={error}, container={result_container}')

            if error != '0x00000000':
                return {
                    'success': False,
                    'error': f'Install failed: {error}',
                    'error_code': error,
                }

            return {
                'success': True,
                'container': result_container,
                'thumbprint': thumbprint,
            }
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    # ------------------------------------------------------------------ #
    #  История установки
    # ------------------------------------------------------------------ #

    def _add_install_history(self, thumbprint: str, source_node: str):
        record = {
            'thumbprint': thumbprint,
            'source_node': source_node,
            'installed_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        }
        self._install_history.append(record)
        self.log.info(f'Install history: {thumbprint[:8]} from {source_node}')

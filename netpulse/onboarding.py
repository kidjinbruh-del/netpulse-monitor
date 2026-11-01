"""Admin-only device setup; stores references to credentials, never plaintext secrets."""
import copy
import os
import threading
from .config import save_config
from .routeros import validate_device, credentials, tls_context, collect, RouterError
from .mikrotik import configured_devices, normalize

LOCK = threading.RLock()
FIELDS = {'id', 'name', 'url', 'transport', 'username', 'password_env', 'ca_file',
          'timeout_sec', 'legacy_login', 'tables'}


def validate(body):
    if not isinstance(body, dict) or set(body) - FIELDS:
        raise ValueError('Неизвестные поля: пароль задаётся только через password_env')
    device = copy.deepcopy(body)
    try:
        validate_device(device)
    except RouterError as error:
        raise ValueError(str(error)) from None
    for field in ('name', 'ca_file'):
        if field in device and (not isinstance(device[field], str) or len(device[field]) > 512):
            raise ValueError('Некорректное поле ' + field)
    if not isinstance(device.get('legacy_login', False), bool):
        raise ValueError('legacy_login должен быть логическим значением')
    return device


def configuration(service):
    try:
        devices = configured_devices(service.cfg)
    except RouterError:
        return {'enabled': False, 'devices': [], 'error': 'Исправьте некорректную локальную конфигурацию MikroTik'}
    return {'enabled': bool((service.cfg.get('mikrotik') or {}).get('enabled')), 'devices': [
        {**{k:v for k,v in d.items() if k in FIELDS},
         'credential_available': bool(os.environ.get(d['password_env']))} for d in devices]}


def save_device(service, body):
    device = validate(body)
    with LOCK:
        candidate = copy.deepcopy(service.cfg)
        cfg = candidate.setdefault('mikrotik', {})
        devices = cfg.get('devices', [])
        devices = [d for d in devices if d['id'] != device['id']] + [device]
        cfg.update(enabled=True, devices=devices)
        try:
            configured_devices(candidate)
        except RouterError as error:
            raise ValueError(str(error)) from None
        if not save_config(candidate):
            raise RuntimeError('Не удалось сохранить конфигурацию; текущие настройки не изменены')
        service.cfg['mikrotik'] = candidate['mikrotik']
    return {'ok': True, 'id': device['id'], 'credential_available': bool(os.environ.get(device['password_env']))}


def probe(body):
    device = validate(body)
    try:
        credentials(device)
        tls_context(device)
        data = normalize(collect(device))
        return {'ok': True, 'data': data}
    except (RouterError, OSError, ValueError):
        return {'ok': False, 'error': 'Проверьте доступность службы, имя/CA сертификата, права и переменную пароля'}

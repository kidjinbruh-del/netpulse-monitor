"""Bounded, cached MikroTik polling; HTTP scrapes never contact routers."""
import copy
import math
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from .routeros import collect, validate_device, RouterError, TABLE_GROUPS


def number(value):
    try:
        result = float(value)
        return result if math.isfinite(result) and result >= 0 else None
    except (TypeError, ValueError):
        return None


def uptime_seconds(value):
    value = str(value or '')
    if re.fullmatch(r'(?:\d+[wdhms])+', value):
        return sum(int(n) * {'w':604800,'d':86400,'h':3600,'m':60,'s':1}[unit]
                   for n, unit in re.findall(r'(\d+)([wdhms])', value))
    match = re.fullmatch(r'(?:(\d+)w)?(?:(\d+)d)?(\d+):(\d{2}):(\d{2})', value)
    if match:
        w, d, h, m, s = (int(x or 0) for x in match.groups())
        if m < 60 and s < 60:
            return w*604800+d*86400+h*3600+m*60+s
    return None


def normalize(raw):
    resources = raw.get('system/resource') or []
    if not resources:
        raise RouterError('Router resource data is empty')
    resource = resources[0]
    identity = raw.get('system/identity') or [{}]
    interfaces = []
    names = set()
    for row in raw.get('interface', []):
        name = str(row.get('name', ''))[:128]
        if not name or name in names:
            continue
        names.add(name)
        interfaces.append({
            'name': name, 'type': str(row.get('type', ''))[:64],
            'running': str(row.get('running', '')).lower() in ('true','yes','1'),
            'disabled': str(row.get('disabled', '')).lower() in ('true','yes','1'),
            **{key.replace('-', '_'): number(row.get(key)) for key in
               ('rx-byte','tx-byte','rx-error','tx-error','rx-drop','tx-drop')},
        })
    return {
        'identity': str(identity[0].get('name', ''))[:128],
        'version': str(resource.get('version', ''))[:64],
        'board': str(resource.get('board-name', ''))[:64],
        'cpu_percent': number(resource.get('cpu-load')),
        'memory_free_bytes': number(resource.get('free-memory')),
        'memory_total_bytes': number(resource.get('total-memory')),
        'uptime_seconds': uptime_seconds(resource.get('uptime')),
        'interfaces': interfaces,
        'details': {group: [{str(k): str(v)[:256] for k,v in row.items()} for row in raw.get(path, [])[:256]] for group,path in TABLE_GROUPS.items() if path in raw},
        'table_errors': {group: error for group,path in TABLE_GROUPS.items() for p,error in (raw.get('_table_errors') or {}).items() if p == path},
    }


def configured_devices(config):
    cfg = config.get('mikrotik') or {}
    if not isinstance(cfg, dict):
        raise RouterError('mikrotik must be an object')
    devices = cfg.get('devices') or []
    if not isinstance(devices, list) or len(devices) > 16:
        raise RouterError('Configure at most 16 MikroTik devices')
    ids = set()
    for device in devices:
        validate_device(device)
        if device['id'] in ids:
            raise RouterError('MikroTik device ids must be unique')
        ids.add(device['id'])
    return devices


class MikroTikMonitor:
    def __init__(self, service):
        self.svc = service
        self._lock = threading.Lock()
        self._poll_lock = threading.Lock()
        self._status = {'enabled': False, 'devices': [], 'error': '', 'checked_at': None}

    def status(self):
        with self._lock:
            return copy.deepcopy(self._status)

    def _device(self, device):
        row = {'id': device['id'], 'name': str(device.get('name') or device['id'])[:128],
               'transport': device.get('transport','rest'), 'ok': False, 'data': None,
               'checked_at': time.time(), 'error': ''}
        started = time.monotonic()
        try:
            row['data'] = normalize(collect(device))
            row['ok'] = True
            row['last_success_at'] = time.time()
        except RouterError as error:
            row['error'] = str(error)
        except Exception:
            row['error'] = 'Router polling failed; check local configuration'
        row['duration_seconds'] = time.monotonic() - started
        row['checked_at'] = time.time()
        return row

    def poll(self):
        if not self._poll_lock.acquire(blocking=False):
            return self.status()
        try:
            cfg = self.svc.cfg.get('mikrotik') or {}
            if not isinstance(cfg, dict):
                cfg = {'enabled': True, 'devices': 'invalid'}
            state = {'enabled': bool(cfg.get('enabled')), 'devices': [], 'error': '', 'checked_at': time.time()}
            if state['enabled']:
                try:
                    devices = configured_devices(self.svc.cfg)
                    with ThreadPoolExecutor(max_workers=4, thread_name_prefix='np-router') as pool:
                        state['devices'] = list(pool.map(self._device, devices))
                    with self._lock:
                        old = {d['id']: d for d in self._status['devices']}
                    for row in state['devices']:
                        if not row['ok']:
                            row['last_success_at'] = old.get(row['id'], {}).get('last_success_at')
                except RouterError as error:
                    state['error'] = str(error)
            operations = getattr(self.svc, 'operations', None)
            if operations:
                for row in state['devices']:
                    try:
                        event = operations.observe_router(row)
                        if event:
                            self.svc.notify_external('ROUTER_' + event.upper(), row['name'] + (' — связь восстановлена' if event == 'resolved' else ' — нет связи после повторной проверки'))
                    except Exception:
                        state['persistence_error'] = 'Не удалось записать состояние инцидента'
            state['checked_at'] = time.time()
            with self._lock:
                self._status = state
            return self.status()
        finally:
            self._poll_lock.release()

    def loop(self):
        while not self.svc._stop_event.is_set():
            self.poll()
            try:
                interval = max(15, min(3600, int((self.svc.cfg.get('mikrotik') or {}).get('poll_interval_sec',30))))
            except (ValueError, TypeError, AttributeError):
                interval = 30
            self.svc._stop_event.wait(interval)

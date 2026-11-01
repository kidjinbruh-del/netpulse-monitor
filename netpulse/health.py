"""Read-only readiness checks; no network probes and no secrets in diagnostics."""
import os
import time
from . import __version__


def report(service):
    checks = []
    try:
        rows = service.db.execute('SELECT 1 AS ok', fetch=True)
        checks.append({'name': 'database', 'ok': bool(rows and rows[0]['ok'] == 1)})
    except Exception:
        checks.append({'name': 'database', 'ok': False})
    snapshot = service.get_snapshot()
    age = max(0, time.time() - float(snapshot.get('ts') or 0))
    checks.append({'name': 'snapshot', 'ok': age < 60, 'age_seconds': round(age, 1)})
    monitor = getattr(service, 'mikrotik', None)
    if monitor:
        state = monitor.status()
        if state['enabled']:
            interval = (service.cfg.get('mikrotik') or {}).get('poll_interval_sec', 30)
            try:
                interval = max(15, min(3600, int(interval)))
            except (ValueError, TypeError):
                interval = 30
            stale = time.time() - (state.get('checked_at') or 0) > interval*3+30
            checks.append({'name': 'mikrotik_collector', 'ok': not stale and not state.get('error') and not state.get('persistence_error')})
    checks.append({'name': 'authentication', 'ok': bool(service.cfg.get('web_auth_enabled')) or
                   service.cfg.get('web_host', '127.0.0.1') in ('127.0.0.1', '::1', 'localhost')})
    return {'version': __version__, 'status': 'ok' if all(c['ok'] for c in checks) else 'degraded',
            'checks': checks, 'pid': os.getpid(), 'timestamp': time.time()}

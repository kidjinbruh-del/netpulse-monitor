"""Isolated fixture. No equipment polling or external notification channels."""
import json
import os
import sys
import tempfile
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from core.database import DatabaseManager
from netpulse.config import load_config, merge_updates
from netpulse.inventory import Inventory
from netpulse.mikrotik import MikroTikMonitor
from netpulse.operations import Operations
from netpulse.notifications import Notifications
from netpulse.server import build_server, BackupManager
from tests.test_netpulse import MiniService

os.environ.setdefault('NP_METRICS_TOKEN', 'ci-metrics')
os.environ.setdefault('NP_ALERTMANAGER_TOKEN', 'ci-alertmanager')
with tempfile.TemporaryDirectory(prefix='netpulse-fixture-') as directory:
    os.chdir(directory)
    cfg = load_config()
    port = int(os.environ.get('NP_FIXTURE_PORT', '8796'))
    host = os.environ.get('NP_FIXTURE_HOST', '127.0.0.1')
    merge_updates(cfg, {'web_auth_enabled': True, 'web_token': 'ci-admin',
        'web_port': port, 'web_host': host, 'p2p': {'enabled': False},
        'ai': {'enabled': False},
        'web_users': [{'name': 'Viewer', 'token': 'ci-viewer', 'role': 'viewer'}],
        'mikrotik': {'enabled': True, 'devices': [{'id': 'lab',
            'name': 'Office (test fixture)', 'url': 'https://router.invalid',
            'username': 'readonly', 'password_env': 'NP_FIXTURE_ABSENT_PASSWORD'}]}})
    svc = MiniService()
    svc.cfg = cfg
    svc.db = DatabaseManager('fixture.db')
    svc.get_snapshot = lambda: {**svc.snapshot, 'ts': time.time()}
    svc.state_json_cached = lambda: json.dumps(svc.get_snapshot())
    svc.inventory = Inventory(svc)
    svc.inventory.upsert_host('Lab-PC', '192.0.2.2')
    svc.operations = Operations(svc)
    svc.notifications = Notifications(svc)
    svc.mikrotik = MikroTikMonitor(svc)
    svc.mikrotik._status = {'enabled': True, 'checked_at': time.time(), 'error': '',
        'devices': [{'id': 'lab', 'name': 'Office (test fixture)', 'transport': 'rest',
            'ok': True, 'checked_at': time.time(), 'last_success_at': time.time(),
            'error': '', 'duration_seconds': .01, 'data': {'version': '7.fixture',
                'cpu_percent': 12, 'memory_free_bytes': 512000,
                'memory_total_bytes': 1024000, 'uptime_seconds': 1000,
                'interfaces': [], 'details': {}}}]}
    svc.operations.open_incident('router:lab', 'Fixture connectivity check')
    server = build_server(svc, cfg, BackupManager(cfg), host=host, port=port)
    print('Fixture ready on ' + str(server.server_address[1]), flush=True)
    try:
        server.serve_forever(poll_interval=.1)
    finally:
        server.server_close()
        svc.notifications.stop()
        svc.db.close()

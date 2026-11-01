"""CI-only integration: real Prometheus, Grafana and Alertmanager containers."""
import base64
import json
import subprocess
import time
from pathlib import Path
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = ROOT / 'deploy' / 'observability'
COMMAND = ['docker', 'compose', '-p', 'netpulse-ci', '-f', str(DEPLOY / 'compose.yml')]


def request(url, data=None, headers=None):
    with urlopen(Request(url, data=data, headers=headers or {}), timeout=5) as response:
        body = response.read()
        return json.loads(body) if body else {}


def eventually(check, seconds=90):
    deadline = time.monotonic() + seconds
    last = None
    while time.monotonic() < deadline:
        try:
            value = check()
            if value:
                return value
        except Exception as error:
            last = type(error).__name__
        time.sleep(1)
    raise AssertionError('Integration check timed out: ' + str(last))


if __name__ == '__main__':
    secrets = DEPLOY / 'secrets'
    secrets.mkdir(exist_ok=True)
    for name, value in [('netpulse_metrics_token', 'ci-metrics'),
                        ('netpulse_alertmanager_token', 'ci-alertmanager'),
                        ('grafana_admin_password', 'ci-grafana')]:
        (secrets / (name + '.txt')).write_text(value, encoding='utf-8')
    try:
        subprocess.run(COMMAND + ['up', '-d'], check=True)
        eventually(lambda: request('http://127.0.0.1:3000/api/health').get('database') == 'ok')
        eventually(lambda: request('http://127.0.0.1:9090/api/v1/query?query=netpulse_up')['data']['result'])
        auth = base64.b64encode(b'admin:ci-grafana').decode()
        dashboard = request('http://127.0.0.1:3000/api/dashboards/uid/netpulse-mikrotik',
                            headers={'Authorization': 'Basic ' + auth})
        assert dashboard['dashboard']['panels']
        def alertmanager_ready():
            with urlopen('http://127.0.0.1:9093/-/ready', timeout=5) as response:
                return response.status == 200
        eventually(alertmanager_ready)
        request('http://127.0.0.1:9093/api/v2/alerts', json.dumps([{
            'labels': {'alertname': 'NetPulseSmoke', 'instance': 'fixture'},
            'annotations': {'summary': 'CI Alertmanager delivery'}}]).encode(),
            {'Content-Type': 'application/json'})
        eventually(lambda: any(i['title'] == 'CI Alertmanager delivery' for i in
            request('http://127.0.0.1:8770/api/operations',
                    headers={'X-Auth': 'ci-admin'})['incidents']))
        print('Prometheus scrape, Grafana dashboard and Alertmanager delivery: OK')
    finally:
        subprocess.run(COMMAND + ['logs', '--tail', '20'], check=False)
        subprocess.run(COMMAND + ['down'], check=False)

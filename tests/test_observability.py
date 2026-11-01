import json
from pathlib import Path
import yaml
from netpulse.doctor import check
from netpulse.mikrotik import MikroTikMonitor, configured_devices
from netpulse.routeros import RouterError
from types import SimpleNamespace
import pytest

ROOT = Path(__file__).resolve().parents[1] / 'deploy'

def test_provisioning_has_consistent_datasource_and_dashboard():
    base = ROOT / 'observability'
    compose = yaml.safe_load((base/'compose.yml').read_text(encoding='utf-8'))
    assert set(compose['services']) == {'prometheus', 'grafana', 'alertmanager'}
    for service in compose['services'].values():
        assert all(port.startswith('127.0.0.1:') for port in service['ports'])
    dashboard = json.loads((base/'grafana/dashboards/netpulse.json').read_text(encoding='utf-8'))
    assert dashboard['panels']
    datasource = yaml.safe_load((base/'grafana/provisioning/datasources/prometheus.yml').read_text(encoding='utf-8'))['datasources'][0]
    assert datasource['uid'] == 'netpulse-prometheus'
    for panel in dashboard['panels']:
        assert panel['datasource']['uid'] == datasource['uid']
    prometheus = yaml.safe_load((base/'prometheus/prometheus.yml').read_text(encoding='utf-8'))
    scrape = prometheus['scrape_configs'][0]
    assert scrape['authorization']['credentials_file'] == '/run/secrets/netpulse_metrics_token'
    assert not scrape.get('tls_config', {}).get('insecure_skip_verify')
    rules = yaml.safe_load((base/'prometheus/alerts.yml').read_text(encoding='utf-8'))['groups'][0]['rules']
    assert len(rules) == 5
    assert 'poll_interval_seconds' in next(rule['expr'] for rule in rules if rule['alert']=='MikroTikCollectorStale')

def test_zabbix_template_uses_verified_tls_and_no_embedded_token():
    template = yaml.safe_load((ROOT/'zabbix/netpulse-7.0.yaml').read_text(encoding='utf-8'))['zabbix_export']['templates'][0]
    master = next(item for item in template['items'] if item['type'] == 'HTTP_AGENT')
    assert master['verify_peer'] == 'YES' and master['verify_host'] == 'YES'
    assert master['headers'][0]['value'] == 'Bearer {$NETPULSE.TOKEN}'
    assert next(macro for macro in template['macros'] if macro['macro']=='{$NETPULSE.TOKEN}')['type'] == 'SECRET_TEXT'

def test_malformed_router_config_does_not_crash_collector():
    monitor = MikroTikMonitor(SimpleNamespace(cfg={'mikrotik': 'bad'}))
    status = monitor.poll()
    assert status['error']
    with pytest.raises(RouterError): configured_devices({'mikrotik': 'bad'})

def test_doctor_missing_router_environment_is_sanitized(tmp_path):
    path = tmp_path/'config.json'
    path.write_text(json.dumps({'mikrotik': {'enabled':True,'devices':[{'id':'office','url':'https://localhost','username':'monitor','password_env':'NP_ABSENT_TEST_PASSWORD'}]}}))
    checks = check(path)
    router = next(item for item in checks if item['name']=='mikrotik')
    assert not router['ok']
    assert 'office' not in router['detail']

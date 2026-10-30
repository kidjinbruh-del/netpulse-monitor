"""Read-only preflight checks; does not start monitoring or print credentials."""
import importlib.util
import json
import platform
import sys
from pathlib import Path

def check(config_path='config.json'):
    checks=[{'name':'python','ok':sys.version_info >= (3,12),'detail':platform.python_version()}]
    for module in ('psutil','numpy','pandas','sklearn','msgpack'):
        checks.append({'name':module,'ok':importlib.util.find_spec(module) is not None,'detail':'dependency'})
    path=Path(config_path)
    if not path.exists():
        checks.append({'name':'config','ok':True,'detail':'not created; defaults on first start'})
        return checks
    try:
        cfg=json.loads(path.read_text(encoding='utf-8-sig'))
        if not isinstance(cfg,dict):raise ValueError()
    except (ValueError,OSError):
        checks.append({'name':'config','ok':False,'detail':'unreadable or invalid JSON object'})
        return checks
    port=cfg.get('web_port',8770)
    checks.append({'name':'port','ok':isinstance(port,int) and not isinstance(port,bool) and 1<=port<=65535,'detail':'valid range: 1..65535'})
    host=cfg.get('web_host','127.0.0.1')
    protected=bool(cfg.get('web_auth_enabled')) or host in ('127.0.0.1','::1','localhost')
    checks.append({'name':'access','ok':protected,'detail':'loopback or authentication required'})
    tls=cfg.get('web_tls') or {}
    if tls.get('enabled'):
        checks.append({'name':'tls-files','ok':all(Path(tls.get(key) or '__missing__').is_file() for key in ('cert','key')),'detail':'configured certificate and key must exist'})
    return checks

def main(config_path='config.json'):
    checks=check(config_path)
    print(json.dumps({'ok':all(c['ok'] for c in checks),'checks':checks},ensure_ascii=False,indent=2))
    return 0 if all(c['ok'] for c in checks) else 1

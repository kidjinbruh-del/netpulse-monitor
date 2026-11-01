import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from types import SimpleNamespace
from pathlib import Path
import pytest
from core.database import DatabaseManager
from netpulse.operations import Operations
from netpulse.notifications import Notifications
from netpulse.mikrotik import MikroTikMonitor
from netpulse import onboarding
from netpulse.routeros import RouterError
from netpulse.health import report
from netpulse.metrics import render_metrics
from tests.test_hardening import server
from tests.test_netpulse import _get, _post

DEVICE={'id':'edge','name':'Office','url':'https://router.test','username':'readonly','password_env':'NP_OPS_TEST_PASSWORD'}

@pytest.fixture
def svc(tmp_path):
    db=DatabaseManager(str(tmp_path/'operations.db'))
    svc=SimpleNamespace(db=db,cfg={'mikrotik':{'enabled':True,'devices':[dict(DEVICE)]},'web_host':'127.0.0.1'},get_snapshot=lambda:{'ts':time.time()})
    svc.operations=Operations(svc);svc.notifications=Notifications(svc);svc.mikrotik=MikroTikMonitor(svc)
    svc.notify_external=svc.notifications.enqueue
    yield svc
    svc.notifications.stop();db.close()

def sample(ok):
    return {'id':'edge','name':'Office','ok':ok,'checked_at':time.time(),'data':None,'error':''}

def test_router_incident_threshold_dedup_restart_and_recovery(svc):
    assert svc.operations.observe_router(sample(False)) is None
    assert svc.operations.incidents()==[]
    assert svc.operations.observe_router(sample(False))=='opened'
    incident=svc.operations.incidents()[0]
    svc.operations.change_incident({'id':incident['id'],'action':'acknowledge'},'operator')
    svc.operations=Operations(svc)
    assert svc.operations.observe_router(sample(False)) is None
    assert len(svc.operations.incidents())==1
    assert svc.operations.observe_router(sample(True))=='resolved'
    result=svc.operations.incident(incident['id'])
    assert result['status']=='resolved'
    assert [e['action'] for e in result['timeline']]==['opened','acknowledge','resolve']
    assert svc.operations.observe_router(sample(False)) is None

def test_metadata_maintenance_and_expiry(svc):
    device=svc.operations.save_context({'id':'router:edge','site':'Офис','owner':'Admin','tags':['wan','wan'],'maintenance_until':time.time()+100})
    assert device['tags']==['wan']
    assert svc.operations.devices(query='офис',tag='wan')[0]['site']=='Офис'
    assert svc.operations.observe_router(sample(False)) is None
    assert svc.operations.observe_router(sample(False)) is None
    svc.operations.save_context({'id':'router:edge','maintenance_until':0})
    assert svc.operations.observe_router(sample(False))=='opened'
    with pytest.raises(ValueError):svc.operations.save_context({'id':'router:edge','maintenance_until':float('nan')})
    with pytest.raises(ValueError):svc.operations.save_context({'id':'router:missing'})

def test_concurrent_incidents_have_one_active_identity(svc):
    with ThreadPoolExecutor(max_workers=8) as pool:
        results=list(pool.map(lambda _:svc.operations.open_incident('router:edge','Failure',event_key='same'),range(20)))
    assert len(set(result[0] for result in results))==1
    assert sum(result[1] for result in results)==1
    assert svc.operations.incidents()[0]['occurrences']==20

def test_incident_validation_and_history(svc):
    ident,_=svc.operations.open_incident('','Manual')
    with pytest.raises(ValueError):svc.operations.change_incident({'id':ident,'action':'comment','message':''},'operator')
    result=svc.operations.change_incident({'id':ident,'action':'assign','owner':'Helpdesk'},'operator')
    assert result['owner']=='Helpdesk'
    result=svc.operations.change_incident({'id':ident,'action':'comment','message':'Проверяем'},'operator')
    assert result['timeline'][-1]['message']=='Проверяем'
    with pytest.raises(ValueError):svc.operations.incidents(status='sql injection')

def test_probe_missing_secret_and_plaintext_rejection(monkeypatch):
    monkeypatch.delenv('NP_OPS_TEST_PASSWORD',raising=False)
    assert not onboarding.probe(dict(DEVICE))['ok']
    with pytest.raises(ValueError):onboarding.validate({**DEVICE,'password':'must-not-be-stored'})
    with pytest.raises(ValueError):onboarding.validate({**DEVICE,'tables':['system/reboot']})
    with pytest.raises(ValueError):onboarding.validate({**DEVICE,'legacy_login':'yes'})

def test_setup_save_failure_does_not_change_running_config(svc,monkeypatch):
    monkeypatch.setattr(onboarding,'save_config',lambda _:False)
    with pytest.raises(RuntimeError):onboarding.save_device(svc,{**DEVICE,'name':'Changed'})
    assert svc.cfg['mikrotik']['devices'][0]['name']=='Office'

def test_setup_saves_reference_without_secret(svc,monkeypatch):
    captured={}
    monkeypatch.setenv('NP_OPS_TEST_PASSWORD','private-value')
    monkeypatch.setattr(onboarding,'save_config',lambda cfg:captured.update(cfg) or True)
    assert onboarding.save_device(svc,{**DEVICE,'name':'Changed','tables':['dhcp']})['credential_available']
    assert 'private-value' not in json.dumps(captured)
    assert svc.cfg['mikrotik']['devices'][0]['name']=='Changed'
    assert onboarding.configuration(svc)['devices'][0]['credential_available']

def test_health_is_read_only_and_detects_old_snapshot(svc):
    svc.get_snapshot=lambda:{'ts':time.time()-1000}
    result=report(svc)
    assert result['status']=='degraded'
    assert not next(c for c in result['checks'] if c['name']=='snapshot')['ok']

def test_maintenance_metrics_dont_scrape_router(svc,monkeypatch):
    svc.operations.save_context({'id':'router:edge','maintenance_until':time.time()+100})
    svc.mikrotik._status={'enabled':True,'devices':[sample(False)],'checked_at':time.time(),'error':''}
    monkeypatch.setattr('netpulse.mikrotik.collect',lambda _:pytest.fail('scrape contacted router'))
    metrics=render_metrics(svc)
    assert 'netpulse_mikrotik_maintenance{router="edge"} 1' in metrics

@contextmanager
def ops_server(tmp_path):
    with server({'web_auth_enabled':True,'web_token':'admin-test','p2p':{'enabled':False},'web_users':[{'name':'Observer','token':'viewer-test','role':'viewer'},{'name':'Operator','token':'operator-test','role':'operator'},{'name':'Bad','token':'bad-role','role':'unexpected'}]}) as (httpd,base):
        service=httpd.svc
        db=DatabaseManager(str(tmp_path/'http.db'));service.db=db
        service.operations=Operations(service);service.notifications=Notifications(service);service.mikrotik=MikroTikMonitor(service)
        try:yield service,base
        finally:service.notifications.stop();db.close()

def test_http_onboarding_roles_and_incident_workflow(tmp_path):
    with ops_server(tmp_path) as (service,base):
        assert _get(base+'/healthz')[0]==200
        assert _get(base+'/api/operations')[0]==401
        assert _get(base+'/api/operations',{'X-Auth':'viewer-test'})[0]==200
        assert _get(base+'/api/deviceconfig',{'X-Auth':'viewer-test'})[0]==403
        assert _post(base+'/api/devicesave',DEVICE,{'X-Auth':'operator-test'})[0]==403
        assert _post(base+'/api/devicesave',DEVICE,{'X-Auth':'admin-test'})[0]==200
        assert service.cfg['mikrotik']['devices'][0]['id']=='edge'
        assert _post(base+'/api/incidentcreate',{'title':'Test'}, {'X-Auth':'viewer-test'})[0]==403
        assert _post(base+'/api/incidentcreate',{'title':'Test'}, {'X-Auth':'bad-role'})[0]==403
        code,body=_post(base+'/api/incidentcreate',{'device_id':'router:edge','title':'Test'}, {'X-Auth':'operator-test'})
        assert code==200;ident=json.loads(body)['id']
        assert _post(base+'/api/incidentchange',{'id':ident,'action':'acknowledge'}, {'X-Auth':'operator-test'})[0]==200
        assert _post(base+'/api/notificationtest',{}, {'X-Auth':'operator-test'})[0]==403
        assert _get(base+'/api/incident?id=missing',{'X-Auth':'admin-test'})[0]==400
        assert _post(base+'/api/devicesave',{**DEVICE,'password':'private'}, {'X-Auth':'admin-test'})[0]==400
        settings=json.loads(_get(base+'/api/settings',{'X-Auth':'admin-test'})[1])
        assert 'private' not in json.dumps(settings)


def test_notification_delivery_retry_and_secret_sanitization(svc,monkeypatch):
    attempts=[]
    svc.cfg['webhook']={'enabled':True,'url':'https://example.test/secret-token'}
    def sender(*args):
        attempts.append(1)
        if len(attempts)<2:raise RuntimeError('secret-token')
    monkeypatch.setattr(Notifications,'_send',staticmethod(sender))
    monkeypatch.setattr(svc.notifications.stopped,'wait',lambda _:False)
    ids=svc.notifications.enqueue('Test','message')
    deadline=time.monotonic()+3
    while time.monotonic()<deadline:
        rows=svc.notifications.history()
        if rows and rows[0]['status']=='sent':break
        time.sleep(.01)
    assert rows[0]['status']=='sent' and rows[0]['attempts']==2
    assert 'secret-token' not in json.dumps(rows)
    assert len(ids)==1

def test_webhook_insecure_and_redirected_targets_rejected():
    with pytest.raises(ValueError):Notifications._send('webhook',{'url':'http://example.test'},'Test','message')
    from netpulse.notifications import NoRedirect
    with pytest.raises(ValueError):NoRedirect().redirect_request(None,None,None,None,None,None)

def test_config_replace_failure_preserves_original(tmp_path,monkeypatch):
    from netpulse import config
    path=tmp_path/'config.json';path.write_text('{"old":true}',encoding='utf-8')
    monkeypatch.setattr(config.os,'replace',lambda *_:(_ for _ in ()).throw(OSError('disk error')))
    assert not config.save_config({'new':True},str(path))
    assert json.loads(path.read_text())=={'old':True}
    assert not list(tmp_path.glob('.netpulse-config-*'))


def test_alertmanager_dedup_and_recovery(svc):
    payload={'alerts':[{'status':'firing','labels':{'alertname':'MikroTikHighCPU','router':'edge'},'annotations':{'summary':'High CPU'}}]}
    assert svc.operations.receive_alerts(payload)['opened']==1
    assert svc.operations.receive_alerts(payload)['opened']==0
    payload['alerts'][0]['status']='resolved'
    assert svc.operations.receive_alerts(payload)['resolved']==1
    assert svc.operations.receive_alerts(payload)['resolved']==0

def test_alertmanager_shares_router_incident_and_does_not_close_unhealthy_router(svc):
    svc.operations.observe_router(sample(False));svc.operations.observe_router(sample(False))
    payload={'alerts':[{'status':'firing','labels':{'alertname':'MikroTikUnreachable','router':'edge'}}]}
    assert svc.operations.receive_alerts(payload)['opened']==0
    payload['alerts'][0]['status']='resolved'
    assert svc.operations.receive_alerts(payload)['resolved']==0
    assert svc.operations.observe_router(sample(True))=='resolved'

def test_alertmanager_token_is_dedicated(tmp_path,monkeypatch):
    monkeypatch.setenv('NP_ALERTMANAGER_TOKEN','receiver-test')
    monkeypatch.setenv('NP_METRICS_TOKEN','metrics-test')
    with ops_server(tmp_path) as (_,base):
        payload={'alerts':[{'status':'firing','labels':{'alertname':'Example'}}]}
        assert _post(base+'/api/alertmanager',payload,{'Authorization':'Bearer metrics-test'})[0]==401
        assert _post(base+'/api/alertmanager',payload,{'Authorization':'Bearer receiver-test'})[0]==200
        assert _post(base+'/api/settings',{}, {'Authorization':'Bearer receiver-test'})[0]==401
        assert _get(base+'/api/settings',{'Authorization':'Bearer receiver-test'})[0]==401

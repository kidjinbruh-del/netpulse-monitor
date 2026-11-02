from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import Mock
import threading

import pytest
from netpulse.sysadmin import availability, ram_trend
from netpulse.proxmox import ProxmoxClient
from netpulse.server import Api


def event(t,kind): return {'timestamp':datetime.fromtimestamp(t,timezone.utc).isoformat(),'kind':kind}


def test_availability_zero_is_valid_and_missing_is_unknown():
    assert availability([],100,200)['sla_pct'] is None
    result=availability([event(50,'OFFLINE')],100,200)
    assert result['sla_pct']==0
    assert result['coverage_pct']==100
    result=availability([event(150,'ONLINE')],100,200)
    assert result['sla_pct'] is None
    assert result['observed_pct']==100
    assert result['unknown_seconds']==50


def test_availability_uses_durations_and_anchor_not_count():
    result=availability([event(95,'ONLINE'),event(120,'OFFLINE'),event(180,'ONLINE')],100,200)
    assert result['sla_pct']==40
    assert result['down_seconds']==60
    assert result['up_seconds']==40


def test_ram_uses_elapsed_time_and_bounded_horizon():
    result=ram_trend([(100,80),(160,85),(220,90)])
    assert result['slope_pct_pt']==5
    assert result['seconds_to_95']==60
    assert result['span_seconds']==120
    assert ram_trend([(0,10),(60,10.01),(120,10.02)])['seconds_to_95'] is None
    assert ram_trend([(0,10),(1,20),(2,30)])['ok'] is False
    assert ram_trend([(0,30),(60,20),(120,10)])['last_pct']==10


def test_proxmox_preserves_last_good_and_uses_correct_units(monkeypatch):
    svc=SimpleNamespace(cfg={'proxmox':{'enabled':True,'host':'pve.invalid','token_id':'test@pve!read','token_env':'NP_TEST_PVE'}},db=SimpleNamespace(execute=Mock()))
    monkeypatch.setenv('NP_TEST_PVE','fixture-secret')
    client=ProxmoxClient(svc)
    client._request=Mock(side_effect=[[{'node':'lab','status':'online','cpu':0,'mem':1073741824,'maxmem':2147483648,'uptime':0}],[]])
    client.poll()
    assert client.status()['nodes'][0]['cpu']==0
    assert client.status()['nodes'][0]['mem']==1
    assert client.status()['nodes'][0]['maxmem']==2
    client._request=Mock(side_effect=RuntimeError('token=fixture-secret'))
    result=client.poll()
    assert result['stale'] is True
    assert result['nodes'][0]['mem']==1
    assert 'fixture-secret' not in str(result)
    assert client.status()['verify_tls'] is True


def test_proxmox_origin_does_not_duplicate_port_and_uses_tls(monkeypatch):
    svc=SimpleNamespace(cfg={'proxmox':{'host':'https://pve.invalid:8006','token_id':'fixture','token_secret':'fixture-secret'}},db=SimpleNamespace(execute=Mock()))
    client=ProxmoxClient(svc)
    response=Mock();response.__enter__=Mock(return_value=response);response.__exit__=Mock();response.read.return_value=b'{"data":[]}'
    request=Mock(return_value=response)
    monkeypatch.setattr('netpulse.proxmox.urlopen',request)
    assert client._request('nodes')==[]
    args,kwargs=request.call_args
    assert args[0].full_url=='https://pve.invalid:8006/api2/json/nodes'
    assert kwargs['context'].check_hostname is True
    svc.cfg['proxmox']['host']='http://pve.invalid'
    with pytest.raises(ValueError):client._request('nodes')


def test_disabled_cve_cannot_query_nvd():
    api=Api.__new__(Api);api.cfg={'cve':{'enabled':False}}
    assert api.cve_scan({})[0]==503


def test_cve_job_reports_partial_and_releases_lock(monkeypatch):
    api=Api.__new__(Api);api.cfg={'cve':{'enabled':True}}
    checker=SimpleNamespace(_lock=threading.Lock(),last_error='Some products unavailable',check_products=Mock(return_value=[]))
    api.svc=SimpleNamespace(cve=checker,db=SimpleNamespace(execute=Mock(return_value=[{'name':'Fixture','version':'1'}])))
    results=[]
    def submit(fn):results.append(fn());return 'fixture-job'
    monkeypatch.setattr('netpulse.server.submit_job',submit)
    assert api.cve_scan({})=={'job':'fixture-job'}
    assert results[0]['complete'] is False
    assert results[0]['products']==1
    assert checker._lock.acquire(blocking=False)
    checker._lock.release()

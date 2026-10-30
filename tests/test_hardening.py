"""Regression coverage for HTTP boundaries, request isolation and resource lifecycle."""
import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
import os
import urllib.request
import urllib.error
import pytest
from core.database import DatabaseManager
from netpulse.server import Api, _ip_in_network, redact_audit, reset_auth_state
from tests.test_netpulse import _start_server, _get, _post

@contextmanager
def server(config=None):
    cwd = os.getcwd()
    httpd, port, cfg = _start_server(config)
    try:
        yield httpd, f'http://127.0.0.1:{port}'
    finally:
        httpd.shutdown()
        httpd.server_close()
        os.chdir(cwd)
        reset_auth_state()

@pytest.mark.parametrize('raw', [b'{', b'[]', b'null', b'"text"', b'\xff'])
def test_invalid_json_cannot_mutate(raw):
    with server() as (_, base):
        req = urllib.request.Request(base+'/api/journaladd', data=raw,
            headers={'Content-Type':'application/json'}, method='POST')
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(req, timeout=5)
        assert error.value.code == 400

@pytest.mark.parametrize('length,code', [('-1',400),('nonsense',400),('1048577',413)])
def test_body_length_is_bounded(length, code):
    with server() as (_, base):
        req = urllib.request.Request(base+'/api/journaladd', data=b'',
            headers={'Content-Type':'application/json','Content-Length':length}, method='POST')
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(req, timeout=5)
        assert error.value.code == code

def test_viewer_can_login_but_cannot_write():
    with server({'web_auth_enabled':True, 'web_users':[{'name':'Observer','token':'viewer-test','role':'viewer'}]}) as (_,base):
        code, body = _post(base+'/api/login', {'token':'viewer-test'})
        assert code == 200 and json.loads(body)['user'] == 'Observer'
        code, _ = _post(base+'/api/journaladd', {'text':'denied'}, {'X-Auth':'viewer-test'})
        assert code == 403

def test_servers_do_not_share_auth_context():
    with server({'web_auth_enabled':True,'web_token':'first'}) as (_,first):
        with server({'web_auth_enabled':True,'web_token':'second'}) as (_,second):
            assert _get(first+'/api/state', {'X-Auth':'first'})[0] == 200
            assert _get(first+'/api/state', {'X-Auth':'second'})[0] == 401
            assert _get(second+'/api/state', {'X-Auth':'second'})[0] == 200

def test_parallel_request_body_and_actor_are_isolated():
    api=Api(None, {}, None)
    barrier=threading.Barrier(8)
    def request(i):
        api._cached_body={'id':i};api._cached_actor=f'user-{i}';api._cached_role=str(i)
        barrier.wait(timeout=5)
        return api._cached_body['id'],api._cached_actor,api._cached_role
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert list(pool.map(request,range(8))) == [(i,f'user-{i}',str(i)) for i in range(8)]

def test_borrowed_sqlite_connection_closes_on_shutdown(tmp_path):
    db=DatabaseManager(str(tmp_path/'test.db'),pool_size=1)
    with db.connection() as conn:
        db.close()
    with pytest.raises(sqlite3.ProgrammingError): conn.execute('SELECT 1')
    assert db._pool.empty()

def test_pool_rejects_zero_size():
    with pytest.raises(ValueError): DatabaseManager(':memory:',pool_size=0)

def test_ipv6_allowlist_and_invalid_prefix():
    assert _ip_in_network('::1','::1/128')
    assert _ip_in_network('2001:db8::10','2001:db8::/32')
    assert not _ip_in_network('192.168.1.1','192.168.1.0/33')
    assert not _ip_in_network('999.1.1.1','0.0.0.0/0')

def test_nested_audit_secrets_redacted_before_truncation():
    value={'users':[{'password':'private','token':'credential'}], 'snmp':{'community':'private'},'text':'kept'}
    redacted=redact_audit(value)
    assert redacted['users'][0] == {'password':'***','token':'***'}
    assert redacted['snmp']['community']=='***' and redacted['text']=='kept'
    assert value['users'][0]['password']=='private'

def test_worker_backpressure_and_submission_failure(monkeypatch):
    from netpulse import server as mod
    monkeypatch.setattr(mod,'JOB_SLOTS',threading.BoundedSemaphore(1))
    assert mod.JOB_SLOTS.acquire(blocking=False)
    with pytest.raises(mod.JobCapacityError):mod.submit_job(lambda:None)
    mod.JOB_SLOTS.release()
    class FailedExecutor:
        def submit(self,fn):raise RuntimeError('stopped')
    monkeypatch.setattr(mod,'WORKERS',FailedExecutor())
    with pytest.raises(RuntimeError):mod.submit_job(lambda:None)
    assert mod.JOB_SLOTS.acquire(blocking=False)
    mod.JOB_SLOTS.release()

def test_doctor_does_not_create_config(tmp_path):
    from netpulse.doctor import check
    path=tmp_path/'missing.json'
    result=check(path)
    assert any(x['name']=='config' and x['ok'] for x in result)
    assert not path.exists()

def test_doctor_hides_secrets_and_rejects_unsafe_config(tmp_path):
    from netpulse.doctor import check
    path=tmp_path/'config.json'
    path.write_text(json.dumps({'web_port':70000,'web_host':'0.0.0.0','web_token':'do-not-output'}))
    result=check(path)
    assert 'do-not-output' not in str(result)
    assert not next(x for x in result if x['name']=='port')['ok']
    assert not next(x for x in result if x['name']=='access')['ok']

"""Local TLS RouterOS simulators: no real router or credentials required."""
import base64
import datetime
import hashlib
import io
import json
import socket
import socketserver
import ssl
import threading
import time
from types import SimpleNamespace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from prometheus_client.parser import text_string_to_metric_families
from netpulse.routeros import RestClient, ApiSSLClient, RouterError, encode_length, validate_device
from netpulse.mikrotik import MikroTikMonitor, normalize, uptime_seconds
from netpulse.metrics import render_metrics
from tests.test_hardening import server
from tests.test_netpulse import _get, _post

RAW={
 'system/resource':[{'uptime':'1w2d03:04:05','version':'7.20','board-name':'CHR','cpu-load':'12','free-memory':'512000','total-memory':'1024000'}],
 'system/identity':[{'name':'test-router'}],
 'interface':[{'name':'ether1','type':'ether','running':'true','disabled':'false','rx-byte':'123456789','tx-byte':'54321','rx-error':'0'}],
}

@pytest.fixture
def tls_files(tmp_path):
 key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
 name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'localhost')])
 now=datetime.datetime.now(datetime.timezone.utc)
 cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
       .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
       .not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),critical=False)
       .add_extension(x509.BasicConstraints(ca=True,path_length=None),critical=True).sign(key,hashes.SHA256()))
 cert_file=tmp_path/'router-ca.pem';key_file=tmp_path/'key.pem'
 cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
 key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
 ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cert_file,key_file)
 return ctx,str(cert_file)

@pytest.fixture
def router_device(monkeypatch):
 monkeypatch.setenv('NP_TEST_ROUTER_PASSWORD','test-only-password')
 return {'id':'edge','url':'https://localhost','username':'test-read','password_env':'NP_TEST_ROUTER_PASSWORD','timeout_sec':2}

@pytest.fixture
def rest_router(tls_files,router_device):
 context,ca=tls_files;calls=[]
 class Handler(BaseHTTPRequestHandler):
  def log_message(self,*args):pass
  def do_GET(self):self.reply()
  def do_POST(self):self.reply()
  def reply(self):
   calls.append((self.command,self.path,self.headers.get('Authorization')))
   assert self.headers['Authorization']=='Basic '+base64.b64encode(b'test-read:test-only-password').decode()
   path=self.path.split('?')[0].removeprefix('/rest/')
   if path=='interface/print':
    body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
    assert body['stats']=='' and 'rx-byte' in body['.proplist'];path='interface'
   if path not in RAW:self.send_error(404);return
   data=json.dumps(RAW[path]).encode();self.send_response(200);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
 srv=ThreadingHTTPServer(('127.0.0.1',0),Handler);srv.socket=context.wrap_socket(srv.socket,server_side=True)
 t=threading.Thread(target=srv.serve_forever,daemon=True);t.start()
 yield {**router_device,'url':f'https://localhost:{srv.server_port}','ca_file':ca},calls
 srv.shutdown();srv.server_close();t.join(timeout=3)

def test_rest_over_verified_tls_and_fixed_read_only_commands(rest_router):
 cfg,calls=rest_router
 from netpulse.routeros import collect
 data=normalize(collect(cfg))
 assert data['cpu_percent']==12 and data['interfaces'][0]['running']
 assert data['uptime_seconds']==788645
 assert [m for m,_,_ in calls]==['GET','GET','POST']
 assert all('password' not in path for _,path,_ in calls)
 with pytest.raises(RouterError):RestClient(cfg).read('system/reboot')

def test_rest_does_not_disable_certificate_verification(rest_router):
 cfg,_=rest_router;cfg={**cfg,'ca_file':None}
 with pytest.raises(RouterError,match='TLS'):RestClient(cfg).read('system/resource')

@pytest.mark.parametrize('legacy',[False,True])
def test_api_ssl_modern_and_legacy_login(tls_files,router_device,legacy):
 ctx,ca=tls_files;commands=[];errors=[]
 class Handler(socketserver.BaseRequestHandler):
  def handle(self):
   try:
    conn=ctx.wrap_socket(self.request,server_side=True)
    with conn:
     reader=ApiSSLClient(router_device);reader.sock=conn
     def read():
      words=[];reader.deadline=time.monotonic()+3
      while True:
       size=reader._length()
       if not size:return words
       words.append(reader._recv(size).decode())
     def send(words):
      conn.sendall(b''.join(encode_length(len(w.encode()))+w.encode() for w in words)+b'\0')
     login=read();commands.append(login[0]);assert login[0]=='/login'
     if legacy:
      assert login==['/login'];challenge='11'*16;send(['!done','=ret='+challenge]);login=read()
      expected='00'+hashlib.md5(b'\0test-only-password'+bytes.fromhex(challenge)).hexdigest()
      assert '=response='+expected in login
     else:assert '=password=test-only-password' in login
     send(['!done'])
     for _ in range(3):
      words=read();commands.append(words[0]);path=words[0][1:].removesuffix('/print')
      assert path in RAW
      if path=='interface':assert '=stats=' in words
      for row in RAW[path]:send(['!re']+['='+k+'='+v for k,v in row.items()])
      send(['!done'])
   except Exception as e:errors.append(e)
 srv=socketserver.ThreadingTCPServer(('127.0.0.1',0),Handler);srv.daemon_threads=True
 t=threading.Thread(target=srv.serve_forever,daemon=True);t.start()
 cfg={**router_device,'transport':'api_ssl','url':f'https://localhost:{srv.server_address[1]}','ca_file':ca,'legacy_login':legacy}
 try:
  from netpulse.routeros import collect
  assert normalize(collect(cfg))['version']=='7.20'
  assert not errors
  assert commands==['/login','/system/resource/print','/system/identity/print','/interface/print']
 finally:srv.shutdown();srv.server_close();t.join(timeout=3)

@pytest.mark.parametrize('length',[0,127,128,16383,16384,2097151,2097152])
def test_api_length_boundaries(length):
 class Socket:
  def __init__(self,data):self.data=io.BytesIO(data)
  def recv(self,n):return self.data.read(min(n,1))
  def settimeout(self,n):pass
 client=ApiSSLClient.__new__(ApiSSLClient);client.sock=Socket(encode_length(length));client.timeout=2;client.deadline=time.monotonic()+2
 assert client._length()==length

@pytest.mark.parametrize('url',['http://router','https://user:pass@router','https://router/rest','https://router:99999','https://router?password=secret'])
def test_device_configuration_rejects_unsafe_urls(router_device,url):
 with pytest.raises(RouterError):validate_device({**router_device,'url':url})

def test_monitor_cache_and_failures_do_not_become_zero_measurements(rest_router,monkeypatch):
 cfg,calls=rest_router;svc=SimpleNamespace(cfg={'mikrotik':{'enabled':True,'devices':[cfg]}},_stop_event=threading.Event())
 monitor=MikroTikMonitor(svc);svc.mikrotik=monitor
 good=monitor.poll();assert good['devices'][0]['ok'];assert len(calls)==3
 svc.get_snapshot=lambda:{'ts':100,'down_kbps':1,'up_kbps':2,'ping':{'current':None},'quality':{},'system':{}}
 text=render_metrics(svc,now=101);assert len(calls)==3
 families=list(text_string_to_metric_families(text));assert families
 assert 'netpulse_mikrotik_interface_receive_bytes_total{interface="ether1",router="edge"} 123456789' in text
 assert 'netpulse_ping_seconds' not in text
 monkeypatch.delenv('NP_TEST_ROUTER_PASSWORD')
 failed=monitor.poll();assert not failed['devices'][0]['ok']
 assert failed['devices'][0]['last_success_at']==good['devices'][0]['last_success_at']
 text=render_metrics(svc);assert 'netpulse_mikrotik_up{router="edge"} 0' in text
 assert 'netpulse_mikrotik_cpu_percent' not in text
 assert 'test-only-password' not in json.dumps(failed)

def test_metrics_token_is_scoped_and_settings_are_redacted(monkeypatch):
 monkeypatch.setenv('NP_TEST_METRICS_TOKEN','metrics-only')
 with server({'web_auth_enabled':True,'web_token':'admin-test','metrics':{'token_env':'NP_TEST_METRICS_TOKEN'},'telegram':{'token':'do-not-expose'}}) as (_,base):
  code,text=_get(base+'/metrics',{'Authorization':'Bearer metrics-only'});assert code==200 and text.endswith('\n')
  assert list(text_string_to_metric_families(text))
  assert _get(base+'/api/settings',{'Authorization':'Bearer metrics-only'})[0]==401
  code,text=_get(base+'/api/settings',{'X-Auth':'admin-test'});assert code==200
  assert 'admin-test' not in text and 'do-not-expose' not in text
  assert _post(base+'/api/settings',{'telegram':{'token':'***'}},{'X-Auth':'admin-test'})[0]==200

def test_uptime_variants():
 assert uptime_seconds('1d2h3m4s')==93784
 assert uptime_seconds('03:04:05')==11045
 assert uptime_seconds('invalid') is None

def test_prometheus_label_escaping_and_family_grouping():
 from netpulse.metrics import Exposition
 out=Exposition();out.add('first','one','gauge',1,router='a"\\\nb');out.add('second','two','gauge',2);out.add('first','one','gauge',3,router='c')
 text=out.text();assert text.index('router="c"')<text.index('# HELP second')
 families=list(text_string_to_metric_families(text));assert families[0].samples[0].labels['router']=='a"\\\nb'


def test_rotated_token_returned_once_and_redacted_secrets_survive_save():
 with server({'web_auth_enabled':True,'web_token':'old-admin','web_users':[{'name':'Observer','token':'viewer-test','role':'viewer'}],'webhook':{'url':'https://example.test/?token=private-test'}}) as (httpd,base):
  code,text=_get(base+'/api/settings',{'X-Auth':'old-admin'});assert code==200
  settings=json.loads(text);assert 'private-test' not in text and 'viewer-test' not in text
  assert _post(base+'/api/settings',settings,{'X-Auth':'old-admin'})[0]==200
  assert httpd.svc.cfg['web_users'][0]['token']=='viewer-test'
  assert httpd.svc.cfg['webhook']['url']=='https://example.test/?token=private-test'
  code,text=_post(base+'/api/settings',{'_regen_token':True},{'X-Auth':'old-admin'});assert code==200
  result=json.loads(text);new=result['new_token'];assert len(new)==32
  assert _get(base+'/api/settings',{'X-Auth':'old-admin'})[0]==401
  code,text=_get(base+'/api/settings',{'X-Auth':new});assert code==200 and new not in text


def test_optional_tables_do_not_break_core_poll(rest_router,monkeypatch):
 cfg,_=rest_router
 monkeypatch.setitem(RAW,'ip/arp',[{'address':'192.0.2.1','mac-address':'00:11:22:33:44:55','interface':'bridge'}])
 from netpulse.routeros import collect
 result=normalize(collect({**cfg,'tables':['arp','dhcp']}))
 assert result['cpu_percent']==12
 assert result['details']['arp'][0]['address']=='192.0.2.1'
 assert 'dhcp' in result['table_errors']

def test_api_trap_is_drained_before_next_command(router_device):
 def sentence(*words):return b''.join(encode_length(len(w.encode()))+w.encode() for w in words)+b'\0'
 data=sentence('!trap','=message=denied')+sentence('!done')+sentence('!re','=name=ether1')+sentence('!done')
 class Socket:
  def __init__(self):self.data=io.BytesIO(data)
  def recv(self,n):return self.data.read(n)
  def settimeout(self,n):pass
  def sendall(self,n):pass
 client=ApiSSLClient(router_device);client.sock=Socket()
 with pytest.raises(RouterError):client._exchange(['/unknown/print'])
 assert client._exchange(['/interface/print'])[0]==[{'name':'ether1'}]

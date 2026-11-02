import threading
from types import SimpleNamespace
from unittest.mock import Mock
from netpulse import runbooks


def runner(definition):
    r=runbooks.RunbookRunner.__new__(runbooks.RunbookRunner)
    r._lock=threading.Lock();r._defs={definition['id']:definition}
    r.svc=SimpleNamespace(cfg={'runbooks':{'enabled':True}},db=SimpleNamespace(execute=Mock()),push_alert=Mock())
    return r


def test_disk_builtin_is_structured_and_never_invokes_shell(monkeypatch):
    r=runner(runbooks.EXAMPLE_DISKS)
    monkeypatch.setattr(runbooks.psutil,'disk_partitions',lambda all=False:[SimpleNamespace(device='disk1',mountpoint='/fixture')])
    monkeypatch.setattr(runbooks.shutil,'disk_usage',lambda mount:SimpleNamespace(total=10*1073741824,used=6*1073741824,free=4*1073741824))
    shell=Mock();monkeypatch.setattr(runbooks.subprocess,'run',shell)
    result=r.execute('disk-space-local',actor='fixture-admin')
    assert result['ok']
    assert result['disks'][0]['free_gb']==4
    assert result['disks'][0]['used_pct']==60
    shell.assert_not_called()
    assert r.svc.db.execute.call_args.args[1][3]=='fixture-admin'


def test_remote_requires_host_and_rejects_shell_fragments(monkeypatch):
    r=runner(runbooks.EXAMPLE_SPOOLER)
    monkeypatch.setattr(runbooks.sys,'platform','win32')
    shell=Mock();monkeypatch.setattr(runbooks.subprocess,'run',shell)
    assert not r.execute('restart-spooler',{})['ok']
    assert not r.execute('restart-spooler',{'host':'PC; Stop-Service X'})['ok']
    shell.assert_not_called()


def test_remote_quotes_host_and_stops_on_powershell_errors(monkeypatch):
    r=runner(runbooks.EXAMPLE_SPOOLER)
    monkeypatch.setattr(runbooks.sys,'platform','win32')
    monkeypatch.setattr(runbooks.subprocess,'CREATE_NO_WINDOW',0,raising=False)
    shell=Mock(return_value=SimpleNamespace(returncode=1,stdout=b'',stderr=b'access denied'))
    monkeypatch.setattr(runbooks.subprocess,'run',shell)
    result=r.execute('restart-spooler',{'host':'OFFICE-PC'})
    command=shell.call_args.args[0][-1]
    assert "-ComputerName 'OFFICE-PC'" in command
    assert "$ErrorActionPreference='Stop'" in command
    assert result['ok'] is False
    assert result['target']=='OFFICE-PC'


def test_disabled_runbook_and_unsupported_os_do_not_execute(monkeypatch):
    r=runner(runbooks.EXAMPLE_SPOOLER)
    r.svc.cfg['runbooks']['enabled']=False
    assert not r.execute('restart-spooler',{'host':'PC'})['ok']
    r.svc.cfg['runbooks']['enabled']=True
    monkeypatch.setattr(runbooks.sys,'platform','linux')
    assert 'Windows' in r.execute('restart-spooler',{'host':'PC'})['error']

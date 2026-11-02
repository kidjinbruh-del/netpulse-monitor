import socket
from types import SimpleNamespace
import pytest
import psutil
from netpulse import lan_discovery as lan
from netpulse.services import LANNetworkScanner


def address(ip, mask):
    return SimpleNamespace(family=socket.AF_INET,address=ip,netmask=mask)


def test_physical_interface_preferred_over_vpn_and_mask_preserved(monkeypatch):
    monkeypatch.setattr(psutil,'net_if_addrs',lambda:{
        'happ-xray':[address('172.19.0.1','255.255.255.252')],
        'Ethernet':[address('192.168.0.185','255.255.255.0')],
        'Loopback':[address('127.0.0.1','255.0.0.0')]})
    monkeypatch.setattr(psutil,'net_if_stats',lambda:{
        'happ-xray':SimpleNamespace(isup=True,speed=10000),
        'Ethernet':SimpleNamespace(isup=True,speed=1000)})
    assert lan.select()['subnet']=='192.168.0.0/24'
    assert lan.select('happ-xray|172.19.0.1')['subnet']=='172.19.0.0/30'
    with pytest.raises(ValueError):lan.select('missing')


def test_arp_filters_other_subnets_multicast_and_broadcast():
    text='''192.168.0.1 02-11-22-33-44-55 dynamic
192.168.0.2 ff-ff-ff-ff-ff-ff static
192.168.0.3 01-00-5e-00-00-01 static
192.168.0.4 00-00-00-00-00-00 dynamic
192.168.0.255 02-11-22-33-44-55 static
172.19.0.2 02-66-77-88-99-aa dynamic'''
    assert lan.arp_entries(text,'192.168.0.0/24')=={'192.168.0.1':'02:11:22:33:44:55'}


def test_ping_requires_an_actual_echo_reply():
    assert lan.ping_reply(0,'Reply from 192.168.0.1: bytes=32 time<1ms TTL=64')
    assert lan.ping_reply(0,'64 bytes from host: icmp_seq=1 ttl=64 time=0.2 ms')
    assert not lan.ping_reply(0,'Reply from 192.168.0.1: Destination host unreachable.')
    assert not lan.ping_reply(1,'TTL=64')


def test_scan_merges_arp_without_claiming_online_and_resets_on_error(monkeypatch):
    selected={'id':'Ethernet|192.168.0.1','name':'Ethernet','ip':'192.168.0.1','subnet':'192.168.0.0/29','hosts':6}
    monkeypatch.setattr(lan,'select',lambda *_:selected)
    monkeypatch.setattr(psutil,'net_if_addrs',lambda:{'Ethernet':[SimpleNamespace(family=psutil.AF_LINK,address='02-11-22-33-44-55')]})
    monkeypatch.setattr('netpulse.services.subprocess.run',lambda *args,**kwargs:SimpleNamespace(returncode=1,stdout=b''))
    calls=[]
    scanner=LANNetworkScanner(SimpleNamespace(db=SimpleNamespace(execute=lambda *args,**kwargs:calls.append(args) or []),cfg={},push_alert=lambda *args:None))
    monkeypatch.setattr(scanner,'arp_table',lambda _: {'192.168.0.2':'02:66:77:88:99:aa'})
    result=scanner.scan()
    assert [(d['ip'],d['online'],d['source']) for d in result]==[
        ('192.168.0.1',True,'self'),('192.168.0.2',None,'arp')]
    assert not scanner.scanning
    monkeypatch.setattr(scanner,'arp_table',lambda _:(_ for _ in ()).throw(RuntimeError('failure')))
    with pytest.raises(RuntimeError):scanner.scan()
    assert not scanner.scanning
    assert scanner._scan_lock.acquire(blocking=False)
    scanner._scan_lock.release()


def test_oversized_network_rejected_before_probing(monkeypatch):
    monkeypatch.setattr(lan,'select',lambda *_:{'subnet':'10.0.0.0/8','hosts':16777214})
    scanner=LANNetworkScanner(SimpleNamespace(db=SimpleNamespace(execute=lambda *a,**k:[])))
    with pytest.raises(ValueError,match='1024'):scanner.scan()

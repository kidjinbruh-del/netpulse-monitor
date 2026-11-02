"""Run inside the disposable Linux network namespace created by linux_lab.sh."""
import argparse
import json
import os
import platform
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import Request, build_opener, ProxyHandler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from netpulse.lan_discovery import select
from netpulse import recovery


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--report', required=True)
    parser.add_argument('--arp-only', action='store_true')
    args = parser.parse_args()
    checks = []
    selected = select()
    assert selected['ip'] == '10.203.0.1' and selected['subnet'] == '10.203.0.0/29', selected
    checks.append('physical_interface_preferred_over_dummy_vpn')
    with tempfile.TemporaryDirectory(prefix='netpulse-linux-lab-') as directory:
        directory = Path(directory)
        cfg = {'web_host':'127.0.0.1','web_port':8871,'web_auth_enabled':True,
               'web_token':'linux-lab-only','p2p':{'enabled':False},
               'ai':{'enabled':False},'lan':{'auto_scan_min':0}}
        (directory/'config.json').write_text(json.dumps(cfg))
        environment = {**os.environ, 'PYTHONPATH':str(ROOT), 'PYTHONUNBUFFERED':'1', 'NETPULSE_NO_BROWSER':'1'}
        with (directory/'server.log').open('wb') as output:
            process = subprocess.Popen([sys.executable,'-m','netpulse'],cwd=directory,
                                       env=environment,stdout=output,stderr=subprocess.STDOUT)
            opener = build_opener(ProxyHandler({}))
            def request(path, data=None):
                body = json.dumps(data).encode() if data is not None else None
                headers = {'X-Auth':'linux-lab-only','Content-Type':'application/json'}
                with opener.open(Request('http://127.0.0.1:8871'+path,data=body,headers=headers),timeout=5) as response:
                    return json.load(response)
            try:
                deadline = time.monotonic()+40
                while time.monotonic()<deadline:
                    try:
                        assert request('/readyz')['status']=='ok'
                        break
                    except Exception:
                        if process.poll() is not None:
                            raise AssertionError('Server exited before readiness')
                        time.sleep(.2)
                else:
                    raise AssertionError('Linux server did not become ready')
                checks.append('real_server_startup_and_readiness')
                metadata = request('/api/landevices')
                assert metadata['subnet']=='10.203.0.0/29'
                job = request('/api/lanscanjob',{'interface':metadata['selected_interface']})
                deadline = time.monotonic()+30
                while time.monotonic()<deadline:
                    state=request('/api/securityresult?job='+job['job'])
                    if state['status']!='running':break
                    time.sleep(.2)
                assert state['status']=='done',state
                devices={row['ip']:row for row in state['result']}
                assert devices['10.203.0.1']['is_me']
                peer=devices['10.203.0.2']
                assert peer['mac']=='02:00:00:00:00:02',peer
                if args.arp_only:
                    assert peer['source']=='arp' and peer['online'] is None,peer
                    checks.append('icmp_blocked_peer_found_by_linux_neighbor_table_without_false_online')
                else:
                    assert peer['source']=='icmp' and peer['online'] is True,peer
                    checks.append('real_source_bound_ping_and_mac_discovery')
                assert '172.19.0.2' not in devices
                history=request('/api/landevices')['devices']
                assert any(row['ip']=='10.203.0.2' for row in history)
                checks.append('device_persisted_to_sqlite')
                bundle=recovery.create(directory,directory/'copies')
                restored=directory/'restored'
                recovery.restore(bundle['archive'],restored)
                assert (restored/'network_stats.db').is_file()
                checks.append('live_database_backup_and_restore_on_linux')
            finally:
                process.send_signal(signal.SIGINT)
                try:process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill();process.wait(timeout=5)
                log=(directory/'server.log').read_text(errors='replace')
                if 'Traceback (most recent call last)' in log:
                    print(log[-6000:])
    report={'platform':platform.platform(),'python':platform.python_version(),
            'arp_only':args.arp_only,'checks':checks,'ok':True,
            'scope':'isolated Linux namespace; no physical LAN or MikroTik'}
    Path(args.report).write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()

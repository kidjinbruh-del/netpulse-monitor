"""Prometheus 0.0.4 exposition, bounded labels and explicit units."""
import time
from .mikrotik import number


def label(value):
    return str(value).replace('\\', '\\\\').replace('\n', '\\n').replace('"', '\\"')


class Exposition:
    def __init__(self):
        self.families = {}

    def add(self, name, help_text, kind, value, **labels):
        value = number(value)
        if value is None:
            return
        if name not in self.families:
            self.families[name] = [f'# HELP {name} {help_text}', f'# TYPE {name} {kind}']
        suffix = '{' + ','.join(f'{key}="{label(value)}"' for key, value in sorted(labels.items())) + '}' if labels else ''
        self.families[name].append(f'{name}{suffix} {value:.17g}')

    def text(self):
        return '\n'.join(line for family in self.families.values() for line in family) + '\n'


def render_metrics(service, now=None):
    now = time.time() if now is None else now
    snap = service.get_snapshot()
    out = Exposition()
    out.add('netpulse_up','NetPulse exporter available','gauge',1)
    out.add('netpulse_snapshot_timestamp_seconds','Latest monitor snapshot timestamp','gauge',snap.get('ts'))
    for key, old, name in [('down_kbps','np_down_speed','receive'),('up_kbps','np_up_speed','transmit')]:
        value = number(snap.get(key))
        out.add(old,'Current traffic speed KiB/s','gauge',value)
        out.add(f'netpulse_network_{name}_bytes_per_second','Current traffic speed bytes/s','gauge',value*1024 if value is not None else None)
    ping = snap.get('ping') or {}
    out.add('np_ping_ms','Current ping milliseconds','gauge',ping.get('current'))
    out.add('netpulse_ping_seconds','Current ping seconds','gauge',number(ping.get('current'))/1000 if number(ping.get('current')) is not None else None)
    out.add('np_quality_score','Network quality score 0-100','gauge',(snap.get('quality') or {}).get('score'))
    out.add('np_alerts_unread','Unacknowledged alerts','gauge',snap.get('alerts_unread'))
    for key, name in [('total_down_mb','down'),('total_up_mb','up')]:
        out.add(f'np_traffic_total_{name}_mb','Session traffic MiB','counter',snap.get(key))
    for key in ('cpu','mem_pct'):
        out.add('netpulse_system_'+key+'_percent','Host resource utilization percent','gauge',(snap.get('system') or {}).get(key))
    try:
        hosts = service.inventory.list_hosts()[:1024]
        out.add('np_hosts_total','Known machines (export capped at 1024)','gauge',len(hosts))
        for host in hosts:
            out.add('np_host_karma','Machine health score','gauge',host.get('health_score',100),host=str(host.get('name') or '?')[:128])
    except AttributeError:
        pass
    try:
        rows = service.db.execute("SELECT COUNT(*) AS n FROM journal WHERE timestamp > datetime('now','localtime','-1 day')", fetch=True)
        out.add('np_journal_entries_24h','Journal entries in last 24 hours','gauge',rows[0]['n'] if rows else 0)
    except (AttributeError, IndexError, KeyError):
        pass
    monitor = getattr(service,'mikrotik',None)
    state = monitor.status() if monitor else {'enabled':False,'devices':[]}
    out.add('netpulse_mikrotik_enabled','MikroTik collector enabled','gauge',int(state['enabled']))
    operations = getattr(service, 'operations', None)
    contexts = operations.contexts() if operations else {}
    if operations:
        for status, count in operations.summary().items():
            if status != 'scope':
                out.add('netpulse_incidents', 'Incidents among latest 500', 'gauge', count, status=status)
    for device in state['devices'][:16]:
        labels = {'router':device['id']}
        out.add('netpulse_mikrotik_maintenance', 'Router maintenance window active', 'gauge', int(contexts.get('router:'+device['id'], {}).get('maintenance_until', 0) > now), **labels)
        try:
            interval = max(15, min(3600, int((service.cfg.get('mikrotik') or {}).get('poll_interval_sec', 30))))
        except (ValueError, TypeError, AttributeError):
            interval = 30
        out.add('netpulse_mikrotik_poll_interval_seconds','Configured router poll interval','gauge',interval,**labels)
        out.add('netpulse_mikrotik_up','Last router poll succeeded','gauge',int(device['ok']),**labels)
        out.add('netpulse_mikrotik_last_poll_timestamp_seconds','Last completed router poll','gauge',device.get('checked_at'),**labels)
        out.add('netpulse_mikrotik_last_success_timestamp_seconds','Last successful router poll','gauge',device.get('last_success_at'),**labels)
        out.add('netpulse_mikrotik_poll_duration_seconds','Duration of last poll','gauge',device.get('duration_seconds'),**labels)
        if not device['ok']:
            continue
        data = device['data'] or {}
        for key in ('cpu_percent','memory_free_bytes','memory_total_bytes','uptime_seconds'):
            out.add('netpulse_mikrotik_'+key,'Router '+key.replace('_',' '),'gauge',data.get(key),**labels)
        for iface in data.get('interfaces',[])[:256]:
            fields = {**labels,'interface':iface['name']}
            for key in ('running','disabled'):
                out.add('netpulse_mikrotik_interface_'+key,'Interface '+key,'gauge',int(iface[key]),**fields)
            for source, target in [('rx_byte','receive_bytes'),('tx_byte','transmit_bytes'),('rx_error','receive_errors'),('tx_error','transmit_errors'),('rx_drop','receive_drops'),('tx_drop','transmit_drops')]:
                out.add('netpulse_mikrotik_interface_'+target+'_total','Cumulative interface '+target.replace('_',' '),'counter',iface.get(source),**fields)
    return out.text()

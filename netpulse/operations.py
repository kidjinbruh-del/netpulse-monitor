"""Persistent device context and incidents. All mutations use SQLite transactions."""
import json
import hashlib
import math
import re
import time
import uuid


def text(value, limit=160):
    if not isinstance(value, str) or len(value) > limit:
        raise ValueError(f'Ожидается текст не длиннее {limit} символов')
    return value.strip()


class Operations:
    def __init__(self, service):
        self.svc = service
        with self.svc.db.connection() as con:
            con.executescript('''
                CREATE TABLE IF NOT EXISTS device_context (
                    device_id TEXT PRIMARY KEY, site TEXT NOT NULL DEFAULT '',
                    owner TEXT NOT NULL DEFAULT '', tags TEXT NOT NULL DEFAULT '[]',
                    maintenance_until REAL NOT NULL DEFAULT 0, updated REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS incidents (
                    id TEXT PRIMARY KEY, event_key TEXT NOT NULL, device_id TEXT NOT NULL,
                    title TEXT NOT NULL, severity TEXT NOT NULL, status TEXT NOT NULL,
                    owner TEXT NOT NULL DEFAULT '', opened REAL NOT NULL, updated REAL NOT NULL,
                    acknowledged REAL, resolved REAL, occurrences INTEGER NOT NULL DEFAULT 1);
                CREATE UNIQUE INDEX IF NOT EXISTS active_incident_key ON incidents(event_key)
                    WHERE status IN ('open','acknowledged');
                CREATE INDEX IF NOT EXISTS incidents_updated ON incidents(updated);
                CREATE TABLE IF NOT EXISTS incident_timeline (
                    id INTEGER PRIMARY KEY, incident_id TEXT NOT NULL, ts REAL NOT NULL,
                    actor TEXT NOT NULL, action TEXT NOT NULL, message TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS router_health (
                    device_id TEXT PRIMARY KEY, failures INTEGER NOT NULL,
                    last_success REAL, last_check REAL NOT NULL);
            ''')
            con.commit()

    def contexts(self):
        with self.svc.db.connection() as con:
            return {r['device_id']: dict(r) for r in con.execute('SELECT * FROM device_context')}

    def devices(self, query='', site='', tag=''):
        contexts = self.contexts()
        result = []
        monitor = getattr(self.svc, 'mikrotik', None)
        state = monitor.status() if monitor else {'devices': []}
        status = {r['id']: r for r in state['devices']}
        cfg = self.svc.cfg.get('mikrotik') or {}
        from .mikrotik import configured_devices
        from .routeros import RouterError
        try:
            configured = configured_devices(self.svc.cfg)
        except RouterError:
            configured = []
        for device in configured:
            row = status.get(device['id'], {})
            result.append({'id': 'router:' + device['id'], 'name': device.get('name') or device['id'],
                           'kind': 'router', 'online': row.get('ok'), 'checked_at': row.get('checked_at'),
                           'address': device['url'], 'data': row.get('data'), 'error': row.get('error', '')})
        inventory = getattr(self.svc, 'inventory', None)
        if inventory:
            for host in inventory.list_hosts()[:2000]:
                result.append({'id': 'host:' + str(host['id']), 'name': host['name'], 'kind': 'host',
                               'online': bool(host.get('online')), 'address': host.get('ip', ''),
                               'health_score': host.get('health_score'), 'checked_at': host.get('last_seen')})
        for row in result:
            context = contexts.get(row['id'], {})
            row.update({k: context.get(k, '') for k in ('site', 'owner')})
            row['tags'] = json.loads(context.get('tags', '[]'))
            row['maintenance_until'] = context.get('maintenance_until', 0)
            row['maintenance'] = row['maintenance_until'] > time.time()
        query = query.lower().strip()[:160]
        return [r for r in result if (not query or query in ' '.join(str(r.get(k, '')) for k in
                    ('id', 'name', 'address', 'site', 'owner')).lower())
                and (not site or r['site'] == site) and (not tag or tag in r['tags'])]

    def device(self, ident):
        found = next((d for d in self.devices() if d['id'] == ident), None)
        if not found:
            raise ValueError('Устройство не найдено')
        found['incidents'] = self.incidents(device_id=ident)
        if ident.startswith('host:'):
            found['inventory'] = self.svc.inventory.host_detail(int(ident[5:]))
        return found

    def save_context(self, body):
        ident = text(body.get('id'), 64)
        self.device(ident)
        site, owner = text(body.get('site', '')), text(body.get('owner', ''))
        tags = body.get('tags', [])
        if not isinstance(tags, list) or len(tags) > 16:
            raise ValueError('Допустимо до 16 тегов')
        tags = sorted(set(text(tag, 40) for tag in tags if tag))
        until = float(body.get('maintenance_until', 0))
        if not math.isfinite(until) or until < 0 or until > time.time() + 7*86400:
            raise ValueError('Техническое окно: максимум 7 суток')
        with self.svc.db.connection() as con:
            con.execute('''INSERT INTO device_context VALUES (?,?,?,?,?,?)
                ON CONFLICT(device_id) DO UPDATE SET site=excluded.site, owner=excluded.owner,
                tags=excluded.tags, maintenance_until=excluded.maintenance_until, updated=excluded.updated''',
                (ident, site, owner, json.dumps(tags, ensure_ascii=False), until, time.time()))
            con.commit()
        return self.device(ident)

    def incidents(self, status='', device_id='', limit=100):
        if status and status not in ('open', 'acknowledged', 'resolved'):
            raise ValueError('Неизвестный статус')
        limit = min(500, max(1, int(limit)))
        with self.svc.db.connection() as con:
            rows = con.execute('''SELECT * FROM incidents WHERE (?='' OR status=?)
                AND (?='' OR device_id=?) ORDER BY updated DESC LIMIT ?''',
                (status, status, device_id, device_id, limit)).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    def _timeline(con, ident, actor, action, message):
        con.execute('INSERT INTO incident_timeline(incident_id,ts,actor,action,message) VALUES(?,?,?,?,?)',
                    (ident, time.time(), actor[:160], action, message[:2000]))

    def open_incident(self, device_id, title, severity='warning', event_key=None, actor='system'):
        device_id, title = text(device_id, 64), text(title, 300)
        if not title or severity not in ('info', 'warning', 'critical'):
            raise ValueError('Нужны заголовок и допустимая важность')
        key = event_key or ('manual:' + uuid.uuid4().hex)
        now = time.time()
        with self.svc.db.connection() as con:
            con.execute('BEGIN IMMEDIATE')
            old = con.execute("SELECT id FROM incidents WHERE event_key=? AND status IN ('open','acknowledged')", (key,)).fetchone()
            if old:
                con.execute('UPDATE incidents SET updated=?, occurrences=occurrences+1 WHERE id=?', (now, old['id']))
                con.commit()
                return old['id'], False
            ident = uuid.uuid4().hex
            con.execute('''INSERT INTO incidents(id,event_key,device_id,title,severity,status,opened,updated)
                        VALUES(?,?,?,?,?,'open',?,?)''', (ident, key, device_id, title, severity, now, now))
            self._timeline(con, ident, actor, 'opened', title)
            con.commit()
        return ident, True

    def incident(self, ident):
        with self.svc.db.connection() as con:
            row = con.execute('SELECT * FROM incidents WHERE id=?', (ident,)).fetchone()
            if not row:
                raise ValueError('Инцидент не найден')
            timeline = con.execute('SELECT ts,actor,action,message FROM incident_timeline WHERE incident_id=? ORDER BY id DESC LIMIT 100', (ident,)).fetchall()
        return {**dict(row), 'timeline': [dict(r) for r in reversed(timeline)]}

    def change_incident(self, body, actor):
        ident, action = text(body.get('id'), 64), body.get('action')
        if action not in ('acknowledge', 'resolve', 'assign', 'comment'):
            raise ValueError('Неизвестное действие')
        message = text(body.get('message', ''), 2000)
        with self.svc.db.connection() as con:
            con.execute('BEGIN IMMEDIATE')
            row = con.execute('SELECT * FROM incidents WHERE id=?', (ident,)).fetchone()
            if not row:
                raise ValueError('Инцидент не найден')
            if action == 'acknowledge':
                if row['status'] != 'open':
                    raise ValueError('Подтверждать можно только открытый инцидент')
                con.execute("UPDATE incidents SET status='acknowledged', acknowledged=?, updated=? WHERE id=?", (time.time(), time.time(), ident))
            elif action == 'resolve':
                if row['status'] == 'resolved':
                    raise ValueError('Инцидент уже закрыт')
                con.execute("UPDATE incidents SET status='resolved', resolved=?, updated=? WHERE id=?", (time.time(), time.time(), ident))
            elif action == 'assign':
                message = text(body.get('owner', ''))
                con.execute('UPDATE incidents SET owner=?, updated=? WHERE id=?', (message, time.time(), ident))
            elif not message:
                raise ValueError('Комментарий пуст')
            self._timeline(con, ident, actor, action, message)
            con.commit()
        return self.incident(ident)

    def observe_router(self, row):
        ident = 'router:' + row['id']
        now = time.time()
        with self.svc.db.connection() as con:
            con.execute('BEGIN IMMEDIATE')
            old = con.execute('SELECT * FROM router_health WHERE device_id=?', (ident,)).fetchone()
            failures = 0 if row['ok'] else (old['failures'] if old else 0) + 1
            success = now if row['ok'] else (old['last_success'] if old else None)
            con.execute('INSERT OR REPLACE INTO router_health VALUES(?,?,?,?)', (ident, failures, success, now))
            context = con.execute('SELECT maintenance_until FROM device_context WHERE device_id=?', (ident,)).fetchone()
            maintenance = context and context['maintenance_until'] > now
            con.commit()
        key = 'router-unreachable:' + row['id']
        if row['ok']:
            with self.svc.db.connection() as con:
                active = con.execute("SELECT id FROM incidents WHERE event_key=? AND status IN ('open','acknowledged')", (key,)).fetchone()
            if active:
                self.change_incident({'id': active['id'], 'action': 'resolve', 'message': 'Связь восстановлена'}, 'collector')
                return 'resolved'
        elif not maintenance and failures >= 2:
            _, created = self.open_incident(ident, 'Нет связи: ' + row['name'], 'critical', key)
            if created:
                return 'opened'
        return None

    def summary(self):
        rows = self.incidents(limit=500)
        return {'open': sum(r['status'] == 'open' for r in rows),
                'acknowledged': sum(r['status'] == 'acknowledged' for r in rows),
                'resolved': sum(r['status'] == 'resolved' for r in rows), 'scope': 'latest_500'}

    def receive_alerts(self, body):
        alerts = body.get('alerts')
        if not isinstance(alerts, list) or len(alerts) > 100:
            raise ValueError('Ожидается до 100 оповещений')
        validated = []
        for alert in alerts:
            if not isinstance(alert, dict) or alert.get('status') not in ('firing', 'resolved'):
                raise ValueError('Некорректное оповещение')
            labels = alert.get('labels') or {}
            if not isinstance(labels, dict):
                raise ValueError('Некорректные метки')
            labels = {key: text(labels.get(key, ''), 256) for key in ('alertname','job','instance','router')}
            if not labels['alertname']:
                raise ValueError('Отсутствует alertname')
            annotations = alert.get('annotations') or {}
            if not isinstance(annotations, dict):
                raise ValueError('Некорректные аннотации')
            title = text(annotations.get('summary') or labels['alertname'], 300)
            validated.append((alert['status'], labels, title))
        contexts = self.contexts()
        router_ids = {device['id'][7:] for device in self.devices() if device['kind']=='router'}
        outcome = {'opened':0, 'resolved':0, 'ignored':0, 'notifications':[]}
        for status, labels, title in validated:
            router = labels['router'] if labels['router'] in router_ids else ''
            device_id = 'router:'+router if router else ''
            key = 'prometheus:'+hashlib.sha256(json.dumps(labels,sort_keys=True).encode()).hexdigest()
            shared = labels['alertname']=='MikroTikUnreachable' and router
            if shared:
                key = 'router-unreachable:'+router
            if status == 'firing':
                if contexts.get(device_id,{}).get('maintenance_until',0)>time.time():
                    outcome['ignored']+=1;continue
                _,created = self.open_incident(device_id,title,'critical',key,'alertmanager')
                if created:
                    outcome['opened']+=1;outcome['notifications'].append(('ALERT_OPENED',title))
                else:outcome['ignored']+=1
            else:
                with self.svc.db.connection() as con:
                    active = con.execute("SELECT id FROM incidents WHERE event_key=? AND status IN ('open','acknowledged')",(key,)).fetchone()
                    health = con.execute('SELECT failures FROM router_health WHERE device_id=?',(device_id,)).fetchone() if shared else None
                if not active or (health and health['failures']):
                    outcome['ignored']+=1;continue
                try:
                    self.change_incident({'id':active['id'],'action':'resolve','message':'Alertmanager: восстановление'},'alertmanager')
                    outcome['resolved']+=1;outcome['notifications'].append(('ALERT_RESOLVED',title))
                except ValueError:outcome['ignored']+=1
        return outcome

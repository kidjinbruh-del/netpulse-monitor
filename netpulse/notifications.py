"""Bounded notification delivery with persistent, credential-free status."""
import json
import smtplib
import ssl
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from urllib.parse import urlsplit
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise ValueError('Notification redirects are not accepted')


class Notifications:
    def __init__(self, service):
        self.svc = service
        self.pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix='np-notify')
        self.slots = threading.BoundedSemaphore(32)
        self.stopped = threading.Event()
        with self.svc.db.connection() as con:
            con.execute('''CREATE TABLE IF NOT EXISTS notification_delivery (
                id TEXT PRIMARY KEY, channel TEXT NOT NULL, title TEXT NOT NULL,
                status TEXT NOT NULL, attempts INTEGER NOT NULL, error TEXT NOT NULL,
                created REAL NOT NULL, updated REAL NOT NULL)''')
            con.execute("UPDATE notification_delivery SET status='interrupted' WHERE status IN ('queued','sending')")
            con.commit()

    def history(self):
        with self.svc.db.connection() as con:
            return [dict(r) for r in con.execute('SELECT * FROM notification_delivery ORDER BY created DESC LIMIT 100')]

    def _status(self, ident, status, attempts, error=''):
        with self.svc.db.connection() as con:
            con.execute('UPDATE notification_delivery SET status=?,attempts=?,error=?,updated=? WHERE id=?',
                        (status, attempts, error, time.time(), ident))
            con.commit()

    def enqueue(self, title, message):
        ids = []
        for channel in ('telegram', 'webhook', 'email'):
            cfg = dict(self.svc.cfg.get(channel) or {})
            if not cfg.get('enabled') or self.stopped.is_set():
                continue
            if not self.slots.acquire(blocking=False):
                break
            ident = uuid.uuid4().hex
            try:
                with self.svc.db.connection() as con:
                    con.execute('INSERT INTO notification_delivery VALUES(?,?,?,?,?,?,?,?)',
                        (ident, channel, str(title)[:160], 'queued', 0, '', time.time(), time.time()))
                    # Bound retained delivery metadata, independently of traffic retention.
                    con.execute('''DELETE FROM notification_delivery WHERE id IN
                        (SELECT id FROM notification_delivery WHERE status NOT IN ('queued','sending')
                         ORDER BY created DESC LIMIT -1 OFFSET 2000)''')
                    con.commit()
                self.pool.submit(self._deliver, ident, channel, cfg, str(title)[:160], str(message)[:3500])
                ids.append(ident)
            except Exception:
                self.slots.release()
                raise
        return ids

    @staticmethod
    def _send(channel, cfg, title, message):
        if channel == 'email':
            mail = EmailMessage()
            mail['Subject'] = '[NetPulse] ' + title
            mail['From'] = cfg.get('from') or 'netpulse@localhost'
            mail['To'] = cfg['to']
            mail.set_content(message)
            with smtplib.SMTP(cfg['smtp_host'], int(cfg.get('smtp_port', 25)), timeout=10) as client:
                if cfg.get('use_tls', True):
                    client.starttls(context=ssl.create_default_context())
                if cfg.get('user'):
                    client.login(cfg['user'], cfg.get('password', ''))
                client.send_message(mail)
            return
        if channel == 'telegram':
            url = 'https://api.telegram.org/bot' + cfg['token'] + '/sendMessage'
            body = {'chat_id': cfg['chat_id'], 'text': '[NetPulse] ' + title + '\n' + message}
        else:
            url = cfg['url']
            parts = urlsplit(url)
            if parts.scheme != 'https' or not parts.hostname or parts.username or parts.password:
                raise ValueError('Webhook requires HTTPS without URL credentials')
            body = {'source': 'netpulse', 'type': title, 'message': message, 'ts': time.time(),
                    'text': '[NetPulse] ' + title + ': ' + message}
        request = Request(url, data=json.dumps(body).encode(),
                          headers={'Content-Type': 'application/json'}, method='POST')
        with build_opener(NoRedirect()).open(request, timeout=10) as response:
            if channel == 'telegram':
                data = json.loads(response.read(65537))
                if data.get('ok') is not True:
                    raise ValueError('Receiver rejected notification')

    def _deliver(self, ident, channel, cfg, title, message):
        try:
            for attempt in range(1, 4):
                if self.stopped.is_set():
                    self._status(ident, 'interrupted', attempt-1)
                    return
                self._status(ident, 'sending', attempt)
                try:
                    self._send(channel, cfg, title, message)
                    self._status(ident, 'sent', attempt)
                    return
                except Exception:
                    # Never persist exception text: upstream URLs can contain tokens.
                    if attempt == 3:
                        self._status(ident, 'failed', attempt, 'Проверьте сеть, TLS, адрес и учётные данные получателя')
                    else:
                        self.stopped.wait(attempt)
        except Exception:
            # A shutdown may close the database while an upstream request finishes.
            pass
        finally:
            self.slots.release()

    def stop(self):
        self.stopped.set()
        self.pool.shutdown(wait=False)

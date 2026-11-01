from datetime import datetime, timedelta
from types import SimpleNamespace
from urllib.error import HTTPError
import pytest
from core.database import DatabaseManager
from netpulse import cve


def test_expired_cache_network_failure_and_success(tmp_path, monkeypatch):
    db = DatabaseManager(str(tmp_path / 'cve.db'))
    try:
        checker = cve.CVEChecker(SimpleNamespace(db=db))
        old = (datetime.now() - timedelta(days=2)).isoformat()
        db.execute('INSERT INTO sw_cve(product,version,cve,checked_at) VALUES(?,?,?,?)',
                   ('App', '1', 'CVE-old', old))
        def unavailable(product):
            raise cve.CVEUnavailable('offline')
        monkeypatch.setattr(checker, '_query', unavailable)
        assert checker.check_products([('App', '1')]) == []
        assert checker.status()['error']
        assert db.execute('SELECT checked_at FROM sw_cve', fetch=True)[0]['checked_at'] == old
        calls = []
        monkeypatch.setattr(checker, '_query', lambda product: calls.append(product) or [])
        assert checker.check_products([('App', '1')]) == []
        assert not checker.status()['error']
        checker.check_products([('App', '1')])
        assert calls == ['App 1']
        assert db.execute('SELECT cve FROM sw_cve', fetch=True)[0]['cve'] is None
    finally:
        db.close()


def test_nvd_429_raises_and_defers_next_request(monkeypatch):
    checker = object.__new__(cve.CVEChecker)
    monkeypatch.setattr(cve, '_last_req', [0.0])
    def limited(*args, **kwargs):
        raise HTTPError(cve.NVD_API, 429, 'rate limited', {}, None)
    monkeypatch.setattr(cve, 'urlopen', limited)
    with pytest.raises(cve.CVEUnavailable):
        checker._query('App')
    assert cve._last_req[0] > cve.time.monotonic() + 25

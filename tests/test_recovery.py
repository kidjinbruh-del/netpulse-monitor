import json
import sqlite3
import subprocess
import sys
import zipfile
from contextlib import closing
from pathlib import Path
import pytest
from netpulse import recovery


@pytest.fixture
def source(tmp_path):
    data = tmp_path / 'data'
    data.mkdir()
    (data / 'config.json').write_text(json.dumps({'web_token': 'private-test-token', 'theme': 'dark'}))
    con = sqlite3.connect(data / 'network_stats.db')
    con.execute('PRAGMA journal_mode=WAL')
    con.execute('PRAGMA wal_autocheckpoint=0')
    con.execute('CREATE TABLE events(id INTEGER PRIMARY KEY, note TEXT)')
    con.execute('INSERT INTO events(note) VALUES(?)', ('committed in WAL',))
    con.commit()
    # Source connection remains open so a raw file copy would omit WAL content.
    yield data, con
    con.close()


def bundle(source, tmp_path):
    return Path(recovery.create(source[0], tmp_path / 'archives')['archive'])


def test_live_wal_snapshot_restore_and_no_secret_output(source, tmp_path):
    archive = bundle(source, tmp_path)
    checked = recovery.inspect(archive)
    assert checked['tables'] == 1
    assert 'private-test-token' not in json.dumps(checked)
    output = tmp_path / 'restored'
    recovery.restore(archive, output)
    with closing(sqlite3.connect(output / 'network_stats.db')) as con:
        assert con.execute('SELECT note FROM events').fetchall() == [('committed in WAL',)]
    assert json.loads((output / 'config.json').read_text())['web_token'] == 'private-test-token'
    with pytest.raises(recovery.RecoveryError, match='уже существует'):
        recovery.restore(archive, output)
    assert source[1].execute('SELECT count(*) FROM events').fetchone()[0] == 1


def rewrite(archive, transform):
    with zipfile.ZipFile(archive) as z:
        entries = {name: z.read(name) for name in z.namelist()}
    transform(entries)
    with zipfile.ZipFile(archive, 'w') as z:
        for name, data in entries.items():
            z.writestr(name, data)


@pytest.mark.parametrize('kind', ['checksum', 'database', 'config', 'traversal', 'version', 'missing'])
def test_invalid_archives_never_create_restore_target(source, tmp_path, kind):
    archive = bundle(source, tmp_path)
    def corrupt(entries):
        manifest = json.loads(entries['manifest.json'])
        if kind == 'checksum':
            entries['config.json'] = b' ' + entries['config.json'][1:]
        elif kind in ('database', 'config'):
            name = 'network_stats.db' if kind == 'database' else 'config.json'
            entries[name] = b'invalid file'
            import hashlib
            manifest['files'][name] = {'size': len(entries[name]), 'sha256': hashlib.sha256(entries[name]).hexdigest()}
        elif kind == 'traversal':
            entries['../outside.txt'] = b'outside'
        elif kind == 'version':
            manifest['schema'] = 100
        else:
            del entries['config.json']
        entries['manifest.json'] = json.dumps(manifest).encode()
    rewrite(archive, corrupt)
    with pytest.raises(recovery.RecoveryError):
        recovery.restore(archive, tmp_path / 'restored')
    assert not (tmp_path / 'restored').exists()
    assert not (tmp_path / 'outside.txt').exists()


def test_duplicate_entries_and_limits(source, tmp_path, monkeypatch):
    archive = bundle(source, tmp_path)
    with zipfile.ZipFile(archive, 'a') as z:
        with pytest.warns(UserWarning):
            z.writestr('config.json', '{}')
    with pytest.raises(recovery.RecoveryError):
        recovery.inspect(archive)
    archive = bundle(source, tmp_path)
    monkeypatch.setattr(recovery, 'MAX_BYTES', 16)
    with pytest.raises(recovery.RecoveryError):
        recovery.inspect(archive)


def test_failed_create_has_no_final_archive(source, tmp_path, monkeypatch):
    monkeypatch.setattr(recovery, 'check_database', lambda path: (_ for _ in ()).throw(recovery.RecoveryError('broken')))
    with pytest.raises(recovery.RecoveryError):
        recovery.create(source[0], tmp_path / 'archives')
    assert list((tmp_path / 'archives').iterdir()) == []


def test_dpapi_marker_and_only_expected_files(source, tmp_path):
    (source[0] / 'config.json').write_text('{"web_token":"dpapi:fixture"}')
    (source[0] / '.env').write_text('SECRET=not-for-backup')
    archive = bundle(source, tmp_path)
    assert recovery.inspect(archive)['dpapi_values'] == 1
    with zipfile.ZipFile(archive) as z:
        assert set(z.namelist()) == {'manifest.json', 'config.json', 'network_stats.db'}


def test_cli_round_trip_without_starting_service(source, tmp_path):
    command = [sys.executable, '-m', 'netpulse']
    result = subprocess.run(command + ['--backup-create', str(tmp_path / 'archives'), '--data-dir', str(source[0])], capture_output=True, text=True, cwd=Path(__file__).resolve().parents[1])
    assert result.returncode == 0, result.stdout + result.stderr
    archive = json.loads(result.stdout)['archive']
    result = subprocess.run(command + ['--backup-restore', archive, '--restore-dir', str(tmp_path / 'new')], capture_output=True, text=True, cwd=Path(__file__).resolve().parents[1])
    assert result.returncode == 0, result.stdout + result.stderr
    result = subprocess.run(command + ['--backup-restore', archive, '--restore-dir', str(tmp_path / 'new')], capture_output=True, text=True, cwd=Path(__file__).resolve().parents[1])
    assert result.returncode == 1


def test_missing_source_never_creates_empty_database(tmp_path):
    with pytest.raises(recovery.RecoveryError):
        recovery.create(tmp_path, tmp_path / 'archives')
    assert not (tmp_path / 'network_stats.db').exists()


def test_scheduled_backup_failure_does_not_mark_day_complete(tmp_path, monkeypatch):
    from netpulse.server import BackupManager
    manager = BackupManager({'backup': {'enabled': True, 'time': '00:00', 'dir': str(tmp_path)}})
    monkeypatch.setattr(manager, 'run_backup_now', lambda: {'ok': False})
    manager.run_backup_if_due()
    assert not (tmp_path / '.last_auto_run').exists()


def test_backup_manager_uses_wal_snapshot(source, tmp_path, monkeypatch):
    from netpulse.server import BackupManager
    monkeypatch.chdir(source[0])
    result = BackupManager({'backup': {'dir': str(tmp_path / 'archives')}}).run_backup_now()
    assert result['ok']
    assert recovery.inspect(result['archive'])['tables'] == 1


def test_http_backup_verification_roles_and_path_boundary(source, tmp_path):
    from tests.test_operations import ops_server
    from tests.test_netpulse import _post, _get
    import time
    archive = bundle(source, tmp_path)
    with ops_server(tmp_path) as (service, base):
        service.cfg['backup']['dir'] = str(archive.parent)
        for role in ('viewer', 'operator'):
            headers = {'X-Auth': role + '-test'}
            assert _post(base + '/api/backupverify', {'name': archive.name}, headers)[0] == 403
            assert _post(base + '/api/backupjob', {}, headers)[0] == 403
        headers = {'X-Auth': 'admin-test'}
        assert _post(base + '/api/backupverify', {'name': '../outside.zip'}, headers)[0] == 400
        code, body = _post(base + '/api/backupverify', {'name': archive.name}, headers)
        assert code == 200
        job = json.loads(body)['job']
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            code, body = _get(base + '/api/securityresult?job=' + job, headers)
            result = json.loads(body)
            if result['status'] != 'running':
                break
            time.sleep(.02)
        assert result['status'] == 'done', result
        assert result['result']['ok']
        assert 'private-test-token' not in body

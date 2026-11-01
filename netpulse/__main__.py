"""NetPulse CLI. --check validates local setup without starting monitoring."""
import argparse
import json
import sqlite3
from pathlib import Path

def port_number(value):
    try:
        port=int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError('port must be an integer') from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError('port must be between 1 and 65535')
    return port

def main():
    parser=argparse.ArgumentParser(description='NetPulse network operations dashboard')
    parser.add_argument('--port',type=port_number)
    actions=parser.add_mutually_exclusive_group()
    actions.add_argument('--check',action='store_true',help='read-only setup diagnostics (JSON)')
    actions.add_argument('--backup-create',metavar='DIRECTORY',help='create a verified data recovery bundle')
    actions.add_argument('--backup-inspect',metavar='ARCHIVE',help='verify checksums and SQLite integrity')
    actions.add_argument('--backup-restore',metavar='ARCHIVE',help='restore into a new directory only')
    parser.add_argument('--data-dir',default='.',help='source data directory for backup creation')
    parser.add_argument('--restore-dir',help='new, nonexistent destination for recovery')
    args=parser.parse_args()
    recovery_action=args.backup_create or args.backup_inspect or args.backup_restore
    if args.restore_dir and not args.backup_restore:
        parser.error('--restore-dir requires --backup-restore')
    if args.backup_restore and not args.restore_dir:
        parser.error('--backup-restore requires --restore-dir')
    if recovery_action:
        if args.port is not None:
            parser.error('--port cannot be combined with backup operations')
        from . import recovery
        try:
            if args.backup_create:
                result=recovery.create(Path(args.data_dir),Path(args.backup_create))
            elif args.backup_inspect:
                result=recovery.inspect(args.backup_inspect)
            else:
                result=recovery.restore(args.backup_restore,args.restore_dir)
            print(json.dumps(result,ensure_ascii=True,indent=2))
        except (OSError,ValueError,sqlite3.Error) as error:
            print(json.dumps({'ok':False,'error':str(error)},ensure_ascii=True))
            raise SystemExit(1)
        return
    if args.check:
        from .doctor import main as doctor
        raise SystemExit(doctor())
    from .config import load_config
    from . import server
    server.setup_logging()
    config=load_config()
    if args.port is not None:config['web_port']=args.port
    server.run(config)

if __name__=='__main__':main()

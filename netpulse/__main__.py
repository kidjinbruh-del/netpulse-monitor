"""NetPulse CLI. --check validates local setup without starting monitoring."""
import argparse

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
    parser.add_argument('--check',action='store_true',help='read-only setup diagnostics (JSON)')
    args=parser.parse_args()
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

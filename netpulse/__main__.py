"""
Точка входа: python -m netpulse [--port 8770]
"""

import sys
from .config import load_config
from . import server


def main():
    args = sys.argv[1:]
    config = load_config()
    if "--port" in args:
        try:
            config["web_port"] = int(args[args.index("--port") + 1])
        except (ValueError, IndexError):
            print("использование: python -m netpulse [--port 8770]")
            sys.exit(1)

    print("=" * 50)
    print(f"NETPULSE v{__import__('netpulse', fromlist=['__version__']).__version__}")
    print("Сетевой центр мониторинга | Ctrl+C - выход")
    print("=" * 50)

    server.run(config)


if __name__ == "__main__":
    main()

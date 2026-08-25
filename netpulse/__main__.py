"""
Точка входа: python -m netpulse [--port 8770]
"""

import sys
from .config import load_config
from . import server
import logging

logger = logging.getLogger(__name__)

def main():
    server.setup_logging()
    args = sys.argv[1:]
    config = load_config()
    if "--port" in args:
        try:
            config["web_port"] = int(args[args.index("--port") + 1])
        except (ValueError, IndexError):
            logger.info("использование: python -m netpulse [--port 8770]")
            sys.exit(1)

    logger.info("=" * 50)
    logger.info(f"NETPULSE v{__import__('netpulse', fromlist=['__version__']).__version__}")
    logger.info("Сетевой центр мониторинга | Ctrl+C - выход")
    logger.info("=" * 50)

    server.run(config)


if __name__ == "__main__":
    main()

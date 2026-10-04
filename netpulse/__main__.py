"""
Точка входа NetPulse v3: python -m netpulse [--port 8770]

Порядок запуска:
  1. Загрузить конфигурацию (config.json + DEFAULTS + validate)
  2. Создать AppContext и выполнить startup (БД, сервисы)
  3. Создать FastAPI-приложение и запустить uvicorn
  4. При остановке — graceful shutdown через AppContext
"""

import sys

from netpulse import __version__
from netpulse.config import load_config
from netpulse.context import AppContext, set_global_context
from netpulse.server.main import create_app


def main() -> None:
    args = sys.argv[1:]
    config = load_config()

    if "--port" in args:
        try:
            config.web.port = int(args[args.index("--port") + 1])
        except (ValueError, IndexError):
            print("использование: python -m netpulse [--port 8770]")
            sys.exit(1)

    with AppContext(config) as ctx:
        set_global_context(ctx)
        ctx.logger.info("=" * 50)
        ctx.logger.info(f"NETPULSE v{__version__}")
        ctx.logger.info("Сетевой центр мониторинга | Ctrl+C - выход")
        ctx.logger.info("=" * 50)

        app = create_app(config, ctx)

        import uvicorn
        uvicorn.run(
            app,
            host=config.web.host,
            port=config.web.port,
            log_config=None,
            access_log=False,
        )


if __name__ == "__main__":
    main()

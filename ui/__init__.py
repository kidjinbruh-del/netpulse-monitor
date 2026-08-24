"""
UI Module - пользовательский интерфейс
"""

from .main_window import App
from .trace_window import TraceWindow
from .security_window import SecurityWindow
from .ai_dashboard_window import AIDashboard
from .settings_window import SettingsWindow
from .alerts_window import AlertsWindow
from .stats_window import StatsWindow
from .widgets.mini_chart import MiniChart
from .widgets.graceful_shutdown import GracefulShutdown

__all__ = [
    'App',
    'TraceWindow',
    'SecurityWindow',
    'AIDashboard',
    'SettingsWindow',
    'AlertsWindow',
    'StatsWindow',
    'MiniChart',
    'GracefulShutdown'
]

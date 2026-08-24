"""
Main Window - главное окно приложения
"""

import customtkinter as ctk
import threading
import os
from datetime import datetime
from tkinter import filedialog, messagebox
import logging

from core import DatabaseManager, Sniffer, Pinger, is_admin
from ai import AIOrchestrator
from .trace_window import TraceWindow
from .security_window import SecurityWindow
from .ai_dashboard_window import AIDashboard
from .settings_window import SettingsWindow
from .alerts_window import AlertsWindow
from .stats_window import StatsWindow
from .widgets.mini_chart import MiniChart
from .widgets.graceful_shutdown import GracefulShutdown

logger = logging.getLogger(__name__)

class App:
    """Главное окно приложения"""

    def __init__(self, db_manager, sniffer, pinger, ai_orchestrator, config):
        self.db_manager = db_manager
        self.sniffer = sniffer
        self.pinger = pinger
        self.ai_orchestrator = ai_orchestrator
        self.config = config

        self.running = True
        self._update_timer = None

        self.trace_window = None
        self.security_window = None
        self.ai_dashboard = None
        self.settings_window = None
        self.alerts_window = None
        self.stats_window = None
        self._is_closing = False
        self._close_lock = threading.Lock()

        # Настройка темы
        ctk.set_appearance_mode(config.get("theme", "dark"))
        ctk.set_default_color_theme("blue")

        # Создание главного окна
        self.root = ctk.CTk()
        self.root.title("Network Monitor Pro v7.0 - AI Enterprise")
        self.root.geometry("580x950")
        self.root.minsize(500, 800)
        self.root.configure(fg_color="#0b0b10")

        # Центрирование
        self.root.update_idletasks()
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        x = (screen_width - 580) // 2
        y = (screen_height - 950) // 2
        self.root.geometry(f"+{x}+{y}")

        # Обработка закрытия
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Построение UI
        self._build_ui()

        # Запуск мониторинга
        self.root.after(500, self._start_monitoring)
        self._start_update_loop()

        logger.info("Главное окно создано")

    def _safe_update(self, func):
        """Потокобезопасное обновление UI: из любого потока через after() главного цикла"""
        try:
            root = self.root
            if not root or not root.winfo_exists():
                return

            in_main_thread = threading.current_thread() is threading.main_thread()
            if in_main_thread:
                func()
            else:
                root.after(0, func)
        except Exception:
            pass

    def _show_message(self, kind, title, message):
        """Потокобезопасный показ messagebox"""
        def show():
            try:
                if self.root and self.root.winfo_exists():
                    getattr(messagebox, kind)(title, message)
            except Exception as e:
                logger.error(f"Ошибка messagebox: {e}")
        self._safe_update(show)

    def _on_close(self):
        """Обработчик закрытия"""
        with self._close_lock:
            if self._is_closing:
                return
            self._is_closing = True

        logger.info("Закрытие приложения...")

        shutdown = GracefulShutdown(self)
        shutdown.execute()

    def _build_ui(self):
        """Построение интерфейса"""
        # Header
        header = ctk.CTkFrame(self.root, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=(10, 5))

        ctk.CTkLabel(
            header,
            text="🌐 NETWORK MONITOR PRO v7.0",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#9146FF"
        ).pack(side="left")

        self.uptime_label = ctk.CTkLabel(
            header,
            text="0с",
            font=ctk.CTkFont(size=12),
            text_color="#6a6a7a"
        )
        self.uptime_label.pack(side="right", padx=5)

        self.mode_label = ctk.CTkLabel(
            header,
            text="…",
            font=ctk.CTkFont(size=12),
            text_color="#6a6a7a"
        )
        self.mode_label.pack(side="right", padx=10)

        # Кнопки
        btn_row = ctk.CTkFrame(self.root, fg_color="transparent")
        btn_row.pack(fill="x", padx=15, pady=3)

        ctk.CTkButton(
            btn_row,
            text="🤖 AI",
            command=self._open_ai_dashboard,
            fg_color="#12121a",
            border_width=1,
            border_color="#9146FF",
            text_color="#9146FF",
            height=30
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            btn_row,
            text="🌍 Трассировка",
            command=self._open_trace,
            fg_color="#12121a",
            border_width=1,
            border_color="#9146FF",
            text_color="#9146FF",
            height=30
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            btn_row,
            text="🛡️ Безопасность",
            command=self._open_security,
            fg_color="#12121a",
            border_width=1,
            border_color="#ff4757",
            text_color="#ff4757",
            height=30
        ).pack(side="left", padx=3)

        ctk.CTkButton(
            btn_row,
            text="📄 Отчёт",
            command=self._export_report,
            fg_color="#12121a",
            border_width=1,
            border_color="#2ed573",
            text_color="#2ed573",
            height=30
        ).pack(side="left", padx=3)

        # Вторая панель: настройки / алерты / статистика
        btn_row2 = ctk.CTkFrame(self.root, fg_color="transparent")
        btn_row2.pack(fill="x", padx=15, pady=(0, 3))

        ctk.CTkButton(
            btn_row2,
            text="⚙️ Настройки",
            command=self._open_settings,
            fg_color="#12121a",
            border_width=1,
            border_color="#6a6a7a",
            text_color="#e0e0e0",
            height=26
        ).pack(side="left", padx=3)

        self.alerts_btn = ctk.CTkButton(
            btn_row2,
            text="🔔 Алерты",
            command=self._open_alerts,
            fg_color="#12121a",
            border_width=1,
            border_color="#f1c40f",
            text_color="#f1c40f",
            height=26
        )
        self.alerts_btn.pack(side="left", padx=3)

        ctk.CTkButton(
            btn_row2,
            text="📊 Статистика",
            command=self._open_stats,
            fg_color="#12121a",
            border_width=1,
            border_color="#9146FF",
            text_color="#9146FF",
            height=26
        ).pack(side="left", padx=3)

        # Контейнеры скорости и пинга
        containers = ctk.CTkFrame(self.root, fg_color="transparent")
        containers.pack(fill="x", padx=15, pady=5)

        # Скорость
        speed_container = ctk.CTkFrame(
            containers,
            fg_color="#12121a",
            corner_radius=12,
            border_width=1,
            border_color="#1e1e28"
        )
        speed_container.pack(side="left", fill="both", expand=True, padx=(0, 4))

        self.speed_label = ctk.CTkLabel(
            speed_container,
            text="0.0",
            font=ctk.CTkFont(size=34, weight="bold"),
            text_color="#2ed573"
        )
        self.speed_label.pack(pady=(12, 0))

        ctk.CTkLabel(
            speed_container,
            text="скорость KB/s",
            font=ctk.CTkFont(size=10),
            text_color="#6a6a7a"
        ).pack()

        speed_row = ctk.CTkFrame(speed_container, fg_color="transparent")
        speed_row.pack(fill="x", padx=12, pady=8)

        self.max_speed_label = ctk.CTkLabel(
            speed_row,
            text="пик 0",
            font=ctk.CTkFont(size=10),
            text_color="#f1c40f"
        )
        self.max_speed_label.pack(side="left")

        self.total_label = ctk.CTkLabel(
            speed_row,
            text="0 MB",
            font=ctk.CTkFont(size=10),
            text_color="#6a6a7a"
        )
        self.total_label.pack(side="right")

        self.updown_label = ctk.CTkLabel(
            speed_container,
            text="↓ 0 KB/s  ↑ 0 KB/s",
            font=ctk.CTkFont(size=10),
            text_color="#6a6a7a"
        )
        self.updown_label.pack(pady=(0, 4))

        # Пинг
        ping_container = ctk.CTkFrame(
            containers,
            fg_color="#12121a",
            corner_radius=12,
            border_width=1,
            border_color="#1e1e28"
        )
        ping_container.pack(side="right", fill="both", expand=True, padx=(4, 0))

        self.ping_label = ctk.CTkLabel(
            ping_container,
            text="0",
            font=ctk.CTkFont(size=34, weight="bold"),
            text_color="#2ed573"
        )
        self.ping_label.pack(pady=(12, 0))

        ctk.CTkLabel(
            ping_container,
            text="пинг ms",
            font=ctk.CTkFont(size=10),
            text_color="#6a6a7a"
        ).pack()

        ping_row = ctk.CTkFrame(ping_container, fg_color="transparent")
        ping_row.pack(fill="x", padx=12, pady=8)

        self.jitter_label = ctk.CTkLabel(
            ping_row,
            text="джиттер 0",
            font=ctk.CTkFont(size=10),
            text_color="#f1c40f"
        )
        self.jitter_label.pack(side="left")

        self.loss_label = ctk.CTkLabel(
            ping_row,
            text="потери 0%",
            font=ctk.CTkFont(size=10),
            text_color="#ff4757"
        )
        self.loss_label.pack(side="right")

        # Статус сети
        status_container = ctk.CTkFrame(
            self.root,
            fg_color="#12121a",
            corner_radius=10,
            border_width=1,
            border_color="#1e1e28"
        )
        status_container.pack(fill="x", padx=15, pady=6)

        self.alert_label = ctk.CTkLabel(
            status_container,
            text="⏳ Запуск...",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#f1c40f"
        )
        self.alert_label.pack(pady=8)

        # Графики
        self._create_charts()

        # Список подключений
        ip_container = ctk.CTkFrame(
            self.root,
            fg_color="#12121a",
            corner_radius=12,
            border_width=1,
            border_color="#1e1e28"
        )
        ip_container.pack(fill="both", expand=True, padx=15, pady=4)

        ctk.CTkLabel(
            ip_container,
            text="🌍 ПОДКЛЮЧЕНИЯ",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#9146FF"
        ).pack(anchor="w", padx=12, pady=(8, 3))

        self.ip_list = ctk.CTkScrollableFrame(ip_container, fg_color="transparent")
        self.ip_list.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        # Status bar
        status_bar = ctk.CTkFrame(self.root, fg_color="#0d0d0d", height=26, corner_radius=0)
        status_bar.pack(fill="x", side="bottom")

        self.status_dot = ctk.CTkFrame(
            status_bar,
            width=8,
            height=8,
            corner_radius=4,
            fg_color="#f1c40f"
        )
        self.status_dot.place(x=12, y=9)

        ctk.CTkLabel(
            status_bar,
            text="Live",
            font=ctk.CTkFont(size=10),
            text_color="#6a6a7a"
        ).place(x=24, y=4)

        ai_enabled = self.config.get("ai", {}).get("enabled", True)
        ai_status_text = "🤖 AI: Активен" if ai_enabled else "🤖 AI: Выключен"
        ctk.CTkLabel(
            status_bar,
            text=ai_status_text,
            font=ctk.CTkFont(size=10),
            text_color="#9146FF"
        ).place(x=100, y=4)

        self.avg_label = ctk.CTkLabel(
            status_bar,
            text="",
            font=ctk.CTkFont(size=10),
            text_color="#6a6a7a"
        )
        self.avg_label.pack(side="right", padx=12)

    def _create_charts(self):
        """Создание графиков"""
        # График скорости
        speed_chart_container = ctk.CTkFrame(
            self.root,
            fg_color="#12121a",
            corner_radius=12,
            border_width=1,
            border_color="#1e1e28"
        )
        speed_chart_container.pack(fill="x", padx=15, pady=4)

        ctk.CTkLabel(
            speed_chart_container,
            text="📈 СКОРОСТЬ",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#9146FF"
        ).pack(anchor="w", padx=12, pady=(8, 2))

        self.speed_chart = MiniChart(
            speed_chart_container,
            width=500,
            height=130,
            color="#9146FF"
        )

        # График пинга
        ping_chart_container = ctk.CTkFrame(
            self.root,
            fg_color="#12121a",
            corner_radius=12,
            border_width=1,
            border_color="#1e1e28"
        )
        ping_chart_container.pack(fill="x", padx=15, pady=4)

        ctk.CTkLabel(
            ping_chart_container,
            text="📉 ПИНГ",
            font=ctk.CTkFont(size=11, weight="bold"),
            text_color="#9146FF"
        ).pack(anchor="w", padx=12, pady=(8, 2))

        self.ping_chart = MiniChart(
            ping_chart_container,
            width=500,
            height=110,
            color="#2ed573"
        )

    def _start_monitoring(self):
        """Запуск мониторинга"""
        try:
            self.sniffer.start()
            self.pinger.start()

            self._safe_update(lambda: self.alert_label.configure(
                text="✅ Сеть стабильна",
                text_color="#2ed573"
            ))
            self._safe_update(lambda: self.status_dot.configure(fg_color="#2ed573"))

            logger.info("Мониторинг запущен")
        except Exception as e:
            logger.error(f"Ошибка запуска мониторинга: {e}")
            self._safe_update(lambda: self.alert_label.configure(
                text="❌ Ошибка мониторинга",
                text_color="#ff4757"
            ))

    def _start_update_loop(self):
        """Запуск цикла обновления"""
        if not self.running:
            return

        self._update_ui()
        self._update_timer = self.root.after(
            self.config.get("update_interval", 1000),
            self._start_update_loop
        )

    def _update_ui(self):
        """Обновление UI"""
        if not self.running:
            return

        try:
            sniffer_stats = self.sniffer.get_stats()
            pinger_stats = self.pinger.get_stats()
            speed = self.sniffer.get_speed()

            # Обновление скорости
            speed_color = "#2ed573" if speed < 500 else "#f1c40f" if speed < 1000 else "#ff4757"
            self.speed_label.configure(text=f"{speed:.1f}", text_color=speed_color)
            self.max_speed_label.configure(text=f"пик {sniffer_stats['max_speed']:.0f}")
            self.total_label.configure(text=f"{sniffer_stats['total_mb']:.1f} MB")

            # Раздельные скорости down/up
            down_kb, up_kb = self.sniffer.get_speed_split()
            self.updown_label.configure(
                text=f"↓ {down_kb:.1f} KB/s   ↑ {up_kb:.1f} KB/s",
                text_color="#2ed573" if (down_kb + up_kb) < 500 else "#f1c40f"
            )

            # Индикатор режима захвата
            mode = sniffer_stats.get('mode', 'sim')
            mode_cfg = {
                "real":   ("🔴 Live", "#2ed573"),
                "psutil": ("🟢 Net", "#2ed573"),
                "sim":    ("⚡ Sim", "#f1c40f"),
            }
            mode_text, mode_color = mode_cfg.get(mode, ("⚡ Sim", "#f1c40f"))
            if hasattr(self, 'mode_label'):
                self.mode_label.configure(text=mode_text, text_color=mode_color)

            # Обновление пинга
            display_ping = pinger_stats.get('display', 0)
            ping_color = "#2ed573" if display_ping < 50 else "#f1c40f" if display_ping < 150 else "#ff4757"
            self.ping_label.configure(text=f"{display_ping:.0f}", text_color=ping_color)
            self.jitter_label.configure(text=f"джиттер {pinger_stats['jitter']:.0f}ms")
            self.loss_label.configure(text=f"потери {pinger_stats['loss']:.1f}%")
            self.uptime_label.configure(text=self.sniffer.get_uptime())

            # Обновление статуса
            thresholds = self.config.get("alert_thresholds", {})
            loss = pinger_stats['loss']

            if loss > thresholds.get("loss_critical", 5):
                alert_text, alert_color = "🚨 КРИТИЧЕСКИЕ ПОТЕРИ!", "#ff4757"
            elif loss > thresholds.get("loss_high", 2):
                alert_text, alert_color = "⚠️ Потери пакетов", "#ff4757"
            elif display_ping > thresholds.get("ping_high", 150):
                alert_text, alert_color = "⚠️ Высокий пинг", "#f1c40f"
            elif pinger_stats['jitter'] > thresholds.get("jitter_high", 30):
                alert_text, alert_color = "⚠️ Высокий джиттер", "#f1c40f"
            else:
                alert_text, alert_color = "✅ Сеть стабильна", "#2ed573"

            self.alert_label.configure(text=alert_text, text_color=alert_color)
            self.status_dot.configure(fg_color=alert_color)

            # AI Анализ
            if self.ai_orchestrator and self.config.get("ai", {}).get("enabled", True):
                ai_data = {
                    "speed": speed,
                    "bytes_in": sniffer_stats['bytes_in_delta'],
                    "bytes_out": sniffer_stats['bytes_out_delta'],
                    "ping_ms": display_ping,
                    "jitter": pinger_stats['jitter'],
                    "loss": pinger_stats['loss']
                }

                ai_result = self.ai_orchestrator.process_traffic_data(ai_data)

                analysis = ai_result.get('analysis', {})
                if analysis.get('is_anomaly', False):
                    confidence = analysis.get('confidence', 0)
                    severity = "HIGH" if confidence > 0.8 else "MEDIUM"
                    self.alert_label.configure(
                        text=f"🤖 AI: Аномалия ({severity})",
                        text_color="#ff4757"
                    )

            # Обновление графиков и IP-списка (не каждый тик)
            self._tick_counter = getattr(self, '_tick_counter', 0) + 1
            if self._tick_counter % 2 == 0:
                self._update_charts(sniffer_stats, pinger_stats)
            if self._tick_counter % 3 == 0:
                self._update_ip_list()
            # Дорогие операции с БД - раз в 5 тиков
            if self._tick_counter % 5 == 0:
                self._update_avg_stats()
                self._update_alerts_badge()

        except Exception as e:
            logger.error(f"Ошибка обновления UI: {e}")

    def _update_charts(self, sniffer_stats, pinger_stats):
        """Обновление графиков"""
        speed_history = sniffer_stats['speed_history']
        ping_history = pinger_stats['history']

        self.speed_chart.draw(list(speed_history))
        self.ping_chart.draw([(t, ms) for t, ms, loss in ping_history])

    def _update_ip_list(self):
        """Обновление списка IP (снимок данных в главном потоке, рендер сразу)"""
        try:
            top_ips = self.sniffer.get_top_ips(6)
            self._render_ip_list(top_ips)
        except Exception as e:
            logger.error(f"Ошибка получения IP: {e}")

    def _render_ip_list(self, top_ips):
        """Рендеринг списка IP"""
        try:
            for widget in self.ip_list.winfo_children():
                widget.destroy()

            if not top_ips:
                placeholder = ("Per-IP доступен в режиме 🔴 Live (запуск от админа)"
                               if self.sniffer.mode != "real" else "Нет активных подключений")
                ctk.CTkLabel(
                    self.ip_list,
                    text=placeholder,
                    text_color="#6a6a7a"
                ).pack(pady=10)
                return

            for ip, data in top_ips:
                row = ctk.CTkFrame(self.ip_list, fg_color="transparent")
                row.pack(fill="x", pady=1)

                ctk.CTkLabel(
                    row,
                    text=ip,
                    font=ctk.CTkFont(size=10),
                    text_color="#e0e0e0"
                ).pack(side="left")

                ctk.CTkLabel(
                    row,
                    text=f"{data['bytes']/1024:.0f} KB",
                    font=ctk.CTkFont(size=10),
                    text_color="#f1c40f"
                ).pack(side="right", padx=8)

                ctk.CTkLabel(
                    row,
                    text=f"{data['packets']} pkt",
                    font=ctk.CTkFont(size=10),
                    text_color="#6a6a7a"
                ).pack(side="right", padx=8)
        except Exception as e:
            logger.error(f"Ошибка рендеринга IP: {e}")

    def _update_avg_stats(self):
        """Обновление средней статистики"""
        try:
            avg_stats = self.db_manager.execute(
                """SELECT 
                    (SELECT AVG(speed) FROM traffic WHERE timestamp > datetime('now','localtime','-1 hour')) as avg_speed,
                    (SELECT AVG(ping_ms) FROM pings WHERE timestamp > datetime('now','localtime','-1 hour') AND loss = 0 AND ping_ms IS NOT NULL) as avg_ping
                """,
                fetch=True
            )

            if avg_stats:
                avg_speed = avg_stats[0].get('avg_speed', 0) or 0
                avg_ping = avg_stats[0].get('avg_ping', 0) or 0
                self.avg_label.configure(
                    text=f"ср. {avg_speed:.1f} KB/s | {avg_ping:.0f}ms"
                )
        except Exception as e:
            logger.debug(f"Ошибка получения средней статистики: {e}")

    def _window_alive(self, window):
        """Проверка живости дочернего окна"""
        if window is None:
            return False
        try:
            win = getattr(window, 'win', window)
            return bool(win.winfo_exists())
        except Exception:
            return False

    def _open_trace(self):
        """Открытие окна трассировки"""
        if not self._window_alive(self.trace_window):
            self.trace_window = TraceWindow(self.root, self.config)
        else:
            self.trace_window.win.lift()
            self.trace_window.win.focus_force()

    def _open_security(self):
        """Открытие окна безопасности"""
        if not self._window_alive(self.security_window):
            self.security_window = SecurityWindow(self.root, self.config)
        else:
            self.security_window.win.lift()
            self.security_window.win.focus_force()

    def _open_ai_dashboard(self):
        """Открытие AI дашборда"""
        if not self._window_alive(self.ai_dashboard):
            self.ai_dashboard = AIDashboard(self.root, self.ai_orchestrator, self.db_manager)
        else:
            self.ai_dashboard.win.lift()
            self.ai_dashboard.win.focus_force()

    def _open_settings(self):
        """Открытие окна настроек"""
        if not self._window_alive(self.settings_window):
            self.settings_window = SettingsWindow(self.root, self)
        else:
            self.settings_window.win.lift()
            self.settings_window.win.focus_force()

    def _open_alerts(self):
        """Открытие журнала алертов"""
        if not self._window_alive(self.alerts_window):
            self.alerts_window = AlertsWindow(
                self.root, self.db_manager,
                on_change=lambda n: self._safe_update(lambda: self._set_alerts_badge(n))
            )
        else:
            self.alerts_window.win.lift()
            self.alerts_window.win.focus_force()
        # Мгновенное обновление бейджа
        self._update_alerts_badge()

    def _open_stats(self):
        """Открытие окна статистики"""
        if not self._window_alive(self.stats_window):
            self.stats_window = StatsWindow(self.root, self.db_manager)
        else:
            self.stats_window.win.lift()
            self.stats_window.win.focus_force()

    def _set_alerts_badge(self, count):
        try:
            text = f"🔔 Алерты ({count})" if count else "🔔 Алерты"
            color = "#ff4757" if count else "#f1c40f"
            if hasattr(self, 'alerts_btn') and self.alerts_btn:
                self.alerts_btn.configure(text=text, border_color=color, text_color=color)
        except Exception:
            pass

    def _update_alerts_badge(self):
        try:
            rows = self.db_manager.execute(
                "SELECT COUNT(*) AS n FROM alerts WHERE acknowledged = 0", fetch=True
            )
            count = (rows[0]["n"] if rows else 0) or 0
            self._set_alerts_badge(count)
        except Exception as e:
            logger.debug(f"Ошибка счётчика алертов: {e}")

    def _export_report(self):
        """Экспорт отчета"""
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Текстовый файл", "*.txt")]
        )

        if not path:
            return

        def export_worker():
            traffic = self.db_manager.execute(
                """SELECT timestamp, speed, bytes_in_delta, bytes_out_delta 
                FROM traffic ORDER BY timestamp DESC LIMIT 30""",
                fetch=True
            )
            pings = self.db_manager.execute(
                """SELECT timestamp, ping_ms, loss 
                FROM pings ORDER BY timestamp DESC LIMIT 30""",
                fetch=True
            )
            content = self._format_report(path, traffic, pings)

            with open(path, "w", encoding="utf-8") as f:
                f.write(content)

            self._safe_update(lambda: self.alert_label.configure(
                text="✅ Отчёт сохранён",
                text_color="#2ed573"
            ))
            self._show_message("showinfo", "Успех", f"Отчёт сохранён: {os.path.basename(path)}")

        def export_error(e):
            logger.error(f"Ошибка экспорта: {e}")
            self._show_message("showerror", "Ошибка", f"Не удалось сохранить отчёт: {e}")

        threading.Thread(target=self._run_bg_task, args=(export_worker, export_error), daemon=True).start()

    @staticmethod
    def _run_bg_task(worker, error_handler=None):
        try:
            worker()
        except Exception as e:
            if error_handler:
                error_handler(e)

    @staticmethod
    def _format_report(path, traffic, pings):
        lines = [
            "=" * 60,
            "ОТЧЁТ СЕТЕВОГО МОНИТОРИНГА",
            f"Сгенерирован: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}",
            "=" * 60,
            "",
            "📈 ТРАФИК",
            "-" * 40,
        ]

        if traffic:
            for row in traffic:
                ts = row['timestamp']
                speed = row['speed']
                bytes_in = row['bytes_in_delta'] or 0
                bytes_out = row['bytes_out_delta'] or 0
                lines.append(
                    f"{ts[11:19]} | {speed:8.1f} KB/s | "
                    f"in:{bytes_in/1024:8.1f} KB | out:{bytes_out/1024:8.1f} KB"
                )
        else:
            lines.append("Нет данных о трафике")

        lines.extend(["", "📉 ПИНГ", "-" * 40])

        if pings:
            last_good = None
            for row in pings:
                ts = row['timestamp']
                ping_ms = row['ping_ms']
                loss = row['loss']

                if loss:
                    display_ping = last_good if last_good is not None else 0
                    ping_display = f"{display_ping:4.0f}ms" if display_ping > 0 else "---"
                    lines.append(f"{ts[11:19]} | {ping_display} | ПОТЕРЯ")
                else:
                    ping_display = f"{ping_ms:4.0f}ms" if ping_ms and ping_ms > 0 else "---"
                    lines.append(f"{ts[11:19]} | {ping_display}")
                    if ping_ms:
                        last_good = ping_ms
        else:
            lines.append("Нет данных о пинге")

        return "\n".join(lines) + "\n"

    def run(self):
        """Запуск приложения"""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            logger.info("Приложение остановлено пользователем")
        except Exception as e:
            logger.error(f"Критическая ошибка: {e}")
            raise

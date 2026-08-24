"""
Settings Window - окно настроек приложения с живым применением
"""

import json
import customtkinter as ctk
import logging

logger = logging.getLogger(__name__)

CONFIG_FILE = "config.json"


class SettingsWindow:
    def __init__(self, parent, app):
        self.win = ctk.CTkToplevel(parent)
        self.win.title("⚙️ Настройки")
        self.win.geometry("520x640")
        self.win.configure(fg_color="#0b0b10")
        self.win.protocol("WM_DELETE_WINDOW", self._on_close)
        self.win.transient(parent)

        self.app = app
        self.config = app.config
        self.entries = {}

        self._build_ui()

    def _on_close(self):
        if self.win and self.win.winfo_exists():
            self.win.destroy()

    def destroy(self):
        self._on_close()

    def _field(self, parent, label, key, default=""):
        ctk.CTkLabel(parent, text=label, font=ctk.CTkFont(size=11),
                     text_color="#6a6a7a").pack(anchor="w", padx=16, pady=(8, 1))
        entry = ctk.CTkEntry(parent, fg_color="#12121a", border_color="#1e1e28", height=28)
        entry.pack(fill="x", padx=16)
        entry.insert(0, str(default))
        self.entries[key] = entry
        return entry

    def _build_ui(self):
        header = ctk.CTkFrame(self.win, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=10)
        ctk.CTkLabel(header, text="⚙️ НАСТРОЙКИ",
                     font=ctk.CTkFont(size=18, weight="bold"),
                     text_color="#9146FF").pack(side="left")

        scroll = ctk.CTkScrollableFrame(self.win, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=5, pady=5)

        # Мониторинг
        sec1 = ctk.CTkFrame(scroll, fg_color="#12121a", corner_radius=10)
        sec1.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(sec1, text="📡 МОНИТОРИНГ", font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#2ed573").pack(anchor="w", padx=16, pady=(10, 2))

        self._field(sec1, "Цель пинга (IP или хост)", "ping_target",
                    self.config.get("ping_target", "8.8.8.8"))
        self._field(sec1, "Интервал обновления UI, мс", "update_interval",
                    self.config.get("update_interval", 1000))
        self._field(sec1, "Очистка БД старше, дней", "db_cleanup_days",
                    self.config.get("db_cleanup_days", 30))

        theme_frame = ctk.CTkFrame(sec1, fg_color="transparent")
        theme_frame.pack(fill="x", padx=16, pady=(8, 4))
        ctk.CTkLabel(theme_frame, text="Тема", font=ctk.CTkFont(size=11),
                     text_color="#6a6a7a").pack(side="left")
        self.theme_menu = ctk.CTkOptionMenu(theme_frame, values=["dark", "light"],
                                            fg_color="#1e1e28", button_color="#9146FF",
                                            height=26)
        self.theme_menu.set(self.config.get("theme", "dark"))
        self.theme_menu.pack(side="right")

        sniffer_frame = ctk.CTkFrame(sec1, fg_color="transparent")
        sniffer_frame.pack(fill="x", padx=16, pady=(4, 10))
        ctk.CTkLabel(sniffer_frame, text="Режим трафика", font=ctk.CTkFont(size=11),
                     text_color="#6a6a7a").pack(side="left")
        self.sniffer_menu = ctk.CTkOptionMenu(
            sniffer_frame,
            values=["auto", "psutil", "sim"],
            fg_color="#1e1e28", button_color="#9146FF", height=26)
        self.sniffer_menu.set(self.config.get("sniffer_mode", "auto"))
        self.sniffer_menu.pack(side="right")

        # Пороги алертов
        sec2 = ctk.CTkFrame(scroll, fg_color="#12121a", corner_radius=10)
        sec2.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(sec2, text="🚨 ПОРОГИ АЛЕРТОВ", font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#f1c40f").pack(anchor="w", padx=16, pady=(10, 2))

        th = self.config.get("alert_thresholds", {})
        th_grid = ctk.CTkFrame(sec2, fg_color="transparent")
        th_grid.pack(fill="x", padx=10, pady=(0, 10))

        for i, (key, label) in enumerate([
            ("ping_high", "Пинг, ms"),
            ("jitter_high", "Джиттер, ms"),
            ("loss_high", "Потери %"),
            ("loss_critical", "Крит. потери %")
        ]):
            frame = ctk.CTkFrame(th_grid, fg_color="transparent")
            frame.grid(row=i // 2, column=i % 2, padx=6, pady=3, sticky="ew")
            th_grid.grid_columnconfigure(i % 2, weight=1)
            self._field(frame, label, f"th_{key}", th.get(key, 0))

        # AI
        sec3 = ctk.CTkFrame(scroll, fg_color="#12121a", corner_radius=10)
        sec3.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(sec3, text="🤖 AI", font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#9146FF").pack(anchor="w", padx=16, pady=(10, 2))

        ai = self.config.get("ai", {})
        self.ai_switch_var = ctk.BooleanVar(value=ai.get("enabled", True))
        ai_row = ctk.CTkFrame(sec3, fg_color="transparent")
        ai_row.pack(fill="x", padx=16, pady=4)
        ctk.CTkLabel(ai_row, text="AI-анализ включён", font=ctk.CTkFont(size=11),
                     text_color="#e0e0e0").pack(side="left")
        ctk.CTkSwitch(ai_row, variable=self.ai_switch_var,
                      progress_color="#9146FF").pack(side="right")

        self._field(sec3, "Порог аномалий (0.1 - 0.95)", "anomaly_threshold",
                    ai.get("anomaly_threshold", 0.6))
        self._field(sec3, "Интервал дообучения, сек", "training_interval",
                    ai.get("training_interval", 300))

        # Безопасность
        sec4 = ctk.CTkFrame(scroll, fg_color="#12121a", corner_radius=10)
        sec4.pack(fill="x", padx=10, pady=(5, 10))
        ctk.CTkLabel(sec4, text="🛡️ БЕЗОПАСНОСТЬ", font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#ff4757").pack(anchor="w", padx=16, pady=(10, 2))
        ports = self.config.get("security", {}).get("suspicious_ports", [])
        self._field(sec4, "Подозрительные порты (через запятую)", "suspicious_ports",
                    ", ".join(str(p) for p in ports))

        # Кнопки
        btns = ctk.CTkFrame(self.win, fg_color="transparent")
        btns.pack(fill="x", padx=15, pady=10)

        ctk.CTkButton(btns, text="💾 Сохранить и применить", command=self._save_and_apply,
                      fg_color="#2ed573", text_color="#000", height=36).pack(side="left", padx=5)
        ctk.CTkButton(btns, text="Отмена", command=self._on_close,
                      fg_color="#1e1e28", text_color="#e0e0e0", height=36).pack(side="left", padx=5)

    def _get_int(self, key, default):
        try:
            return int(float(self.entries[key].get().strip()))
        except Exception:
            return default

    def _get_float(self, key, default):
        try:
            return float(self.entries[key].get().strip().replace(",", "."))
        except Exception:
            return default

    def _save_and_apply(self):
        cfg = self.config

        cfg["ping_target"] = self.entries["ping_target"].get().strip() or "8.8.8.8"
        cfg["update_interval"] = max(250, self._get_int("update_interval", 1000))
        cfg["db_cleanup_days"] = max(1, self._get_int("db_cleanup_days", 30))
        cfg["theme"] = self.theme_menu.get()
        cfg["sniffer_mode"] = self.sniffer_menu.get()

        cfg.setdefault("alert_thresholds", {})
        cfg["alert_thresholds"]["ping_high"] = self._get_float("th_ping_high", 150)
        cfg["alert_thresholds"]["jitter_high"] = self._get_float("th_jitter_high", 30)
        cfg["alert_thresholds"]["loss_high"] = self._get_float("th_loss_high", 2)
        cfg["alert_thresholds"]["loss_critical"] = self._get_float("th_loss_critical", 5)

        cfg.setdefault("ai", {})
        cfg["ai"]["enabled"] = bool(self.ai_switch_var.get())
        cfg["ai"]["anomaly_threshold"] = min(0.95, max(0.1, self._get_float("anomaly_threshold", 0.6)))
        cfg["ai"]["training_interval"] = max(60, self._get_int("training_interval", 300))

        raw_ports = self.entries["suspicious_ports"].get()
        try:
            cfg.setdefault("security", {})["suspicious_ports"] = [
                int(p.strip()) for p in raw_ports.split(",") if p.strip().isdigit()
            ]
        except Exception:
            pass

        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
            logger.info("Конфигурация сохранена в config.json")
        except Exception as e:
            logger.error(f"Ошибка сохранения конфига: {e}")

        # Живое применение без перезапуска
        try:
            import customtkinter as _ctk
            _ctk.set_appearance_mode(cfg["theme"])
        except Exception:
            pass

        if hasattr(self.app, "pinger") and self.app.pinger:
            self.app.pinger.set_target(cfg["ping_target"])
            self.app.pinger.set_thresholds(cfg["alert_thresholds"])

        if hasattr(self.app, "ai_orchestrator") and self.app.ai_orchestrator:
            self.app.ai_orchestrator.set_enabled(cfg["ai"]["enabled"])
            self.app.ai_orchestrator.traffic_agent.anomaly_threshold = cfg["ai"]["anomaly_threshold"]

        logger.info("Настройки применены на живую")
        from tkinter import messagebox
        messagebox.showinfo("Настройки", "Сохранено и применено.\n\nИзменение режима трафика\nвступит в силу после перезапуска.")
        self._on_close()

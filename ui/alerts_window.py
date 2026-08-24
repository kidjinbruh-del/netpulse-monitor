"""
Alerts Window - журнал алертов из БД с отметкой "принято"
"""

import customtkinter as ctk
import logging

logger = logging.getLogger(__name__)

SEVERITY_BY_TYPE = [
    ("КРИТ", "#ff4757", "🔴"),
    ("ПОТЕРИ", "#ff6b6b", "🟠"),
    ("AI_ANOMALY", "#9146FF", "🤖"),
    ("ДЖИТТЕР", "#f1c40f", "🟡"),
    ("ПИНГ", "#f1c40f", "🟡"),
]


def _style_alert(alert_type):
    upper = (alert_type or "").upper()
    for key, color, icon in SEVERITY_BY_TYPE:
        if key in upper:
            return color, icon
    return "#e0e0e0", "⚪"


class AlertsWindow:
    def __init__(self, parent, db_manager, on_change=None):
        self.win = ctk.CTkToplevel(parent)
        self.win.title("🔔 Журнал алертов")
        self.win.geometry("720x560")
        self.win.configure(fg_color="#0b0b10")
        self.win.protocol("WM_DELETE_WINDOW", self._on_close)
        self.win.transient(parent)

        self.db = db_manager
        self.on_change = on_change
        self.is_running = True

        self._build_ui()
        self._refresh_loop()

    def _on_close(self):
        self.is_running = False
        if self.win and self.win.winfo_exists():
            self.win.destroy()

    def destroy(self):
        self._on_close()

    def _alive(self):
        try:
            return self.is_running and self.win and self.win.winfo_exists()
        except Exception:
            return False

    def _build_ui(self):
        header = ctk.CTkFrame(self.win, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(header, text="🔔 ЖУРНАЛ АЛЕРТОВ",
                     font=ctk.CTkFont(size=18, weight="bold"),
                     text_color="#f1c40f").pack(side="left")

        self.unread_label = ctk.CTkLabel(header, text="", font=ctk.CTkFont(size=12),
                                         text_color="#ff4757")
        self.unread_label.pack(side="right")

        btns = ctk.CTkFrame(self.win, fg_color="transparent")
        btns.pack(fill="x", padx=15, pady=5)

        ctk.CTkButton(btns, text="✓ Принять все", command=self._ack_all,
                      fg_color="#2ed573", text_color="#000",
                      height=30).pack(side="left", padx=5)
        ctk.CTkButton(btns, text="🔄 Обновить", command=self._render,
                      fg_color="#1e1e28", text_color="#e0e0e0",
                      height=30).pack(side="left", padx=5)

        self.list_frame = ctk.CTkScrollableFrame(self.win, fg_color="transparent")
        self.list_frame.pack(fill="both", expand=True, padx=15, pady=10)

    def _refresh_loop(self):
        if not self._alive():
            return
        self._render()
        self.win.after(5000, self._refresh_loop)

    def _fetch(self, limit=200):
        try:
            return self.db.execute(
                """SELECT id, timestamp, alert_type, message, source, acknowledged
                   FROM alerts ORDER BY id DESC LIMIT ?""",
                (limit,), fetch=True
            ) or []
        except Exception as e:
            logger.error(f"Ошибка загрузки алертов: {e}")
            return []

    def _render(self):
        if not self._alive():
            return

        for w in self.list_frame.winfo_children():
            w.destroy()

        alerts = self._fetch()
        unread = sum(1 for a in alerts if not a.get("acknowledged"))
        total_unread = self.db.execute(
            "SELECT COUNT(*) AS n FROM alerts WHERE acknowledged = 0", fetch=True)
        unread_total = (total_unread[0]["n"] if total_unread else 0) or 0

        self.unread_label.configure(
            text=f"Непринятых: {unread_total}" if unread_total else "Все приняты ✓",
            text_color="#ff4757" if unread_total else "#2ed573"
        )

        if self.on_change:
            try:
                self.on_change(unread_total)
            except Exception:
                pass

        if not alerts:
            ctk.CTkLabel(self.list_frame, text="✅ Алертов пока нет",
                         font=ctk.CTkFont(size=13),
                         text_color="#6a6a7a").pack(pady=20)
            return

        for a in alerts:
            color, icon = _style_alert(a.get("alert_type"))
            acked = bool(a.get("acknowledged"))

            card = ctk.CTkFrame(
                self.list_frame,
                fg_color="#12121a" if acked else "#16162a",
                corner_radius=8,
                border_width=1,
                border_color="#1e1e28" if acked else "#9146FF"
            )
            card.pack(fill="x", pady=2)

            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=10, pady=(6, 1))

            ts = str(a.get("timestamp", ""))[:19].replace("T", " ")
            ctk.CTkLabel(top, text=f"{icon} {(a.get('alert_type') or '')}",
                         font=ctk.CTkFont(size=12, weight="bold"),
                         text_color="#6a6a7a" if acked else color).pack(side="left")

            right_text = f"{a.get('source', '')} • {'✓ принято' if acked else 'НОВЫЙ'}"
            ctk.CTkLabel(top, text=right_text, font=ctk.CTkFont(size=10),
                         text_color="#2ed573" if acked else "#9146FF").pack(side="right")

            bottom = ctk.CTkFrame(card, fg_color="transparent")
            bottom.pack(fill="x", padx=10, pady=(0, 6))
            msg = (a.get("message") or "")[:120]
            ctk.CTkLabel(bottom, text=f"{ts}  |  {msg}", font=ctk.CTkFont(size=11),
                         anchor="w", text_color="#e0e0e0" if not acked else "#6a6a7a").pack(
                             side="left", fill="x", expand=True)

    def _ack_all(self):
        try:
            self.db.execute("UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0")
            logger.info("Все алерты отмечены принятыми")
            self._render()
        except Exception as e:
            logger.error(f"Ошибка отметки алертов: {e}")

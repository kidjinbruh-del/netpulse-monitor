"""
Stats Window - сводная статистика из БД за 24 часа
"""

import customtkinter as ctk
import logging

logger = logging.getLogger(__name__)


def _fmt_bytes(b):
    b = float(b or 0)
    if b < 1024:
        return f"{b:.0f} B"
    if b < 1024 ** 2:
        return f"{b/1024:.1f} KB"
    if b < 1024 ** 3:
        return f"{b/1024**2:.2f} MB"
    return f"{b/1024**3:.2f} GB"


class StatsWindow:
    def __init__(self, parent, db_manager):
        self.win = ctk.CTkToplevel(parent)
        self.win.title("📊 Статистика")
        self.win.geometry("560x600")
        self.win.configure(fg_color="#0b0b10")
        self.win.protocol("WM_DELETE_WINDOW", self._on_close)
        self.win.transient(parent)

        self.db = db_manager
        self.is_running = True

        self._build_ui()
        self._render()
        self._loop()

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
        ctk.CTkLabel(header, text="📊 СТАТИСТИКА ЗА 24 ЧАСА",
                     font=ctk.CTkFont(size=17, weight="bold"),
                     text_color="#9146FF").pack(side="left")

        ctk.CTkButton(header, text="🔄", width=36, height=30,
                      command=self._render,
                      fg_color="#1e1e28").pack(side="right")

        self.body = ctk.CTkScrollableFrame(self.win, fg_color="transparent")
        self.body.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _card(self, title, value, sub="", color="#e0e0e0"):
        card = ctk.CTkFrame(self.body, fg_color="#12121a", corner_radius=12,
                            border_width=1, border_color="#1e1e28")
        card.pack(fill="x", padx=8, pady=4)

        row = ctk.CTkFrame(card, fg_color="transparent")
        row.pack(fill="x", padx=14, pady=9)

        left = ctk.CTkFrame(row, fg_color="transparent")
        left.pack(side="left")
        ctk.CTkLabel(left, text=title, font=ctk.CTkFont(size=11),
                     text_color="#6a6a7a").pack(anchor="w")
        if sub:
            ctk.CTkLabel(left, text=sub, font=ctk.CTkFont(size=10),
                         text_color="#6a6a7a").pack(anchor="w")

        ctk.CTkLabel(row, text=value, font=ctk.CTkFont(size=20, weight="bold"),
                     text_color=color).pack(side="right")

    def _section(self, text):
        ctk.CTkLabel(self.body, text=text, font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#9146FF").pack(anchor="w", padx=8, pady=(10, 3))

    def _fetch_one(self, query):
        try:
            rows = self.db.execute(query, fetch=True)
            return rows[0] if rows else {}
        except Exception as e:
            logger.error(f"Ошибка запроса статистики: {e}")
            return {}

    def _render(self):
        if not self._alive():
            return

        for w in self.body.winfo_children():
            w.destroy()

        t = self._fetch_one(
            """SELECT COUNT(*) AS n,
                      AVG(speed) AS avg_speed, MAX(speed) AS max_speed,
                      SUM(bytes_in_delta) AS total_in, SUM(bytes_out_delta) AS total_out
               FROM traffic WHERE timestamp > datetime('now','localtime','-24 hours')""")

        p = self._fetch_one(
            """SELECT COUNT(*) AS n,
                      AVG(ping_ms) AS avg_ping, MAX(ping_ms) AS max_ping,
                      SUM(loss) AS lost
               FROM pings WHERE timestamp > datetime('now','localtime','-24 hours') AND ping_ms IS NOT NULL""")

        a = self._fetch_one(
            """SELECT COUNT(*) AS n FROM alerts
               WHERE timestamp > datetime('now','localtime','-24 hours')""")

        tr = self._fetch_one("SELECT COUNT(*) AS n, MIN(timestamp) AS first_ts FROM traffic")

        self._section("📈 Трафик (24ч)")
        self._card("Средняя скорость",
                   f"{(t.get('avg_speed') or 0):.1f} KB/s",
                   sub=f"записей: {t.get('n') or 0}")
        self._card("Пиковая скорость",
                   f"{(t.get('max_speed') or 0):.0f} KB/s",
                   color="#f1c40f")
        dl, ul = _fmt_bytes(t.get("total_in")), _fmt_bytes(t.get("total_out"))
        self._card("Объём трафика", f"{dl} / {ul}", sub="download / upload",
                   color="#2ed573")

        self._section("📉 Пинг (24ч)")
        self._card("Средний пинг",
                   f"{(p.get('avg_ping') or 0):.0f} ms",
                   sub=f"замеров: {p.get('n') or 0}")
        self._card("Максимальный пинг",
                   f"{(p.get('max_ping') or 0):.0f} ms",
                   color="#f1c40f")
        lost = p.get('lost') or 0
        n = p.get('n') or 0
        loss_pct = (lost / n * 100) if n else 0
        loss_color = "#2ed573" if loss_pct < 2 else "#f1c40f" if loss_pct < 5 else "#ff4757"
        self._card("Потери пакетов", f"{loss_pct:.2f}%",
                   sub=f"потеряно: {lost} из {n}", color=loss_color)

        self._section("🔔 Алерты (24ч)")
        alerts_n = a.get('n') or 0
        alert_color = "#2ed573" if alerts_n == 0 else "#f1c40f" if alerts_n < 10 else "#ff4757"
        self._card("Сработало алертов", str(alerts_n), color=alert_color)

        self._section("🗄 База данных")
        first = str(tr.get('first_ts') or '')[:19].replace("T", " ")
        self._card("Всего записей трафика", str(tr.get('n') or 0),
                   sub=f"первая запись: {first or '—'}")

    def _loop(self):
        if not self._alive():
            return
        self.win.after(15000, self.loop_step)

    def loop_step(self):
        if not self._alive():
            return
        self._render()
        self._loop()

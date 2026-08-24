"""
AI Dashboard Window - окно управления AI агентами
"""

import customtkinter as ctk
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class AIDashboard:
    """Окно AI Control Center"""

    def __init__(self, parent, orchestrator, db_manager):
        self.win = ctk.CTkToplevel(parent)
        self.win.title("🤖 AI Control Center")
        self.win.geometry("800x700")
        self.win.configure(fg_color="#0b0b10")
        self.win.protocol("WM_DELETE_WINDOW", self._on_close)

        self.ai = orchestrator
        self.db_manager = db_manager
        self.is_running = True

        self._build_ui()
        self._start_update_loop()

    def _on_close(self):
        self.is_running = False
        if self.win and self.win.winfo_exists():
            self.win.destroy()

    def destroy(self):
        self.is_running = False
        try:
            if self.win and self.win.winfo_exists():
                self.win.destroy()
        except Exception:
            pass

    def _build_ui(self):
        header = ctk.CTkFrame(self.win, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(
            header,
            text="🤖 AI CONTROL CENTER",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#9146FF"
        ).pack(side="left")

        # Synapse статус
        status_frame = ctk.CTkFrame(self.win, fg_color="#12121a", corner_radius=10)
        status_frame.pack(fill="x", padx=15, pady=5)

        self.synapse_status = ctk.CTkLabel(
            status_frame,
            text="🔌 Synapse: Подключение...",
            font=ctk.CTkFont(size=12),
            text_color="#f1c40f"
        )
        self.synapse_status.pack(pady=5)

        # Статистика
        stats_frame = ctk.CTkFrame(self.win, fg_color="#12121a", corner_radius=10)
        stats_frame.pack(fill="x", padx=15, pady=5)

        stats_grid = ctk.CTkFrame(stats_frame, fg_color="transparent")
        stats_grid.pack(fill="x", padx=10, pady=10)

        self.ai_stats_labels = {}
        stats_items = [
            ("total_analyzed", "📊 Всего анализов"),
            ("anomalies_detected", "🚨 Аномалий"),
            ("avg_confidence", "📈 Средняя уверенность"),
            ("model_trained", "🧠 Модель обучена")
        ]

        for i, (key, label) in enumerate(stats_items):
            frame = ctk.CTkFrame(stats_grid, fg_color="transparent")
            frame.grid(row=i // 2, column=i % 2, padx=10, pady=5, sticky="ew")

            ctk.CTkLabel(
                frame,
                text=label,
                font=ctk.CTkFont(size=11),
                text_color="#6a6a7a"
            ).pack(anchor="w")

            self.ai_stats_labels[key] = ctk.CTkLabel(
                frame,
                text="...",
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color="#e0e0e0"
            )
            self.ai_stats_labels[key].pack(anchor="w")

        # Аномалии
        anomalies_frame = ctk.CTkFrame(self.win, fg_color="#12121a", corner_radius=10)
        anomalies_frame.pack(fill="both", expand=True, padx=15, pady=5)

        ctk.CTkLabel(
            anomalies_frame,
            text="🚨 ПОСЛЕДНИЕ АНОМАЛИИ",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#ff4757"
        ).pack(anchor="w", padx=12, pady=8)

        self.anomalies_list = ctk.CTkScrollableFrame(anomalies_frame, fg_color="transparent")
        self.anomalies_list.pack(fill="both", expand=True, padx=12, pady=8)

        # Прогнозы
        predictions_frame = ctk.CTkFrame(self.win, fg_color="#12121a", corner_radius=10)
        predictions_frame.pack(fill="x", padx=15, pady=5)

        ctk.CTkLabel(
            predictions_frame,
            text="🔮 ПРОГНОЗЫ",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#f1c40f"
        ).pack(anchor="w", padx=12, pady=8)

        self.predictions_list = ctk.CTkFrame(predictions_frame, fg_color="transparent")
        self.predictions_list.pack(fill="x", padx=12, pady=8)

        # Кнопки
        btn_frame = ctk.CTkFrame(self.win, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=10)

        self.retrain_btn = ctk.CTkButton(
            btn_frame,
            text="🧠 Переобучить модель",
            command=self._retrain_model,
            fg_color="#9146FF",
            hover_color="#7b3fc0",
            height=35,
            state="disabled"
        )
        self.retrain_btn.pack(side="left", padx=5)

        ctk.CTkButton(
            btn_frame,
            text="🔄 Обновить",
            command=self._refresh,
            fg_color="#1e1e28",
            text_color="#e0e0e0",
            height=35
        ).pack(side="left", padx=5)

    def _alive(self):
        try:
            return self.is_running and self.win and self.win.winfo_exists()
        except Exception:
            return False

    def _start_update_loop(self):
        if not self._alive():
            return

        self._update_ui()
        self.win.after(2000, self._start_update_loop)

    def _update_ui(self):
        if not self._alive():
            return

        try:
            if self.ai.synapse_agent:
                synapse_stats = self.ai.synapse_agent.get_stats()
                if synapse_stats.get('connected'):
                    self.synapse_status.configure(
                        text=f"🔌 Synapse: Подключен ({synapse_stats.get('peers', 0)} пиров)",
                        text_color="#2ed573"
                    )
                else:
                    self.synapse_status.configure(
                        text="🔌 Synapse: Отключен",
                        text_color="#ff4757"
                    )

            stats = self.ai.traffic_agent.get_stats()
            for key, label in self.ai_stats_labels.items():
                if key == "model_trained":
                    value = "✅ Да" if stats.get(key) else "❌ Нет"
                    color = "#2ed573" if stats.get(key) else "#ff4757"
                    if stats.get(key) and str(self.retrain_btn.cget("state")) == "disabled":
                        self.retrain_btn.configure(state="normal")
                elif key == "avg_confidence":
                    value = f"{stats.get(key, 0):.2f}"
                    color = "#f1c40f"
                else:
                    value = str(stats.get(key, 0))
                    color = "#e0e0e0"

                label.configure(text=value, text_color=color)

            self._update_anomalies()
            self._update_predictions()

        except Exception as e:
            logger.error(f"Ошибка обновления AI Dashboard: {e}")

    def _update_anomalies(self):
        for widget in self.anomalies_list.winfo_children():
            widget.destroy()

        anomalies = self.ai.get_anomalies(10)

        if not anomalies:
            ctk.CTkLabel(
                self.anomalies_list,
                text="✅ Аномалий не обнаружено",
                font=ctk.CTkFont(size=12),
                text_color="#2ed573"
            ).pack(pady=10)
            return

        for anomaly in anomalies:
            frame = ctk.CTkFrame(self.anomalies_list, fg_color="#1a1a2a", corner_radius=8)
            frame.pack(fill="x", pady=3)

            ctk.CTkLabel(
                frame,
                text=str(anomaly.get('timestamp', ''))[:19],
                font=ctk.CTkFont(size=10),
                text_color="#6a6a7a"
            ).pack(anchor="w", padx=10, pady=(5, 0))

            features = anomaly.get('features', {})
            confidence = anomaly.get('confidence', 0)
            severity = "🔴" if confidence > 0.8 else "🟡"

            details = []
            if 'speed' in features:
                details.append(f"Скорость: {float(features['speed']):.1f} KB/s")
            if 'ping_ms' in features:
                details.append(f"Пинг: {float(features['ping_ms']):.0f}ms")
            details.append(f"Уверенность: {confidence:.2f}")

            ctk.CTkLabel(
                frame,
                text=f"{severity} {' | '.join(details)}",
                font=ctk.CTkFont(size=11),
                text_color="#e0e0e0"
            ).pack(anchor="w", padx=10, pady=(0, 5))

    def _update_predictions(self):
        for widget in self.predictions_list.winfo_children():
            widget.destroy()

        predictions = self.ai.get_predictions(10)

        if not predictions:
            ctk.CTkLabel(
                self.predictions_list,
                text="⏳ Нет прогнозов",
                font=ctk.CTkFont(size=12),
                text_color="#6a6a7a"
            ).pack(pady=5)
            return

        last = predictions[-1]
        if 'error' not in last:
            frame = ctk.CTkFrame(self.predictions_list, fg_color="transparent")
            frame.pack(fill="x")

            metric = last.get('metric', 'speed')
            current = last.get('current', 0)
            predicted = last.get('predicted', 0)
            trend = last.get('trend', 0) * 100

            trend_symbol = "⬆️" if trend > 0 else "⬇️" if trend < 0 else "➡️"
            trend_color = "#2ed573" if trend > 0 else "#ff4757" if trend < 0 else "#f1c40f"

            ctk.CTkLabel(
                frame,
                text=f"{trend_symbol} {metric.upper()}: {current:.1f} → {predicted:.1f} (тренд: {trend:+.1f}%)",
                font=ctk.CTkFont(size=12),
                text_color=trend_color
            ).pack(side="left")

    def _retrain_model(self):
        """Переобучение модели на исторических данных из БД"""
        if not self.db_manager:
            return

        try:
            data = self.db_manager.execute(
                """SELECT speed, bytes_in_delta AS bytes_in, ping_ms
                FROM traffic
                 WHERE timestamp > datetime('now', 'localtime', '-7 days')
                ORDER BY timestamp DESC
                LIMIT 2000""",
                fetch=True
            )

            if not data or len(data) < 10:
                from tkinter import messagebox
                messagebox.showwarning("Недостаточно данных", "В БД недостаточно записей для обучения (нужно ≥ 10)")
                return

            success = self.ai.train_model(data)
            if success:
                from tkinter import messagebox
                messagebox.showinfo("Успех", f"Модель переобучена на {len(data)} записях")
            else:
                from tkinter import messagebox
                messagebox.showwarning("Не удалось", "Не удалось переобучить модель (см. лог)")
        except Exception as e:
            logger.error(f"Ошибка переобучения: {e}")
            from tkinter import messagebox
            messagebox.showerror("Ошибка", f"Ошибка переобучения: {e}")

    def _refresh(self):
        self._update_ui()

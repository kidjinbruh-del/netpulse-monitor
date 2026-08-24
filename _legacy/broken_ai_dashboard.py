"""
AI Dashboard для Network Monitor Pro
"""

import customtkinter as ctk
import tkinter as tk
from datetime import datetime
import json
from typing import Dict, List

class AIDashboard:
    def __init__(self, parent, ai_orchestrator):
        self.win = ctk.CTkToplevel(parent)
        self.win.title("🤖 AI Control Center")
        self.win.geometry("800x700")
        self.win.configure(fg_color="#0b0b10")
        self.win.protocol("WM_DELETE_WINDOW", self._on_close)
        
        self.ai = ai_orchestrator
        self.is_running = True
        
        self._build_ui()
        self._start_update_loop()
    
    def _on_close(self):
        self.is_running = False
        self.win.destroy()
    
    def _build_ui(self):
        # Header
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
            frame.grid(row=i//2, column=i%2, padx=10, pady=5, sticky="ew")
            
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
        
        self.anomalies_list = ctk.CTkScrollableFrame(
            anomalies_frame,
            fg_color="transparent"
        )
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
        
        self.predictions_list = ctk.CTkFrame(
            predictions_frame,
            fg_color="transparent"
        )
        self.predictions_list.pack(fill="x", padx=12, pady=8)
        
        # Кнопки управления
        btn_frame = ctk.CTkFrame(self.win, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkButton(
            btn_frame,
            text="🧠 Переобучить модель",
            command=self._retrain_model,
            fg_color="#9146FF",
            hover_color="#7b3fc0",
            height=35
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            btn_frame,
            text="🔄 Обновить",
            command=self._refresh,
            fg_color="#1e1e28",
            text_color="#e0e0e0",
            height=35
        ).pack(side="left", padx=5)
    
    def _start_update_loop(self):
        if not self.is_running:
            return
        
        self._update_ui()
        self.win.after(2000, self._start_update_loop)
    
    def _update_ui(self):
        try:
            # Обновление Synapse статуса
            if self.ai.synapse_agent:
                synapse_stats = self.ai.get_synapse_stats()
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
            
            # Обновление статистики AI
            stats = self.ai.traffic_agent.get_stats()
            for key, label in self.ai_stats_labels.items():
                if key == "model_trained":
                    value = "✅ Да" if stats.get(key) else "❌ Нет"
                    color = "#2ed573" if stats.get(key) else "#ff4757"
                elif key == "avg_confidence":
                    value = f"{stats.get(key, 0):.2f}"
                    color = "#f1c40f"
                else:
                    value = str(stats.get(key, 0))
                    color = "#e0e0e0"
                
                label.configure(text=value, text_color=color)
            
            # Обновление списка аномалий
            self._update_anomalies()
            
            # Обновление прогнозов
            self._update_predictions()
            
        except Exception as e:
            logger.error(f"Ошибка обновления AI Dashboard: {e}")
    
    def _update_anomalies(self):
        """Обновление списка аномалий"""
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
            frame = ctk.CTkFrame(
                self.anomalies_list,
                fg_color="#1a1a2a",
                corner_radius=8
            )
            frame.pack(fill="x", pady=3)
            
            # Время
            time_label = ctk.CTkLabel(
                frame,
                text=anomaly.get('timestamp', '')[:19],
                font=ctk.CTkFont(size=10),
                text_color="#6a6a7a"
            )
            time_label.pack(anchor="w", padx=10, pady=(5, 0))
            
            # Детали аномалии
            features = anomaly.get('features', {})
            confidence = anomaly.get('confidence', 0)
            severity = "🔴" if confidence > 0.8 else "🟡"
            
            details = [
                f"Скорость: {features.get('speed', 0):.1f} KB/s",
                f"Пинг: {features.get('ping_ms', 0):.0f}ms",
                f"Уверенность: {confidence:.2f}"
            ]
            
            ctk.CTkLabel(
                frame,
                text=f"{severity} {' | '.join(details)}",
                font=ctk.CTkFont(size=11),
                text_color="#e0e0e0"
            ).pack(anchor="w", padx=10, pady=(0, 5))
    
    def _update_predictions(self):
        """Обновление списка прогнозов"""
        for widget in self.predictions_list.winfo_children():
            widget.destroy()
        
        predictions = self.ai.get_predictions()
        
        if not predictions:
            ctk.CTkLabel(
                self.predictions_list,
                text="⏳ Нет прогнозов",
                font=ctk.CTkFont(size=12),
                text_color="#6a6a7a"
            ).pack(pady=5)
            return
        
        # Показываем последний прогноз
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
        """Переобучение модели"""
        try:
            # Получаем данные из БД
            data = db_manager.execute(
                """SELECT speed, bytes_in_delta, bytes_out_delta, ping_ms
                FROM traffic t
                LEFT JOIN pings p ON date(t.timestamp) = date(p.timestamp)
                ORDER BY t.timestamp DESC 
                LIMIT 1000""",
                fetch=True
            )
            
            if data:
                historical = [
                    {
                        "speed": row['speed'],
                        "bytes_in": row['bytes_in_delta'],
                        "bytes_out": row['bytes_out_delta'],
                        "ping_ms": row.get('ping_ms', 0)
                    }
                    for row in data
                ]
                
                success = self.ai.train_model(historical)
                if success:
                    messagebox.showinfo("Успех", "Модель успешно переобучена!")
                else:
                    messagebox.showwarning("Предупреждение", "Не удалось переобучить модель")
        except Exception as e:
            logger.error(f"Ошибка переобучения: {e}")
            messagebox.showerror("Ошибка", f"Ошибка переобучения: {e}")
    
    def _refresh(self):
        """Принудительное обновление"""
        self._update_ui()

# ========== ДОБАВЛЕНИЕ КНОПКИ В ГЛАВНОЕ ОКНО ==========
# В App._build_ui(), в btn_row:
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

# В App:
def _open_ai_dashboard(self):
    if not hasattr(self, '_ai_dashboard') or not self._ai_dashboard.win.winfo_exists():
        self._ai_dashboard = AIDashboard(self.root, self.ai_orchestrator)
    else:
        self._ai_dashboard.win.focus()
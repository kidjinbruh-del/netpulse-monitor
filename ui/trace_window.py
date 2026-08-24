"""
Trace Window - окно трассировки сети
"""

import customtkinter as ctk
import tkinter as tk
import threading
import socket
import time
from datetime import datetime
import logging

from core import Tracer

logger = logging.getLogger(__name__)

class TraceWindow:
    def __init__(self, parent, config=None):
        self.win = ctk.CTkToplevel(parent)
        self.win.title("🌍 Трассировка")
        self.win.geometry("650x600")
        self.win.configure(fg_color="#0b0b10")
        self.win.protocol("WM_DELETE_WINDOW", self._on_close)
        
        self.config = config or {}
        self.tracer = Tracer()
        self.results_frame = None
        self.progress = None
        self.status_lbl = None
        self.is_running = False
        
        self._build_ui()
        self.win.after(500, self.run_trace)
    
    def _safe_update(self, func):
        try:
            if hasattr(self, 'win') and self.win and self.win.winfo_exists():
                func()
        except:
            pass
    
    def _on_close(self):
        self.is_running = False
        if hasattr(self, 'tracer'):
            self.tracer.stop()
        if self.win:
            self.win.destroy()
    
    def _build_ui(self):
        # Header
        header = ctk.CTkFrame(self.win, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(
            header,
            text="🌍 ТРАССИРОВКА СЕТИ",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#9146FF"
        ).pack(side="left")
        
        # Кнопки
        btn_frame = ctk.CTkFrame(self.win, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkButton(
            btn_frame,
            text="🚀 Трассировать все",
            command=self.run_trace,
            fg_color="#9146FF",
            height=30
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            btn_frame,
            text="🔍 Лучший DNS",
            command=self.find_dns,
            fg_color="#f1c40f",
            text_color="#000",
            height=30
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            btn_frame,
            text="🏥 Проверка сервисов",
            command=self.check_health,
            fg_color="#2ed573",
            text_color="#000",
            height=30
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            btn_frame,
            text="⏱ DNS-резолв",
            command=self.check_dns_resolve,
            fg_color="#9146FF",
            height=30
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            btn_frame,
            text="🔄 Обновить",
            command=self.refresh,
            fg_color="#1e1e28",
            text_color="#e0e0e0",
            height=30
        ).pack(side="left", padx=5)
        
        # Прогресс
        self.progress = ctk.CTkProgressBar(
            self.win,
            fg_color="#1e1e28",
            progress_color="#9146FF",
            height=6
        )
        self.progress.pack(fill="x", padx=15, pady=5)
        self.progress.set(0)
        
        # Статус
        self.status_lbl = ctk.CTkLabel(
            self.win,
            text="Готов к работе",
            font=ctk.CTkFont(size=12),
            text_color="#6a6a7a"
        )
        self.status_lbl.pack(pady=5)
        
        # Результаты
        self.results_frame = ctk.CTkScrollableFrame(
            self.win,
            fg_color="transparent"
        )
        self.results_frame.pack(fill="both", expand=True, padx=15, pady=10)
    
    def refresh(self):
        """Обновление результатов"""
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        self.run_trace()
    
    def run_trace(self):
        """Запуск трассировки"""
        if self.is_running:
            return
        
        self.is_running = True
        self.progress.set(0)
        self._safe_update(lambda: self.status_lbl.configure(text="⏳ Трассировка..."))
        
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        
        threading.Thread(target=self._trace_thread, daemon=True).start()
    
    def _trace_thread(self):
        try:
            def callback(name, result, progress):
                self._safe_update(lambda: self._update_progress(name, result, progress))
            
            results = self.tracer.trace_all(callback)
            self._safe_update(lambda: self._show_results(results))
        except Exception as e:
            logger.error(f"Ошибка трассировки: {e}")
            self._safe_update(lambda: self.status_lbl.configure(
                text=f"❌ Ошибка: {e}",
                text_color="#ff4757"
            ))
        finally:
            self.is_running = False
    
    def _update_progress(self, name, result, progress):
        """Обновление прогресса"""
        self.progress.set(progress)
        avg_ms = result.get('avg_ms', 999)
        total_hops = result.get('total_hops', 0)
        self.status_lbl.configure(text=f"⏳ {name}: {avg_ms:.0f}ms ({total_hops} хопов)")
    
    def find_dns(self):
        """Поиск лучшего DNS"""
        if self.is_running:
            return
        
        self.is_running = True
        self._safe_update(lambda: self.status_lbl.configure(text="🔍 Поиск лучшего DNS..."))
        
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        
        threading.Thread(target=self._dns_thread, daemon=True).start()
    
    def _dns_thread(self):
        try:
            def progress_callback(value):
                self._safe_update(lambda: self.progress.set(value))
            
            best = self.tracer.find_best_dns(progress_callback)
            self._safe_update(lambda: self._show_dns_result(best))
        except Exception as e:
            logger.error(f"Ошибка поиска DNS: {e}")
            self._safe_update(lambda: self.status_lbl.configure(
                text=f"❌ Ошибка: {e}",
                text_color="#ff4757"
            ))
        finally:
            self.is_running = False
    
    def check_health(self):
        """Проверка здоровья сервисов"""
        if self.is_running:
            return
        
        self.is_running = True
        self._safe_update(lambda: self.status_lbl.configure(text="🏥 Проверка сервисов..."))
        
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        
        threading.Thread(target=self._health_thread, daemon=True).start()
    
    def _health_thread(self):
        try:
            services = self.config.get("targets", {}).get("services", {"Google": "8.8.8.8"})
            health = {}
            
            for name, host in services.items():
                try:
                    start = time.time()
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((host, 443))
                    latency = (time.time() - start) * 1000
                    sock.close()
                    health[name] = {"status": "✅", "latency_ms": round(latency, 1)}
                except:
                    health[name] = {"status": "❌", "latency_ms": None}
            
            self._safe_update(lambda: self._show_health(health))
        except Exception as e:
            logger.error(f"Ошибка проверки здоровья: {e}")
            self._safe_update(lambda: self.status_lbl.configure(
                text=f"❌ Ошибка: {e}",
                text_color="#ff4757"
            ))
        finally:
            self.is_running = False
    
    def _show_dns_result(self, best):
        """Отображение результата DNS"""
        self.status_lbl.configure(text="✅ Готово", text_color="#2ed573")
        self.progress.set(1.0)
        
        card = ctk.CTkFrame(
            self.results_frame,
            fg_color="#12121a",
            corner_radius=12,
            border_width=1,
            border_color="#1e1e28"
        )
        card.pack(fill="x", pady=10)
        
        ctk.CTkLabel(
            card,
            text="🏆 ЛУЧШИЙ DNS",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#f1c40f"
        ).pack(pady=10)
        
        if best and best.get('ping', 999) < 999:
            ctk.CTkLabel(
                card,
                text=f"{best['name']} ({best['ip']})",
                font=ctk.CTkFont(size=20, weight="bold"),
                text_color="#2ed573"
            ).pack()
            ctk.CTkLabel(
                card,
                text=f"Пинг: {best['ping']:.0f}ms",
                font=ctk.CTkFont(size=16),
                text_color="#e0e0e0"
            ).pack(pady=5)
        else:
            ctk.CTkLabel(
                card,
                text="❌ Не удалось найти доступный DNS",
                font=ctk.CTkFont(size=16),
                text_color="#ff4757"
            ).pack(pady=10)
    
    def _show_health(self, health):
        """Отображение здоровья сервисов"""
        self.status_lbl.configure(text="✅ Проверка завершена", text_color="#2ed573")
        self.progress.set(1.0)
        
        for name, data in health.items():
            color = "#2ed573" if "✅" in data["status"] else "#ff4757"
            
            card = ctk.CTkFrame(
                self.results_frame,
                fg_color="#12121a",
                corner_radius=10,
                border_width=1,
                border_color="#1e1e28"
            )
            card.pack(fill="x", pady=3)
            
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=8)
            
            ctk.CTkLabel(
                row,
                text=name,
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="#e0e0e0"
            ).pack(side="left")
            
            text = f"{data['status']} {data['latency_ms']:.0f}ms" if data['latency_ms'] else data['status']
            ctk.CTkLabel(
                row,
                text=text,
                font=ctk.CTkFont(size=13),
                text_color=color
            ).pack(side="right")
    
    def check_dns_resolve(self):
        """Измерение времени DNS-резолва известных доменов"""
        if self.is_running:
            return

        self.is_running = True
        self._safe_update(lambda: self.status_lbl.configure(text="⏱ Проверка DNS-резолва..."))

        for widget in self.results_frame.winfo_children():
            widget.destroy()

        threading.Thread(target=self._dns_resolve_thread, daemon=True).start()

    def _dns_resolve_thread(self):
        try:
            import socket

            hosts = set()
            for host in (self.config.get("targets", {}).get("services", {}) or {}).values():
                if host and not host.replace(".", "").isdigit():
                    hosts.add(host)
            hosts.update(["google.com", "youtube.com", "vk.com", "github.com"])

            results = []
            for host in sorted(hosts):
                try:
                    start = time.perf_counter()
                    infos = socket.getaddrinfo(host, 443, socket.AF_INET)
                    elapsed_ms = (time.perf_counter() - start) * 1000
                    ip = infos[0][4][0] if infos else "?"
                    results.append({"host": host, "ip": ip, "ms": elapsed_ms})
                except Exception:
                    results.append({"host": host, "ip": None, "ms": None})

            self._safe_update(lambda: self._show_dns_resolve(results))
        except Exception as e:
            logger.error(f"Ошибка DNS-резолва: {e}")
            self._safe_update(lambda: self.status_lbl.configure(
                text=f"❌ Ошибка: {e}",
                text_color="#ff4757"
            ))
        finally:
            self.is_running = False

    def _show_dns_resolve(self, results):
        self.status_lbl.configure(
            text=f"✅ Проверено доменов: {len(results)}",
            text_color="#2ed573"
        )
        self.progress.set(1.0)

        ok = [r for r in results if r["ms"] is not None]
        if ok:
            best = min(ok, key=lambda r: r["ms"])
            ctk.CTkLabel(
                self.results_frame,
                text=f"🏆 Быстрее всех: {best['host']} ({best['ms']:.0f}ms)",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="#f1c40f"
            ).pack(anchor="w", padx=5, pady=(8, 4))

        for r in results:
            card = ctk.CTkFrame(self.results_frame, fg_color="#12121a",
                                corner_radius=10, border_width=1,
                                border_color="#1e1e28")
            card.pack(fill="x", pady=2)

            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=7)

            ctk.CTkLabel(row, text=r["host"], font=ctk.CTkFont(size=12, weight="bold"),
                         text_color="#e0e0e0").pack(side="left")
            ctk.CTkLabel(row, text=r["ip"] or "не резолвится",
                         font=ctk.CTkFont(size=10),
                         text_color="#6a6a7a").pack(side="right", padx=10)

            if r["ms"] is None:
                color, text = "#ff4757", "❌"
            elif r["ms"] < 50:
                color, text = "#2ed573", f"{r['ms']:.1f}ms"
            elif r["ms"] < 150:
                color, text = "#f1c40f", f"{r['ms']:.1f}ms"
            else:
                color, text = "#ff4757", f"{r['ms']:.1f}ms"

            ctk.CTkLabel(row, text=text, font=ctk.CTkFont(size=12, weight="bold"),
                         text_color=color).pack(side="right")

    def _show_results(self, results):
        """Отображение результатов трассировки"""
        self.status_lbl.configure(text="✅ Трассировка завершена", text_color="#2ed573")
        self.progress.set(1.0)
        
        for name, data in results.items():
            avg_ms = data.get('avg_ms', 999)
            
            if avg_ms < 50:
                color = "#2ed573"
                status = "Отлично"
            elif avg_ms < 150:
                color = "#f1c40f"
                status = "Средне"
            else:
                color = "#ff4757"
                status = "Плохо"
            
            card = ctk.CTkFrame(
                self.results_frame,
                fg_color="#12121a",
                corner_radius=10,
                border_width=1,
                border_color="#1e1e28"
            )
            card.pack(fill="x", pady=3)
            
            row = ctk.CTkFrame(card, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=8)
            
            ctk.CTkLabel(
                row,
                text=name,
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="#e0e0e0"
            ).pack(side="left")
            
            ctk.CTkLabel(
                row,
                text=f"{avg_ms:.0f}ms - {status}",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color=color
            ).pack(side="right")
            
            bar = ctk.CTkProgressBar(
                card,
                fg_color="#1e1e28",
                progress_color=color,
                height=4
            )
            bar.pack(fill="x", padx=12, pady=(0, 5))
            bar.set(min(avg_ms / 300, 1.0))
            
            ctk.CTkLabel(
                card,
                text=f"Хопов: {data.get('total_hops', 0)} | IP: {data.get('target', 'Unknown')}",
                font=ctk.CTkFont(size=10),
                text_color="#6a6a7a"
            ).pack(anchor="w", padx=12, pady=(0, 8))
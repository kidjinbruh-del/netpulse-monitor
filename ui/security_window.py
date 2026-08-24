"""
Security Window - окно сканирования безопасности
"""

import customtkinter as ctk
import threading
import os
from datetime import datetime
from tkinter import filedialog, messagebox
import logging

from core import SecurityScanner

logger = logging.getLogger(__name__)

class SecurityWindow:
    def __init__(self, parent, config=None):
        self.win = ctk.CTkToplevel(parent)
        self.win.title("🛡️ Безопасность")
        self.win.geometry("700x650")
        self.win.configure(fg_color="#0b0b10")
        self.win.protocol("WM_DELETE_WINDOW", self._on_close)
        
        self.config = config or {}
        self.results_frame = None
        self.status_lbl = None
        self.threat_count = None
        self.is_running = False
        
        self._build_ui()
        self.win.after(500, self.run_scan)
    
    def _safe_update(self, func):
        try:
            if self.win and self.win.winfo_exists():
                func()
        except:
            pass
    
    def _on_close(self):
        self.is_running = False
        if self.win:
            self.win.destroy()
    
    def _build_ui(self):
        # Header
        header = ctk.CTkFrame(self.win, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(
            header,
            text="🛡️ СКАНЕР БЕЗОПАСНОСТИ",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#ff4757"
        ).pack(side="left")
        
        # Кнопки
        btn_frame = ctk.CTkFrame(self.win, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkButton(
            btn_frame,
            text="🔍 Полное сканирование",
            command=self.run_scan,
            fg_color="#ff4757",
            hover_color="#ee5a24",
            height=35
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            btn_frame,
            text="🔄 Быстрая проверка",
            command=self.quick_scan,
            fg_color="#f1c40f",
            text_color="#000",
            height=35
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            btn_frame,
            text="📄 Экспорт отчёта",
            command=self.export_report,
            fg_color="#2ed573",
            text_color="#000",
            height=35
        ).pack(side="right", padx=5)
        
        ctk.CTkButton(
            btn_frame,
            text="🔄 Обновить",
            command=self.refresh,
            fg_color="#1e1e28",
            text_color="#e0e0e0",
            height=35
        ).pack(side="right", padx=5)
        
        # Статус
        self.status_frame = ctk.CTkFrame(
            self.win,
            fg_color="#12121a",
            corner_radius=10,
            border_width=1,
            border_color="#1e1e28"
        )
        self.status_frame.pack(fill="x", padx=15, pady=5)
        
        self.status_lbl = ctk.CTkLabel(
            self.status_frame,
            text="Готов к сканированию",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#e0e0e0"
        )
        self.status_lbl.pack(pady=10)
        
        self.threat_count = ctk.CTkLabel(
            self.status_frame,
            text="",
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color="#2ed573"
        )
        self.threat_count.pack(pady=(0, 10))
        
        # Результаты
        self.results_frame = ctk.CTkScrollableFrame(
            self.win,
            fg_color="transparent"
        )
        self.results_frame.pack(fill="both", expand=True, padx=15, pady=10)
        
        # Инфо
        info = ctk.CTkFrame(self.win, fg_color="#12121a", corner_radius=8)
        info.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(
            info,
            text="💡 Запускайте сканирование регулярно для выявления угроз",
            font=ctk.CTkFont(size=10),
            text_color="#6a6a7a"
        ).pack(pady=5)
    
    def refresh(self):
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        self.run_scan()
    
    def run_scan(self):
        if self.is_running:
            return
        
        self.is_running = True
        self._safe_update(lambda: self.status_lbl.configure(
            text="⏳ Полное сканирование...",
            text_color="#f1c40f"
        ))
        self._safe_update(lambda: self.threat_count.configure(text=""))
        
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        
        threading.Thread(target=self._full_scan_thread, daemon=True).start()
    
    def quick_scan(self):
        if self.is_running:
            return
        
        self.is_running = True
        self._safe_update(lambda: self.status_lbl.configure(
            text="⏳ Быстрая проверка...",
            text_color="#f1c40f"
        ))
        self._safe_update(lambda: self.threat_count.configure(text=""))
        
        for widget in self.results_frame.winfo_children():
            widget.destroy()
        
        threading.Thread(target=self._quick_scan_thread, daemon=True).start()
    
    def _full_scan_thread(self):
        try:
            suspicious_ports = self.config.get("security", {}).get("suspicious_ports", [4444, 1337, 8080])
            results = SecurityScanner.run_full_scan(suspicious_ports)
            self._safe_update(lambda: self._show_results(results, "полное"))
        except Exception as e:
            logger.error(f"Ошибка сканирования: {e}")
            self._safe_update(lambda: self.status_lbl.configure(
                text=f"❌ Ошибка: {e}",
                text_color="#ff4757"
            ))
        finally:
            self.is_running = False
    
    def _quick_scan_thread(self):
        try:
            suspicious_ports = self.config.get("security", {}).get("suspicious_ports", [4444, 1337, 8080])
            results = {
                "Подозрительные соединения": SecurityScanner.detect_suspicious_connections(suspicious_ports),
                "HOSTS файл": SecurityScanner.check_hosts_file(),
            }
            self._safe_update(lambda: self._show_results(results, "быстрая"))
        except Exception as e:
            logger.error(f"Ошибка быстрой проверки: {e}")
            self._safe_update(lambda: self.status_lbl.configure(
                text=f"❌ Ошибка: {e}",
                text_color="#ff4757"
            ))
        finally:
            self.is_running = False
    
    def _show_results(self, results, scan_type):
        total_threats = sum(len(v) for v in results.values())
        
        if total_threats == 0:
            self.status_lbl.configure(text="✅ Угроз не обнаружено", text_color="#2ed573")
            self.threat_count.configure(text="🛡️ Чисто", text_color="#2ed573")
        elif total_threats < 3:
            self.status_lbl.configure(text=f"⚠️ Подозрений: {total_threats}", text_color="#f1c40f")
            self.threat_count.configure(text=f"{total_threats} 🔶", text_color="#f1c40f")
        else:
            self.status_lbl.configure(text=f"🚨 УГРОЗ: {total_threats}", text_color="#ff4757")
            self.threat_count.configure(text=f"{total_threats} 🔴", text_color="#ff4757")
        
        for category, threats in results.items():
            if not threats:
                continue
            
            cat_frame = ctk.CTkFrame(self.results_frame, fg_color="transparent")
            cat_frame.pack(fill="x", pady=(10, 5))
            
            ctk.CTkLabel(
                cat_frame,
                text=f"📋 {category} ({len(threats)})",
                font=ctk.CTkFont(size=14, weight="bold"),
                text_color="#9146FF"
            ).pack(anchor="w")
            
            for threat in threats:
                severity = threat.get("severity", "LOW")
                
                if severity == "CRITICAL":
                    color = "#ff4757"
                    icon = "🔴"
                elif severity == "HIGH":
                    color = "#ff6b6b"
                    icon = "🟠"
                elif severity == "MEDIUM":
                    color = "#f1c40f"
                    icon = "🟡"
                else:
                    color = "#2ed573"
                    icon = "🟢"
                
                card = ctk.CTkFrame(
                    self.results_frame,
                    fg_color="#12121a",
                    corner_radius=8,
                    border_width=1,
                    border_color="#1e1e28"
                )
                card.pack(fill="x", pady=2)
                
                line1 = ctk.CTkFrame(card, fg_color="transparent")
                line1.pack(fill="x", padx=10, pady=(8, 2))
                
                process = threat.get("process", threat.get("domain", threat.get("entry", "Неизвестно")))
                ctk.CTkLabel(
                    line1,
                    text=f"{icon} {process}",
                    font=ctk.CTkFont(size=12, weight="bold"),
                    text_color="#e0e0e0"
                ).pack(side="left")
                
                ctk.CTkLabel(
                    line1,
                    text=severity,
                    font=ctk.CTkFont(size=10),
                    text_color=color
                ).pack(side="right")
                
                line2 = ctk.CTkFrame(card, fg_color="transparent")
                line2.pack(fill="x", padx=10, pady=(0, 8))
                
                reason = threat.get("reason", "")
                extra = ""
                if "remote" in threat:
                    extra = f" → {threat['remote']}"
                if "redirects_to" in threat:
                    extra = f" → {threat['redirects_to']}"
                if "connections" in threat:
                    extra = f" ({threat['connections']} соед.)"
                if "line" in threat:
                    extra = f" (строка {threat['line']})"
                
                ctk.CTkLabel(
                    line2,
                    text=f"{reason}{extra}",
                    font=ctk.CTkFont(size=10),
                    text_color="#6a6a7a"
                ).pack(side="left")
    
    def export_report(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Текстовый файл", "*.txt")]
        )
        
        if not path:
            return
        
        try:
            suspicious_ports = self.config.get("security", {}).get("suspicious_ports", [4444, 1337, 8080])
            results = SecurityScanner.run_full_scan(suspicious_ports)
            
            with open(path, "w", encoding="utf-8") as f:
                f.write("=" * 60 + "\n")
                f.write("ОТЧЁТ БЕЗОПАСНОСТИ\n")
                f.write(f"Сгенерирован: {datetime.now().strftime('%d.%m.%Y %H:%M:%S')}\n")
                f.write("=" * 60 + "\n\n")
                
                total = sum(len(v) for v in results.values())
                f.write(f"Всего угроз: {total}\n\n")
                
                for category, threats in results.items():
                    if threats:
                        f.write(f"{'='*40}\n")
                        f.write(f"{category} ({len(threats)})\n")
                        f.write(f"{'='*40}\n")
                        
                        for t in threats:
                            f.write(f"  [{t.get('severity', 'LOW')}] {t.get('reason', '')}\n")
                            if 'process' in t:
                                f.write(f"    Процесс: {t['process']}\n")
                            if 'pid' in t:
                                f.write(f"    PID: {t['pid']}\n")
                            if 'remote' in t:
                                f.write(f"    Удалённый: {t['remote']}\n")
                            if 'path' in t:
                                f.write(f"    Путь: {t['path']}\n")
                            f.write("\n")
            
            messagebox.showinfo("Успех", f"Отчёт сохранён: {os.path.basename(path)}")
            
        except Exception as e:
            logger.error(f"Ошибка экспорта отчета: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сохранить отчёт: {e}")
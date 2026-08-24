"""
Graceful Shutdown - корректное завершение приложения
"""

import time
import sys
import os
import logging

logger = logging.getLogger(__name__)

class GracefulShutdown:
    """Управление корректным завершением приложения"""
    
    def __init__(self, app):
        self.app = app
        self.max_shutdown_time = 10  # секунд
        self.shutdown_start = None
        self.steps_completed = []
        self._is_executing = False
    
    @staticmethod
    def _close_toplevel(window):
        """Безопасное закрытие дочернего окна (объект с .win или само окно)"""
        try:
            win = getattr(window, 'win', window)
            if win and win.winfo_exists():
                # Останавливаем трассировку, если окно её ведёт
                if hasattr(window, 'tracer') and hasattr(window.tracer, 'stop'):
                    try:
                        window.tracer.stop()
                    except Exception:
                        pass
                if hasattr(window, 'is_running'):
                    window.is_running = False
                win.destroy()
        except Exception as e:
            logger.debug(f"Ошибка закрытия окна: {e}")
    
    def execute(self):
        """Выполняет последовательное закрытие с таймаутами"""
        if self._is_executing:
            return
        
        self._is_executing = True
        self.shutdown_start = time.time()
        logger.info("Начинаем graceful shutdown...")
        
        shutdown_steps = [
            ("Остановка UI обновлений", self._stop_ui_updates),
            ("Остановка AI оркестратора", self._stop_ai),
            ("Остановка сниффера", self._stop_sniffer),
            ("Остановка пингера", self._stop_pinger),
            ("Сохранение буферов", self._flush_all_buffers),
            ("Закрытие окон", self._close_windows),
            ("Закрытие БД", self._close_database),
        ]
        
        for step_name, step_func in shutdown_steps:
            if self._check_timeout(step_name):
                break
            
            try:
                step_func()
                self.steps_completed.append(step_name)
                logger.info(f"✓ {step_name}")
            except Exception as e:
                logger.error(f"✗ Ошибка на шаге '{step_name}': {e}")
            
            time.sleep(0.1)
        
        if not self._check_timeout("завершение"):
            elapsed = time.time() - self.shutdown_start
            logger.info(f"Graceful shutdown завершен за {elapsed:.1f}с")
            self._clean_exit(0)
        else:
            self._force_exit()
    
    def _check_timeout(self, step_name):
        """Проверяет, не превышен ли общий таймаут"""
        elapsed = time.time() - self.shutdown_start
        if elapsed > self.max_shutdown_time:
            logger.critical(f"Таймаут превышен на шаге: {step_name} ({elapsed:.1f}с)")
            return True
        
        if elapsed > self.max_shutdown_time * 0.8:
            logger.warning(f"Приближаемся к таймауту на шаге: {step_name} ({elapsed:.1f}с)")
        
        return False
    
    def _stop_ui_updates(self):
        """Останавливает обновление UI"""
        self.app.running = False
        if hasattr(self.app, '_update_timer') and self.app._update_timer:
            try:
                self.app.root.after_cancel(self.app._update_timer)
                self.app._update_timer = None
            except Exception:
                pass
    
    def _stop_ai(self):
        """Останавливает AI оркестратор"""
        ai = getattr(self.app, 'ai_orchestrator', None)
        if ai is not None:
            try:
                ai.stop()
            except Exception:
                pass
    
    def _stop_sniffer(self):
        """Останавливает сниффер"""
        sniffer = getattr(self.app, 'sniffer', None)
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception:
                pass
    
    def _stop_pinger(self):
        """Останавливает пингер"""
        pinger = getattr(self.app, 'pinger', None)
        if pinger is not None:
            try:
                pinger.stop()
            except Exception:
                pass
    
    def _flush_all_buffers(self):
        """Сохраняет все накопленные данные"""
        sniffer = getattr(self.app, 'sniffer', None)
        if sniffer is not None:
            try:
                sniffer._save_traffic_to_db()
            except Exception:
                pass
        pinger = getattr(self.app, 'pinger', None)
        if pinger is not None:
            try:
                pinger._flush_saves()
            except Exception:
                pass
    
    def _close_windows(self):
        """Закрывает дочерние окна и главное окно"""
        for attr in ('ai_dashboard', 'trace_window', 'security_window',
                     'settings_window', 'alerts_window', 'stats_window'):
            window = getattr(self.app, attr, None)
            if window is not None:
                self._close_toplevel(window)
        
        # Закрываем главное окно
        try:
            root = self.app.root
            if root and root.winfo_exists():
                root.quit()
                root.destroy()
        except Exception:
            pass
    
    def _close_database(self):
        """Закрывает соединения с БД"""
        db = getattr(self.app, 'db_manager', None)
        if db is not None:
            try:
                db.close()
            except Exception:
                pass
    
    def _force_exit(self):
        """Принудительное завершение процесса"""
        logger.critical("Принудительное завершение процесса")
        try:
            self._flush_all_buffers()
        except Exception:
            pass
        os._exit(1)
    
    def _clean_exit(self, code=0):
        """Чистое завершение процесса"""
        sys.exit(code)

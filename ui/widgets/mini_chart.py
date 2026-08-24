"""
MiniChart - компактный график для отображения данных
"""

import tkinter as tk
import logging

logger = logging.getLogger(__name__)

class MiniChart:
    """Компактный график для отображения данных"""
    
    def __init__(self, parent, width=500, height=130, color="#9146FF"):
        self.canvas = tk.Canvas(
            parent,
            width=width,
            height=height,
            bg="#0e0e16",
            highlightthickness=0
        )
        self.canvas.pack(fill="x", padx=12, pady=(0, 8))
        self.color = color
        self.width = width
        self.height = height
        self._last_draw_hash = None
        self._is_destroyed = False
        
        # Сохраняем ссылку на родителя для проверки существования
        self._parent = parent
    
    def draw(self, data):
        """Отрисовка графика"""
        # Проверка существования canvas
        if self._is_destroyed:
            return
        
        try:
            if not self.canvas.winfo_exists():
                self._is_destroyed = True
                return
        except:
            self._is_destroyed = True
            return
        
        if len(data) < 2:
            return
        
        try:
            data_tuple = tuple(data)
            data_hash = hash(data_tuple)
            if data_hash == self._last_draw_hash:
                return
            self._last_draw_hash = data_hash
        except:
            return
        
        try:
            self.canvas.delete("all")
            
            w = self.canvas.winfo_width() or self.width
            h = self.canvas.winfo_height() or self.height
            
            # Сетка
            for i in range(1, 5):
                y = h * i // 5
                self.canvas.create_line(0, y, w, y, fill="#1e1e28", dash=(2, 4))
            
            # Фильтрация данных
            valid_data = [(t, v) for t, v in data if v is not None and v > 0]
            if not valid_data:
                return
            
            values = [v for _, v in valid_data]
            max_val = max(values) or 1
            
            # Построение графика
            points = []
            step = max(1, len(valid_data) // min(w, 200))
            
            for i in range(0, len(valid_data), step):
                chunk = valid_data[i:i + step]
                if not chunk:
                    continue
                
                avg_val = sum(v for _, v in chunk) / len(chunk)
                x = i * w / len(valid_data)
                y = h - (avg_val / max_val * h * 0.85)
                points.extend([x, y])
            
            if len(points) >= 4:
                self.canvas.create_line(points, fill=self.color, width=2, smooth=True)
                
                if len(points) >= 2:
                    last_x, last_y = points[-2], points[-1]
                    self.canvas.create_oval(
                        last_x-3, last_y-3,
                        last_x+3, last_y+3,
                        fill=self.color,
                        outline=""
                    )
        except Exception as e:
            logger.debug(f"Ошибка отрисовки графика: {e}")
    
    def clear(self):
        """Очистка графика"""
        if self._is_destroyed:
            return
        
        try:
            if self.canvas.winfo_exists():
                self.canvas.delete("all")
        except:
            self._is_destroyed = True
        
        self._last_draw_hash = None
    
    def destroy(self):
        """Уничтожение виджета"""
        self._is_destroyed = True
        try:
            if self.canvas.winfo_exists():
                self.canvas.destroy()
        except:
            pass
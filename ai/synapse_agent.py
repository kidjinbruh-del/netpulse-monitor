"""
Synapse Agent - коммуникация между агентами
"""

import threading
import time
from collections import deque
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class SynapseAgent:
    """Агент для взаимодействия через Synapse сеть (симуляция)"""
    
    def __init__(self, name, capabilities, config=None):
        self.name = name
        self.capabilities = capabilities
        self.config = config or {}
        self.connected = False
        self.peers = []
        self.tasks = deque(maxlen=100)
        self.message_history = deque(maxlen=1000)
        self.is_enabled = self.config.get('enabled', True)
        self._lock = threading.RLock()
        
        logger.info(f"Synapse Agent '{name}' инициализирован")
    
    def connect(self, hub_url):
        """Подключение к Synapse хабу"""
        if not self.is_enabled:
            return False
        
        with self._lock:
            self.connected = True
            self.peers = ["agent-1", "agent-2", "security-hub"]
            logger.info(f"Synapse Agent '{self.name}' подключен к {hub_url}")
            return True
    
    def broadcast(self, message):
        """Широковещательная рассылка сообщения"""
        if not self.connected or not self.is_enabled:
            return False
        
        with self._lock:
            message["from"] = self.name
            message["timestamp"] = datetime.now().isoformat()
            self.message_history.append(message)
            logger.debug(f"Broadcast от {self.name}: {message.get('type', 'unknown')}")
            return True
    
    def delegate_task(self, task, target_agent=None):
        """Делегирование задачи другому агенту"""
        if not self.connected or not self.is_enabled:
            return False
        
        with self._lock:
            task["delegated_from"] = self.name
            task["delegated_to"] = target_agent or "any"
            task["timestamp"] = datetime.now().isoformat()
            self.tasks.append(task)
            logger.info(f"Задача делегирована: {task.get('type', 'unknown')}")
            return True
    
    def get_stats(self):
        with self._lock:
            return {
                "name": self.name,
                "connected": self.connected,
                "peers": len(self.peers),
                "pending_tasks": len(self.tasks),
                "messages_count": len(self.message_history),
                "capabilities": self.capabilities,
                "is_enabled": self.is_enabled
            }
    
    def set_enabled(self, enabled):
        self.is_enabled = enabled
        logger.info(f"Synapse Agent '{self.name}' {'включен' if enabled else 'отключен'}")
"""Synapse Agent — коммуникация между агентами.

ВНИМАНИЕ: connect()/peers — заглушка (симуляция, наследия v2):
подключение всегда "успешно", пиры фиксированы. Реальный транспорт —
отдельная задача, поведение сохранено 1:1 чтобы ничего не сломать.

v3-реализация: тот же контракт, типизировано.
"""
from __future__ import annotations

import logging
import threading
from collections import deque
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional

logger = logging.getLogger(__name__)

SIMULATED_PEERS = ["agent-1", "agent-2", "security-hub"]


class SynapseAgent:
    """Агент для взаимодействия через Synapse-сеть (симуляция)."""

    def __init__(
        self,
        name: str,
        capabilities: List[str],
        config: Optional[Dict[str, Any]] = None,
    ):
        self.name = name
        self.capabilities = capabilities
        self.config = config or {}
        self.connected = False
        self.peers: List[str] = []
        self.tasks: Deque[Dict[str, Any]] = deque(maxlen=100)
        self.message_history: Deque[Dict[str, Any]] = deque(maxlen=1000)
        self.is_enabled = self.config.get("enabled", True)
        self._lock = threading.RLock()

        logger.info("Synapse Agent '%s' инициализирован", name)

    def connect(self, hub_url: str) -> bool:
        """Подключение к Synapse-хабу (симуляция: всегда успешно)."""
        if not self.is_enabled:
            return False
        with self._lock:
            self.connected = True
            self.peers = list(SIMULATED_PEERS)
            logger.info("Synapse Agent '%s' подключен к %s", self.name, hub_url)
            return True

    def broadcast(self, message: Dict[str, Any]) -> bool:
        """Широковещательная рассылка сообщения."""
        if not self.connected or not self.is_enabled:
            return False
        with self._lock:
            message["from"] = self.name
            message["timestamp"] = datetime.now().isoformat()
            self.message_history.append(message)
            logger.debug("Broadcast от %s: %s",
                         self.name, message.get("type", "unknown"))
            return True

    def delegate_task(
        self, task: Dict[str, Any], target_agent: Optional[str] = None
    ) -> bool:
        """Делегирование задачи другому агенту."""
        if not self.connected or not self.is_enabled:
            return False
        with self._lock:
            task["delegated_from"] = self.name
            task["delegated_to"] = target_agent or "any"
            task["timestamp"] = datetime.now().isoformat()
            self.tasks.append(task)
            logger.info("Задача делегирована: %s", task.get("type", "unknown"))
            return True

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "name": self.name,
                "connected": self.connected,
                "peers": len(self.peers),
                "pending_tasks": len(self.tasks),
                "messages_count": len(self.message_history),
                "capabilities": self.capabilities,
                "is_enabled": self.is_enabled,
            }

    def set_enabled(self, enabled: bool) -> None:
        self.is_enabled = enabled
        logger.info("Synapse Agent '%s' %s", self.name,
                    "включен" if enabled else "отключен")

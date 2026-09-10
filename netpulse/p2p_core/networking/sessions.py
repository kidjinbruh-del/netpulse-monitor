# GRID/sessions.py — управление ожидающими запросами

import asyncio
import logging
from typing import Any, Dict

log = logging.getLogger('Sessions')



class SessionMeta:
    def __init__(self, service: str, method: str):
        self.service = service
        self.method  = method


class SessionTable:
    def __init__(self):
        self._table: Dict[str, asyncio.Future | asyncio.Queue] = {}
        self._meta:  Dict[str, SessionMeta] = {}

    def register_single(self, label: str, service: str = '', method: str = '') -> asyncio.Future:
        f = asyncio.get_event_loop().create_future()
        self._table[label] = f
        self._meta[label]  = SessionMeta(service, method)  # ← новое
        return f

    def resolve(self, label: str, data: Any):
        session = self._table.get(label)
        if isinstance(session, asyncio.Future) and not session.done():
            session.set_result(data)
            self._table.pop(label, None)
            # R4: meta тоже чистим — иначе словарь растёт вечно (утечка
            # на каждый RPC); queue-сессии живут долго, их meta остаётся
            self._meta.pop(label, None)
        elif isinstance(session, asyncio.Queue):
            session.put_nowait(data)
            # Queue sessions: не удаляем из _table —
            # cancel() должен быть вызван явно

    def cancel(self, label: str):
        self._meta.pop(label, None)
        session = self._table.pop(label, None)
        if isinstance(session, asyncio.Future) and not session.done():
            session.cancel()
        elif isinstance(session, asyncio.Queue):
            while not session.empty():
                try:
                    session.get_nowait()
                except asyncio.QueueEmpty:
                    break
            session.put_nowait(None)  # sentinel для ждущего consumer

    def cancel_by_service(self, service_name: str) -> int:
        targets = [
            label for label, meta in self._meta.items()
            if meta.service == service_name
        ]
        for label in targets:
            self.cancel(label)
        return len(targets)


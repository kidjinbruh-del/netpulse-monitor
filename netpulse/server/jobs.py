"""Фоновые задачи API: submit (async-функция) → job_id, get → статус/результат.

Замена legacy JOBS dict + ThreadPoolExecutor + polling-циклов в роутах.
"""
import asyncio
import time
import uuid
from typing import Any, Callable, Coroutine, Dict, Optional


class JobManager:
    def __init__(self, max_age: int = 1800, max_jobs: int = 200):
        self._jobs: Dict[str, Dict[str, Any]] = {}
        self._max_age = max_age
        self._max_jobs = max_jobs

    def submit(self, coro: Coroutine) -> str:
        """Запланировать корутину. Возвращает job_id."""
        job_id = uuid.uuid4().hex[:12]
        self._prune()
        if len(self._jobs) >= self._max_jobs:
            oldest = min(self._jobs, key=lambda k: self._jobs[k]["started"])
            self._jobs.pop(oldest, None)
        record: Dict[str, Any] = {
            "status": "running", "result": None, "error": None,
            "started": time.time(),
        }
        self._jobs[job_id] = record

        async def _wrap():
            try:
                record["result"] = await coro
                record["status"] = "done"
            except asyncio.CancelledError:
                record["status"] = "cancelled"
            except Exception as e:
                record["status"] = "error"
                record["error"] = str(e)[:500]

        record["task"] = asyncio.create_task(_wrap())
        return job_id

    def get(self, job_id: str) -> Optional[Dict[str, Any]]:
        record = self._jobs.get(job_id)
        if record is None:
            return None
        return {
            "status": record["status"],
            "result": record["result"],
            "error": record["error"],
        }

    def _prune(self) -> None:
        cutoff = time.time() - self._max_age
        for jid in list(self._jobs):
            r = self._jobs[jid]
            if r["status"] != "running" and r["started"] < cutoff:
                task = r.get("task")
                if task is not None and not task.done():
                    task.cancel()
                self._jobs.pop(jid, None)


jobs = JobManager()

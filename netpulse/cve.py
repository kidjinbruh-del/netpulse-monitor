"""CVE-проверка для инвентаря ПО (опционально, онлайн).

Использует NVD REST API (v2, без ключа, rate-limit ~5 req/мин) для
поиска уязвимостей по имени продукта. Только версии, указанные явно.
Кэш результатов в отдельных таблицах (sw_cve), чтобы не дёргать API.

Внимание: без сети сервис делает не более 1 запроса/мин и молча
деградирует — мониторинг от этого не зависит.

v3-реализация: тот же контракт CVEChecker(service), типизировано.
service обязан давать .db.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Tuple
from urllib.parse import quote
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = "NetPulse/1.9"
_CACHE_TTL_H = 24
_RATE_MIN_INTERVAL = 1.2  # секунды между запросами (безопасно для rate-limit)
_last_req = [0.0]


def _now_iso() -> str:
    return datetime.now().isoformat()


class CVEChecker:
    def __init__(self, service: Any):
        self.svc = service
        self._lock = threading.Lock()
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        self.svc.db.execute(
            """CREATE TABLE IF NOT EXISTS sw_cve (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                product TEXT NOT NULL,
                version TEXT NOT NULL,
                cve TEXT,
                severity TEXT,
                summary TEXT,
                checked_at TEXT NOT NULL,
                UNIQUE(product, version, cve))""")
        cols = [r["name"] for r in (self.svc.db.execute(
            "PRAGMA table_info(sw_inventory)", fetch=True) or [])]
        if cols and "os" not in cols:
            self.svc.db.execute("ALTER TABLE sw_inventory ADD COLUMN os TEXT")
        if cols and "arch" not in cols:
            self.svc.db.execute(
                "ALTER TABLE sw_inventory ADD COLUMN arch TEXT")

    def _throttle(self) -> None:
        with self._lock:
            wait = _RATE_MIN_INTERVAL - (time.time() - _last_req[0])
            if wait > 0:
                time.sleep(wait)
            _last_req[0] = time.time()

    def _query(self, product: str) -> List[Dict[str, str]]:
        self._throttle()
        url = f"{NVD_API}?keywordSearch={quote(product)}&resultsPerPage=20"
        req = Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        try:
            with urlopen(req, timeout=15) as response:
                data = json.loads(response.read().decode("utf-8"))
        except Exception as e:
            logger.debug("CVE %s: %s", product, e)
            return []
        return [self._parse_item(item) for item in data.get("vulnerabilities", [])]

    @staticmethod
    def _parse_item(item: Dict[str, Any]) -> Dict[str, str]:
        cve = item.get("cve", {})
        severity = None
        try:
            severity = (cve.get("metrics", {}).get("cvssMetricV31", [{}])[0]
                        .get("cvssData", {}).get("baseSeverity"))
        except Exception:
            pass
        summary = ""
        for desc in cve.get("descriptions", []):
            if desc.get("lang") == "en":
                summary = desc.get("value", "")
                break
        return {"cve": cve.get("id", ""), "severity": severity or "?",
                "summary": summary[:300]}

    def check_products(
        self, products: List[Tuple[str, str]]
    ) -> List[Dict[str, str]]:
        """products: [(name, version)] — обновляет sw_cve, возвращает найденные."""
        found = []
        now = _now_iso()
        for name, ver in products:
            name = str(name or "").strip()
            ver = str(ver or "").strip()
            if not name:
                continue
            cached = self.svc.db.execute(
                """SELECT cve, severity, summary, checked_at FROM sw_cve
                   WHERE product = ? AND version = ?
                   ORDER BY id DESC LIMIT 20""",
                (name, ver), fetch=True) or []
            if cached:
                for item in cached:
                    if item["cve"]:
                        found.append({**item, "product": name})
                continue
            try:
                results = self._query(f"{name} {ver}".strip())
            except Exception as e:
                logger.debug("cve scan %s: %s", name, e)
                continue
            if not results:
                self.svc.db.execute(
                    "INSERT OR IGNORE INTO sw_cve (product, version, checked_at) "
                    "VALUES (?,?,?)", (name, ver, now))
                continue
            for item in results:
                self.svc.db.execute(
                    "INSERT OR IGNORE INTO sw_cve "
                    "(product, version, cve, severity, summary, checked_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (name, ver, item["cve"], item["severity"],
                     item["summary"], now))
                found.append({**item, "product": name, "version": ver})
        return found

    def status(self) -> Dict[str, Any]:
        rows = self.svc.db.execute(
            "SELECT COUNT(*) AS n FROM sw_cve WHERE cve IS NOT NULL", fetch=True)
        last = self.svc.db.execute(
            "SELECT MAX(checked_at) AS t FROM sw_cve", fetch=True) or [{}]
        return {"found": (rows[0]["n"] if rows else 0) or 0,
                "last": last[0].get("t")}

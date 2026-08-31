"""
CVE-проверка для инвентаря ПО (опционально, онлайн).

Использует NVD REST API (v2, без ключа, rate-limit ~5 req/мин) для
поиска уязвимостей по имени продукта. Только версии, указанные явно.
Кэш результатов в отдельных таблицах (sw_cve), чтобы не дёргать API.

Внимание: без сети сервис делает не более 1 запроса/мин и молча
деградирует — мониторинг от этого не зависит.
"""

import json
import logging
import threading
import time
from datetime import datetime
from urllib.request import Request, urlopen
from urllib.parse import quote

logger = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = "NetPulse/1.9"
_CACHE_TTL_H = 24
_RATE_MIN = 1.2  # секунды между запросами (безопасно для rate-limit)
_last_req = [0.0]


def _now_iso():
    return datetime.now().isoformat()


class CVEChecker:
    def __init__(self, service):
        self.svc = service
        self._lock = threading.Lock()
        self._ensure()

    def _ensure(self):
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
            self.svc.db.execute("ALTER TABLE sw_inventory ADD COLUMN arch TEXT")

    def _query(self, product):
        with self._lock:
            wait = _RATE_MIN - (time.time() - _last_req[0])
            if wait > 0:
                time.sleep(wait)
            _last_req[0] = time.time()
        url = f"{NVD_API}?keywordSearch={quote(product)}&resultsPerPage=20"
        req = Request(url, headers={"User-Agent": UA, "Accept": "application/json"})
        try:
            with urlopen(req, timeout=15) as r:
                data = json.loads(r.read().decode("utf-8"))
        except Exception as e:
            logger.debug("CVE %s: %s", product, e)
            return []
        out = []
        for item in data.get("vulnerabilities", []):
            cve = item.get("cve", {})
            cid = cve.get("id", "")
            sev = None
            try:
                sev = (cve.get("metrics", {}).get("cvssMetricV31", [{}])[0]
                       .get("cvssData", {}).get("baseSeverity"))
            except Exception:
                pass
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            out.append({"cve": cid, "severity": sev or "?", "summary": desc[:300]})
        return out

    def check_products(self, products):
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
                for c in cached:
                    if c["cve"]:
                        found.append({**c, "product": name})
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
            for r in results:
                self.svc.db.execute(
                    "INSERT OR IGNORE INTO sw_cve "
                    "(product, version, cve, severity, summary, checked_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (name, ver, r["cve"], r["severity"], r["summary"], now))
                found.append({**r, "product": name, "version": ver})
        return found

    def status(self):
        n = self.svc.db.execute(
            "SELECT COUNT(*) AS n FROM sw_cve WHERE cve IS NOT NULL", fetch=True)
        return {"found": (n[0]["n"] if n else 0) or 0,
                "last": (self.svc.db.execute(
                    "SELECT MAX(checked_at) AS t FROM sw_cve", fetch=True)
                         or [{}])[0].get("t")}
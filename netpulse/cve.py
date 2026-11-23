"""
CVE-проверка для инвентаря ПО (опционально, онлайн).

Использует NVD REST API (v2, без ключа, rate-limit ~5 req/мин) для
поиска уязвимостей по имени продукта. Только версии, указанные явно.
Кэш результатов в отдельных таблицах (sw_cve), чтобы не дёргать API.

При недоступности NVD проверка помечается незавершённой;
ошибка сети не кэшируется как отсутствие уязвимостей.
"""

import json
import logging
import threading
import time
from datetime import datetime, timedelta
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import os
from urllib.parse import quote

logger = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
UA = "NetPulse/2.5"
_CACHE_TTL_H = 24
_RATE_MIN = 6.5  # секунды между запросами (безопасно для rate-limit)
_last_req = [0.0]
_REQUEST_LOCK = threading.Lock()


class CVEUnavailable(RuntimeError):
    pass


def _now_iso():
    return datetime.now().isoformat()


class CVEChecker:
    def __init__(self, service):
        self.svc = service
        self._lock = threading.Lock()
        self.last_error = ''
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
        api_key = os.environ.get('NP_NVD_API_KEY', '')
        with _REQUEST_LOCK:
            wait = (0.7 if api_key else _RATE_MIN) - (time.monotonic() - _last_req[0])
            if wait > 0:
                time.sleep(wait)
            _last_req[0] = time.monotonic()
        url = f"{NVD_API}?keywordSearch={quote(product)}&resultsPerPage=20"
        headers = {'User-Agent': UA, 'Accept': 'application/json'}
        if api_key: headers['apiKey'] = api_key
        req = Request(url, headers=headers)
        try:
            with urlopen(req, timeout=15) as r:
                data = json.loads(r.read().decode("utf-8"))
        except HTTPError as error:
            if error.code == 429:
                with _REQUEST_LOCK:
                    _last_req[0] = time.monotonic() + 30
            raise CVEUnavailable('Сервис CVE временно недоступен или ограничил запросы') from None
        except Exception:
            raise CVEUnavailable('Не удалось проверить CVE: сеть или формат ответа') from None
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
        self.last_error = ''
        now = _now_iso()
        cutoff = (datetime.now() - timedelta(hours=_CACHE_TTL_H)).isoformat()
        for name, ver in products:
            name = str(name or "").strip()
            ver = str(ver or "").strip()
            if not name:
                continue
            cached = self.svc.db.execute(
                """SELECT cve, severity, summary, checked_at FROM sw_cve
                   WHERE product = ? AND version = ? AND checked_at > ?
                   ORDER BY id DESC LIMIT 20""",
                (name, ver, cutoff), fetch=True) or []
            if cached:
                for c in cached:
                    if c["cve"]:
                        found.append({**c, "product": name})
                continue
            try:
                results = self._query(f"{name} {ver}".strip())
            except Exception:
                self.last_error = 'Часть продуктов не проверена; отсутствие результата не означает отсутствие уязвимостей'
                continue
            self.svc.db.execute('DELETE FROM sw_cve WHERE product=? AND version=?', (name, ver))
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
        return {"found": (n[0]["n"] if n else 0) or 0, "error": self.last_error, "confidence": "keyword_matches_require_verification",
                "last": (self.svc.db.execute(
                    "SELECT MAX(checked_at) AS t FROM sw_cve", fetch=True)
                         or [{}])[0].get("t")}

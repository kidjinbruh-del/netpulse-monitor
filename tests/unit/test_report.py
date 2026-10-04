"""Unit: /report.txt не падает на deque live_alerts (регресс 500)."""
import asyncio
from collections import deque

from netpulse.server.routes.special import report_txt


class FakeMonitor:
    def __init__(self):
        self.live_alerts = deque([
            {"timestamp": "2024-01-01T00:00:00", "type": "X", "message": "m"}
        ])

    def get_snapshot(self):
        return {"down_kbps": 1.0, "up_kbps": 2.0,
                "quality": {"label": "Ok", "score": 90},
                "ping": {"current": 5}}

    def quota_usage(self):
        return {"daily_used_mb": 1.0}


def test_report_txt_ok():
    resp = asyncio.run(report_txt(monitor=FakeMonitor()))
    assert resp.status_code == 200
    assert "NETPULSE" in resp.body.decode("utf-8")

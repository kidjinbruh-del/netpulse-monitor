"""Интегральная оценка качества связи 0..100 + helpers."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional, Tuple


def _now_iso() -> str:
    return datetime.now().isoformat()


def _is_admin() -> bool:
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def quality_score(
    ping_ms: Optional[float],
    jitter_ms: Optional[float],
    loss_pct: Optional[float],
    q: Dict[str, Any],
) -> float:
    """Интегральная оценка качества 0..100."""
    score = 100.0
    if ping_ms is not None and ping_ms > 0:
        if ping_ms <= q.get("good_ping_ms", 50):
            pass
        elif ping_ms <= q.get("warn_ping_ms", 120):
            score -= ((ping_ms - q["good_ping_ms"])
                      / (q["warn_ping_ms"] - q["good_ping_ms"]) * 25)
        else:
            score -= 25 + min(35, (ping_ms - q["warn_ping_ms"]) / 10 * 2)
    if jitter_ms and jitter_ms > 0:
        score -= min(20, jitter_ms / max(1, q.get("max_jitter_ms", 15)) * 12)
    if loss_pct and loss_pct > 0:
        score -= min(40, loss_pct / max(0.5, q.get("max_loss_pct", 2)) * 18)
    return round(max(0.0, min(100.0, score)), 1)


def quality_label(score: float) -> Tuple[str, str]:
    if score >= 85:
        return "Отлично", "#22d3a7"
    if score >= 65:
        return "Нормально", "#8bd450"
    if score >= 40:
        return "Проблемы", "#f5b942"
    return "Плохо", "#ff5c74"

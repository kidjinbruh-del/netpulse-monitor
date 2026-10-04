"""Jinja2-окружение: лоадер шаблонов, фильтры, globals."""
import os

from jinja2 import Environment, FileSystemLoader, select_autoescape


def templates_dir() -> str:
    return os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "templates"
    )


def fmtnum(value, digits: int = 1) -> str:
    """1234.56 → '1 234,56' (русский формат)."""
    try:
        num = float(value)
    except Exception:
        return "—"
    text = f"{num:,.{int(digits)}f}"
    return text.replace(",", " ").replace(".", ",")


def pct(value, digits: int = 1) -> str:
    """12.34 → '12,3%'."""
    try:
        num = float(value)
    except Exception:
        return "—"
    return f"{num:.{int(digits)}f}%".replace(".", ",")


def status_dot(online=True, karma: int = 100) -> str:
    """CSS-класс точки статуса: ok / warn / bad."""
    try:
        karma = float(karma)
    except Exception:
        karma = 100
    try:
        online = bool(online)
    except Exception:
        online = True
    if not online:
        return "bad"
    if karma < 50:
        return "bad"
    if karma < 80:
        return "warn"
    return "ok"


def mbps(value) -> str:
    """Кбит/с → читаемая скорость."""
    try:
        kb = float(value)
    except Exception:
        return "—"
    if kb >= 1024:
        return f"{fmtnum(kb / 1024)} Мбит/с"
    return f"{fmtnum(kb, 0)} Кбит/с"


_env = None


def get_env() -> Environment:
    global _env
    if _env is None:
        from netpulse import __version__
        _env = Environment(
            loader=FileSystemLoader(templates_dir()),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        _env.filters["fmtnum"] = fmtnum
        _env.filters["pct"] = pct
        _env.filters["status_dot"] = status_dot
        _env.filters["mbps"] = mbps
        _env.globals["app_version"] = __version__
    return _env


def render(name: str, context: dict) -> str:
    return get_env().get_template(name).render(context)

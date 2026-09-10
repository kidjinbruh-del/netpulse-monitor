# services/webpanel/pages/service_view.py — динамический рендер web_ui.py сервиса

import importlib
import importlib.util
import sys

import streamlit as st

from netpulse.p2p_core.services.webpanel.service_meta import SERVICE_META


def _load_web_ui(service_name: str):
    """Динамический импорт services/<name>/web_ui.py."""
    module_name = f"services.{service_name}.web_ui"

    if module_name in sys.modules:
        return sys.modules[module_name]

    from pathlib import Path
    services_dir = Path(__file__).parent.parent.parent
    ui_path = services_dir / service_name / 'web_ui.py'

    if not ui_path.exists():
        return None

    spec = importlib.util.spec_from_file_location(module_name, ui_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def render(rpc, service_name: str):
    icon, group, desc = SERVICE_META.get(service_name, ('📦', '', service_name))
    st.header(f"{icon}  {service_name}")
    if desc and desc != service_name:
        st.caption(desc)

    web_ui = _load_web_ui(service_name)
    if web_ui is None:
        st.warning(f"Сервис `{service_name}` не имеет веб-интерфейса (web_ui.py)")
        return

    if not hasattr(web_ui, 'render'):
        st.error(f"web_ui.py сервиса `{service_name}` не содержит функцию render()")
        return

    try:
        web_ui.render(rpc)
    except Exception as e:
        st.error(f"Ошибка рендеринга UI: {e}")

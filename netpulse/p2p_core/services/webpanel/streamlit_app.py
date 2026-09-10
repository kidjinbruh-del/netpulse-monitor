# services/webpanel/_streamlit_app.py — Streamlit entry point
# Единая панель управления: sidebar навигация + выбор ноды + динамический рендер
import asyncio
import logging
import os
import sys
import time
from pathlib import Path

import streamlit as st

if not os.environ.get('RUNNING', 'False') == 'True':
    raise ImportError("Этот модуль можно запускать только через подпроцесс.")

# ------------------------------------------------------------------ #
#  sys.path — чтобы импорты из корня проекта работали в subprocess
# ------------------------------------------------------------------ #
PROJECT_ROOT = os.environ.get('P2P_PROJECT_ROOT', str(Path(__file__).parent.parent.parent))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from netpulse.p2p_core.services.webpanel.rpc_client import NodeRPC
from netpulse.p2p_core.services.webpanel.service_meta import SERVICE_META, GROUP_ORDER
from netpulse.p2p_core.services.webpanel.auth import check_authentication, is_auth_enabled, render_login_page, logout as auth_logout

# ------------------------------------------------------------------ #
#  Директория сервисов
# ------------------------------------------------------------------ #
SERVICES_DIR = Path(__file__)
logging.getLogger("streamlit.runtime.scriptrunner_utils.script_run_context").setLevel(logging.ERROR)
logging.getLogger("streamlit.runtime.state.session_state_proxy").setLevel(logging.ERROR)

# ------------------------------------------------------------------ #
#  NodeRPC — singleton через session_state
# ------------------------------------------------------------------ #
def get_rpc() -> NodeRPC:
    rpc_exists = 'rpc' in st.session_state
    if rpc_exists and (st.session_state.rpc.connected or st.session_state.rpc.reconnecting):
        return st.session_state.rpc
    if rpc_exists:
        # R9: заменяемый экземпляр не должен течь (поток + loop + сокет)
        try:
            st.session_state.rpc.close()
        except Exception:
            pass
    host = os.environ.get('P2P_WS_HOST', '127.0.0.1')
    port = int(os.environ.get('P2P_WS_PORT', 9000))
    target = os.environ.get('P2P_NODE_ID', 'Node0')
    node_id = f"webpanel_{target}"
    st.session_state.rpc = NodeRPC(
        host=host, port=port,
        node_id=node_id, target_node=target,
    )
    return st.session_state.rpc


# ------------------------------------------------------------------ #
#  Wrapper RPC с поддержкой dst — пробрасывает выбранную ноду
# ------------------------------------------------------------------ #
class RPCProxy:
    """Обёртка над NodeRPC: подставляет dst из session_state."""

    def __init__(self, rpc: NodeRPC):
        self._rpc = rpc

    def call(self, service: str, method: str, data=None, timeout: int = 10,
             dst=None):
        # явный dst имеет приоритет (RPC-консоль), иначе — узел из сайдбара
        if dst is None:
            dst = st.session_state.get('selected_node')
        local_node = self._rpc.node
        if dst is None or dst == local_node:
            dst = None
        return self._rpc.call(service, method, data, dst=dst, timeout=timeout)

    @property
    def connected(self):
        return self._rpc.connected

    @property
    def local_node(self):
        return self._rpc.node


# ------------------------------------------------------------------ #
#  Page config
# ------------------------------------------------------------------ #
st.set_page_config(
    layout="wide",
    page_title="P2P Node Panel",
    page_icon="⬡",
)

# ------------------------------------------------------------------ #
#  Auth guard — не меняет основную функциональность:
#  если webpanel.auth.enabled=false -> прозрачный проход.
#  Если enabled=true и нет сессии -> рендер формы и st.stop().
# ------------------------------------------------------------------ #
if is_auth_enabled() and not check_authentication():
    render_login_page()
    st.stop()

# ------------------------------------------------------------------ #
#  Sidebar
# ------------------------------------------------------------------ #
local_node, rpc = None, None
with st.sidebar:
    try:
        # time.sleep(4)
        rpc = get_rpc()
        local_node = rpc.node
    except Exception as e:
        print('RPC gets failure')
        st.error(f"Ошибка подключения: {e}")
        st.stop()

    # ---- Выбор узла ----
    status = {}
    try:
        status = rpc.call('webpanel', 'node_status')
        connected_nodes = [n.get('node_id', '?') for n in status.get('connected', [])]
        known_nodes = [n.get('node_id', '?') for n in status.get('known', [])]
        all_nodes = [local_node] + \
                    [n for n in connected_nodes if n != local_node] + \
                    [n for n in known_nodes if n not in connected_nodes and n != local_node]
    except Exception:
        all_nodes = [local_node]

    selected_node = st.selectbox(
        "Узел",
        all_nodes,
        index=0,
        key="selected_node_select",
    )

    # При смене узла — очистить кешированные данные всех сервисов
    prev_node = st.session_state.get('_prev_selected_node')
    st.session_state['_prev_selected_node'] = selected_node

    if prev_node is not None and prev_node != selected_node:
        _PRESERVED = {'rpc', 'current_page', '_prev_selected_node',
                       'selected_node_select',
                       '_auth_authenticated', '_auth_user', '_auth_error',
                       '_auth_login_input', '_auth_pwd_input'}
        for key in list(st.session_state.keys()):
            if key not in _PRESERVED:
                del st.session_state[key]
        st.rerun()

    st.session_state['selected_node'] = selected_node

    if selected_node == local_node:
        st.caption("📍 Локальный")
    else:
        st.caption(f"🌐 Удалённый → через {local_node}")

    st.divider()

    # ---- Сервисы с UI ----
    _svc_cache_key = f'_svc_cache_{selected_node}'
    try:
        if selected_node == local_node:
            ui_services = rpc.call('webpanel', 'discover_ui_services')
        else:
            # Сервисы берутся из NeighborTable (голосование) — отдельный RPC не нужен
            ui_services = []
            for n in status.get('connected', []) + status.get('known', []):
                if n.get('node_id') == selected_node:
                    ui_services = list(n.get('services', []))
                    break
        if ui_services:
            st.session_state[_svc_cache_key] = ui_services
        elif _svc_cache_key in st.session_state:
            ui_services = st.session_state[_svc_cache_key]
    except Exception as e:
        st.warning(f"Сервисы недоступны: {e}")
        ui_services = st.session_state.get(_svc_cache_key, [])

    # ---- Текущая страница ----
    if 'current_page' not in st.session_state:
        st.session_state.current_page = 'home'

    # ---- Главная — кнопка ----
    is_home = st.session_state.current_page == 'home'
    if st.button("🏠  Главная", width='stretch', type="primary" if is_home else "secondary"):
        st.session_state.current_page = 'home'
        st.rerun()

    # ---- Группировка сервисов ----
    groups: dict[str, list[tuple[str, str, str]]] = {}  # group → [(name, icon, desc)]
    ungrouped: list[tuple[str, str, str]] = []

    for svc_name in sorted(ui_services):
        meta = SERVICE_META.get(svc_name)
        if meta:
            icon, group, desc = meta
            groups.setdefault(group, []).append((svc_name, icon, desc))
        else:
            ungrouped.append((svc_name, '📦', svc_name))

    # Рендер групп
    for group_name in GROUP_ORDER:
        items = groups.get(group_name, [])
        if not items:
            continue
        st.markdown(f"**{group_name}**")
        for svc_name, icon, desc in items:
            is_active = st.session_state.current_page == svc_name
            btn_type = "primary" if is_active else "secondary"
            if st.button(f"{icon}  {svc_name}", width='stretch', type=btn_type,
                         key=f"nav_{svc_name}"):
                st.session_state.current_page = svc_name
                st.rerun()

    # Без группы
    if ungrouped:
        if groups:
            st.markdown("**Другие**")
        for svc_name, icon, desc in ungrouped:
            is_active = st.session_state.current_page == svc_name
            btn_type = "primary" if is_active else "secondary"
            if st.button(f"{icon}  {svc_name}", width='stretch', type=btn_type,
                         key=f"nav_{svc_name}"):
                st.session_state.current_page = svc_name
                st.rerun()

    # ---- Статус (компактно) ----
    st.divider()
    st.caption(f"🌐 {len(all_nodes)} узлов  •  📦 {len(ui_services)} сервисов")

    # ---- Auth: пользователь + выход (только если включена) ----
    if is_auth_enabled() and st.session_state.get("_auth_authenticated"):
        st.divider()
        st.caption(f"👤 {st.session_state.get('_auth_user', '?')}")
        if st.button("🚪 Выйти", width='stretch', key="auth_logout"):
            auth_logout()
            st.rerun()

# ------------------------------------------------------------------ #
#  Content — роутинг
# ------------------------------------------------------------------ #
proxy = RPCProxy(rpc)

if st.session_state.current_page == 'home':
    from netpulse.p2p_core.services.webpanel.views.home import render
    render(proxy)
else:
    from netpulse.p2p_core.services.webpanel.views.service_view import render
    render(proxy, st.session_state.current_page)

# services/webpanel/pages/home.py — главная страница: состояние узла и сети

import streamlit as st
import pandas as pd


def render(rpc):
    selected_node = st.session_state.get('selected_node', '?')
    is_local = getattr(rpc, 'local_node', '?') == selected_node

    try:
        status = rpc.call('webpanel', 'node_status')
    except Exception as e:
        st.error(f"Ошибка получения данных: {e}")
        return

    # ------------------------------------------------------------------ #
    #  Метрики узла
    # ------------------------------------------------------------------ #
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Узел", status['node_id'])
    c2.metric("Порт", status.get('port', '?'))
    c3.metric("Подключено", status.get('connected_count', 0))
    c4.metric("Известно", status.get('known_count', 0))

    st.divider()

    # ------------------------------------------------------------------ #
    #  Сеть — таблица соседей
    # ------------------------------------------------------------------ #
    st.subheader("Сеть")

    connected = status.get('connected', [])
    known = status.get('known', [])

    if connected or known:
        rows = []
        for n in connected:
            rows.append({
                'Node ID': n.get('node_id', '?'),
                'Host': n.get('host', '?'),
                'Port': n.get('port', '?'),
                'Status': '🟢 CONNECTED',
                'Via': n.get('via', '-'),
                'Services': ', '.join(n.get('services', [])) or '-',
            })
        for n in known:
            rows.append({
                'Node ID': n.get('node_id', '?'),
                'Host': n.get('host', '?'),
                'Port': n.get('port', '?'),
                'Status': '🟡 KNOWN',
                'Via': n.get('via', '-'),
                'Services': ', '.join(n.get('services', [])) or '-',
            })

        df = pd.DataFrame(rows)
        st.dataframe(df, width='stretch', hide_index=True)
    else:
        st.info("Нет известных узлов в сети")

    st.divider()

    # ------------------------------------------------------------------ #
    #  Сервисы
    # ------------------------------------------------------------------ #
    st.subheader("Сервисы")

    all_services = status.get('all_services', [])
    if all_services:
        cols = st.columns(3)
        for i, svc in enumerate(all_services):
            cols[i % 3].info(svc)
    else:
        st.warning("Нет зарегистрированных сервисов")

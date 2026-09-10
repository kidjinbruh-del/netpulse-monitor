# services/netpulse/web_ui.py — веб-интерфейс сервиса NetPulse (мониторинг)
# Контракт: функция render(rpc) вызывается streamlit для рендеринга вкладки.

import streamlit as st
import pandas as pd


def render(rpc):
    st.title("NetPulse — мониторинг сети")

    # Первый рендер / кэш статуса
    if 'np_status' not in st.session_state:
        try:
            st.session_state.np_status = rpc.call('netpulse', 'status')
        except Exception as e:
            st.error(f"Нет связи с сервисом netpulse: {e}")
            return

    status = st.session_state.np_status
    if not status.get('ok'):
        st.error("Мониторинг NetPulse недоступен (сервер не запущен на этом узле).")
        st.write(status)
        return

    st.success(f"Узел `{status.get('node')}` | {status.get('app')} | эндпоинтов: "
               f"{len(status.get('endpoints', []))}")

    tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs(
        ["Состояние", "Алерты", "Парк машин", "События", "Топология", "Карта", "Сеть (mesh)"]
    )

    # ------------------------------------------------------------------ #
    #  Tab 1: Состояние
    # ------------------------------------------------------------------ #
    with tab1:
        if st.button("Обновить", key="np_state_refresh"):
            st.session_state.pop('np_state', None)
        if 'np_state' not in st.session_state:
            try:
                st.session_state.np_state = rpc.call('netpulse', 'collect')
            except Exception as e:
                st.error(f"Ошибка: {e}")
                return
        s = st.session_state.np_state
        if not s.get('ok', True):
            st.warning(s.get('error', 'нет данных'))
        else:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Вниз KB/s", round(s.get('down_kbps', 0), 1))
            c2.metric("Вверх KB/s", round(s.get('up_kbps', 0), 1))
            c3.metric("Ping ms", s.get('ping', {}).get('current'))
            q = s.get('quality', {})
            c4.metric("Качество", f"{q.get('score')} ({q.get('label')})")

            sysm = s.get('system', {})
            st.subheader("Система")
            sc1, sc2, sc3 = st.columns(3)
            sc1.metric("CPU %", round(sysm.get('cpu', 0), 1))
            sc2.metric("RAM %", round(sysm.get('mem_pct', 0), 1))
            sc3.metric("Алертов (непрочит.)", s.get('alerts_unread'))
            if s.get('forecast'):
                st.write("Прогноз скорости (5 мин): "
                         f"`{round(s['forecast'].get('predicted_kbps_5min', 0), 1)}` KB/s")

    # ------------------------------------------------------------------ #
    #  Tab 2: Алерты
    # ------------------------------------------------------------------ #
    with tab2:
        if st.button("Обновить", key="np_alerts_refresh"):
            st.session_state.pop('np_alerts', None)
        if 'np_alerts' not in st.session_state:
            try:
                st.session_state.np_alerts = rpc.call('netpulse', 'alerts', {'limit': 50})
            except Exception as e:
                st.error(f"Ошибка: {e}")
                return
        data = st.session_state.np_alerts
        if data.get('ok') is False:
            st.warning(data.get('error'))
        else:
            alerts = data.get('alerts', [])
            st.caption(f"Непрочитанных: {data.get('unread', 0)} | живых: {len(data.get('live', []))}")
            if alerts:
                rows = [{
                    'time': a.get('timestamp', '')[:19],
                    'type': a.get('alert_type'),
                    'source': a.get('source'),
                    'message': a.get('message'),
                    'ack': bool(a.get('acknowledged')),
                } for a in alerts[:50]]
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            else:
                st.info("Алертов нет")

    # ------------------------------------------------------------------ #
    #  Tab 3: Парк машин
    # ------------------------------------------------------------------ #
    with tab3:
        if st.button("Обновить", key="np_hosts_refresh"):
            st.session_state.pop('np_hosts', None)
        if 'np_hosts' not in st.session_state:
            try:
                st.session_state.np_hosts = rpc.call('netpulse', 'hosts')
            except Exception as e:
                st.error(f"Ошибка: {e}")
                return
        hosts = st.session_state.np_hosts
        if hosts and isinstance(hosts, list):
            st.caption(f"Машин в парке: {len(hosts)}")
            rows = []
            for h in hosts:
                rows.append({
                    'Имя': h.get('name'),
                    'IP': h.get('ip'),
                    'OS': h.get('os'),
                    'Online': h.get('online'),
                    'Карма': h.get('health_score'),
                })
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            st.info(hosts.get('error', 'Нет данных') if isinstance(hosts, dict) else "Нет машин")

    # ------------------------------------------------------------------ #
    #  Tab 4: События
    # ------------------------------------------------------------------ #
    with tab4:
        if st.button("Обновить", key="np_events_refresh"):
            st.session_state.pop('np_events', None)
        if 'np_events' not in st.session_state:
            try:
                st.session_state.np_events = rpc.call('netpulse', 'events', {'limit': 50})
            except Exception as e:
                st.error(f"Ошибка: {e}")
                return
        ev = st.session_state.np_events
        if ev and isinstance(ev, list):
            st.caption(f"Событий: {len(ev)}")
            rows = [{
                'time': e.get('timestamp', '')[:19],
                'kind': e.get('kind'),
                'severity': e.get('severity'),
                'text': e.get('text'),
            } for e in ev[:50]]
            st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        else:
            st.info("Нет событий" if not isinstance(ev, dict) else ev.get('error', 'нет событий'))

    # ------------------------------------------------------------------ #
    #  Tab 5: Топология
    # ------------------------------------------------------------------ #
    with tab5:
        if st.button("Обновить", key="np_topology_refresh"):
            st.session_state.pop('np_topology', None)
        if 'np_topology' not in st.session_state:
            try:
                st.session_state.np_topology = rpc.call('netpulse', 'topology')
            except Exception as e:
                st.error(f"Ошибка: {e}")
                return
        topo = st.session_state.np_topology
        if topo is None or topo.get('ok') is False:
            st.warning((topo or {}).get('error', 'нет данных'))
        else:
            st.json(topo)

    # ------------------------------------------------------------------ #
    #  Tab 6: Единая карта (LAN + L2 + mesh)
    # ------------------------------------------------------------------ #
    with tab6:
        if st.button("Обновить", key="np_map_refresh"):
            st.session_state.pop('np_map', None)
        if 'np_map' not in st.session_state:
            try:
                st.session_state.np_map = rpc.call('netpulse', 'map')
            except Exception as e:
                st.error(f"Ошибка: {e}")
                return
        m = st.session_state.np_map
        if m is None or m.get('ok') is False:
            st.warning((m or {}).get('error', 'нет данных'))
            return

        st.caption(f"Узел `{m.get('node')}` | self_ip `{m.get('self_ip')}` | "
                   f"gateway `{m.get('gateway')}`")

        c1, c2 = st.columns(2)
        with c1:
            st.subheader(f"LAN топология ({len(m.get('lan_nodes', []))})")
            lan = m.get('lan_nodes', [])
            if lan:
                rows = [{
                    'IP': n.get('ip'),
                    'Имя': n.get('alias') or n.get('name'),
                    'Kind': n.get('kind'),
                    'Online': n.get('online'),
                    'Слой': n.get('layer'),
                    'SNMP': bool(n.get('snmp')),
                } for n in lan]
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            else:
                st.info("Нет LAN-узлов")
        with c2:
            st.subheader(f"Mesh-узлы P2P ({len(m.get('mesh_nodes', []))})")
            mesh = m.get('mesh_nodes', [])
            if mesh:
                rows = [{
                    'Node ID': n.get('node_id'),
                    'Host': n.get('host'),
                    'Port': n.get('port'),
                    'Via': n.get('via'),
                    'Сервисы': ', '.join(n.get('services', [])) or '-',
                } for n in mesh]
                st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
            else:
                st.info("Нет mesh-соседей")

        l2 = m.get('l2') or {}
        st.subheader(f"L2 (порты {l2.get('status', {}).get('ports', 0)}, "
                     f"LLDP {l2.get('status', {}).get('lldp', 0)})")
        st.caption(f"Сканирование: {l2.get('status', {}).get('scanning')}")
        if l2.get('ports'):
            st.write(l2['ports'][:20])
        else:
            st.info("Нет данных L2")

    # ------------------------------------------------------------------ #
    #  Tab 7: Распределённая сводка по mesh-узлам
    # ------------------------------------------------------------------ #
    with tab7:
        st.caption("Собирает состояние мониторинга со ВСЕХ узлов сети, "
                   "где запущен сервис netpulse (RPC поверх mesh).")
        section = st.radio("Секция", ["status", "collect", "alerts"],
                           horizontal=True, key="np_gather_section")
        if st.button("Собрать", key="np_gather_go"):
            st.session_state.pop('np_gather', None)
            with st.spinner("Сбор по mesh..."):
                try:
                    res = rpc.call('netpulse', 'gather', {'section': section})
                    st.session_state.np_gather = (section, res)
                except Exception as e:
                    st.error(f"Ошибка: {e}")

        got = st.session_state.get('np_gather')
        if got:
            sec, res = got
            st.subheader(f"Сводка `{sec}` — узлов: {res.get('count', 0)}")
            for n in res.get('nodes', []):
                node_id = n.get('node_id')
                if n.get('ok'):
                    d = n.get('data', {})
                    st.success(f"● `{node_id}`")
                    if sec == 'status':
                        st.write(d.get('app'), '| эндпоинтов:', len(d.get('endpoints', [])))
                    elif sec == 'collect':
                        st.caption(f"↓ {d.get('down_kbps')} KB/s | ↑ {d.get('up_kbps')} "
                                   f"KB/s | ping {d.get('ping', {}).get('current')} ms")
                else:
                    st.error(f"● `{node_id}` — {n.get('error')}")


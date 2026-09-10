# services/speedtest/web_ui.py — замер скорости до удалённого узла
import time

try:
    import streamlit as st
except ImportError:
    st = None

import pandas as pd


def _human(n: float) -> str:
    for unit in ('Б', 'КБ', 'МБ', 'ГБ'):
        if n < 1024 or unit == 'ГБ':
            return f"{n:.0f} {unit}" if unit == 'Б' else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} ГБ"


def render(rpc):
    if st is None:
        return
    st.header("🚀 Speedtest — скорость до узла")
    st.caption("Замер `ping` + `throughput` через mesh (Router.stream, PipeTransport). Поддерживает `via` — транзит через промежуточные хопы. История только в UI.")

    # ---- узлы ----
    try:
        detail = rpc.call('system', 'node_detail', {}, timeout=10)
    except Exception as e:
        st.error(f"Нет связи: {e}")
        return
    own = detail.get('own', '?')
    connected = detail.get('connected', [])
    known = detail.get('known', [])
    # все известные (connected + known)
    all_map = {}
    for n in connected + known:
        nid = n.get('node_id')
        if nid and nid != own and not nid.startswith('webpanel_'):
            all_map[nid] = n
    nodes = sorted(all_map.keys())
    if not nodes:
        st.info("Нет удалённых узлов для теста. Подключитесь к другому узлу.")
        return

    def _fmt(nid):
        info = all_map.get(nid, {})
        via = info.get('via')
        if via:
            return f"{nid} — через {via}"
        # если connected — напрямую
        for c in connected:
            if c.get('node_id') == nid:
                return f"{nid} — напрямую"
        return f"{nid} — known"

    dst = st.selectbox("Узел-цель", nodes, key="st_dst", format_func=_fmt)

    # ---- параметры (выпадающие списки, по умолчанию как предложено) ----
    c1, c2, c3, c4 = st.columns(4)
    mode = c1.selectbox("Режим", ["direct", "bidirectional"], index=0, key="st_mode", help="direct — один поток download, bidirectional — download+upload")
    # маппим mode -> direction для сервиса
    direction = "download" if mode == "direct" else "bidirectional"

    duration = c2.selectbox("Длительность (сек)", [5, 10, 30, 60, 120], index=2, key="st_dur", help="По умолчанию 30с")
    chunk_kb = c3.selectbox("Чанк (КБ)", [64, 128, 256, 512, 1024], index=2, key="st_chunk", help="По умолчанию 256 КБ")
    parallel = c4.selectbox("Параллель (потоков)", [1, 2, 4, 8], index=0, key="st_par", help="По умолчанию 1")

    c5, c6 = st.columns([2, 3])
    max_chunks_opt = c5.selectbox("Лимит чанков", [1000, 10000, 100000, 1_000_000, 10_000_000, 100_000_000], index=5, key="st_maxc", help="Дефолт 10^8")
    c6.caption(f"chunk={chunk_kb}КБ × {max_chunks_opt} ≈ {_human(chunk_kb*1024*max_chunks_opt)} макс; duration {duration}с — сработает первое")

    # ---- запуск ----
    if st.button("▶ Запустить тест", type="primary", key="st_run"):
        st.session_state['st_last_result'] = None
        st.session_state['st_run_params'] = dict(dst=dst, direction=direction, duration=duration, chunk_size=chunk_kb*1024, max_chunks=max_chunks_opt, parallel=parallel)
        st.rerun()

    params = st.session_state.get('st_run_params')
    if params and st.session_state.get('st_last_result') is None:
        # выполняем тест (блокирующий вызов, но с прогрессом)
        # timeout = duration + 20 + parallel*5
        timeout = int(params['duration'] + 30)
        with st.spinner(f"Тест {params['dst']} {params['direction']} {params['duration']}с ..."):
            t0 = time.time()
            try:
                res = rpc.call('speedtest', 'run_test', params, timeout=timeout)
                st.session_state['st_last_result'] = res
                st.session_state['st_last_elapsed'] = time.time() - t0
            except Exception as e:
                st.session_state['st_last_result'] = {"ok": False, "error": str(e)}
            st.rerun()

    res = st.session_state.get('st_last_result')
    if res is not None:
        if not res.get('ok'):
            st.error(f"Ошибка: {res.get('error')}")
            if st.button("↻ Сбросить", key="st_reset_err"):
                st.session_state.pop('st_last_result', None)
                st.session_state.pop('st_run_params', None)
                st.rerun()
            return

        # ping
        ping = res.get('ping', {})
        if ping:
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("RTT avg", f"{ping.get('avg', 0):.1f} мс" if ping.get('avg') is not None else "-")
            c2.metric("RTT min/max", f"{ping.get('min', 0):.1f}/{ping.get('max', 0):.1f}" if ping.get('min') is not None else "-")
            c3.metric("Потери", f"{ping.get('loss', 0):.1f}%")
            c4.metric("Пробы", len(ping.get('rtts', [])))
            # таблица rtts
            if ping.get('rtts'):
                df = pd.DataFrame([{"#": i+1, "RTT мс": f"{x:.1f}" if x is not None else "×"} for i, x in enumerate(ping['rtts'])])
                st.dataframe(df, hide_index=True, width='stretch')

        # download
        dl = res.get('download')
        if dl is not None:
            st.divider()
            st.subheader("⬇ Download (цель → инициатор)")
            if not dl.get('ok', True):
                st.error(dl.get('error'))
            else:
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Скорость", f"{dl.get('mbps', 0):.2f} Мбит/с")
                c2.metric("Байт", _human(dl.get('bytes', 0)))
                c3.metric("Чанков", dl.get('chunks', 0))
                c4.metric("Время", f"{dl.get('elapsed', 0):.1f}с")
                if dl.get('parts'):
                    df = pd.DataFrame([{"поток": i+1, "Мбит/с": f"{p.get('mbps',0):.2f}", "байт": _human(p.get('bytes',0)), "время": f"{p.get('elapsed',0):.1f}с"} for i,p in enumerate(dl['parts'])])
                    st.dataframe(df, hide_index=True, width='stretch')

        ul = res.get('upload')
        if ul is not None:
            st.divider()
            st.subheader("⬆ Upload (инициатор → цель)")
            if not ul.get('ok', True):
                st.error(ul.get('error'))
            else:
                # upload может быть заглушкой если приёмник не вернул bytes
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Скорость", f"{ul.get('mbps', 0):.2f} Мбит/с")
                c2.metric("Байт", _human(ul.get('bytes', 0)))
                c3.metric("Чанков", ul.get('chunks', 0))
                c4.metric("Время", f"{ul.get('elapsed', 0):.1f}с")
                if ul.get('note'):
                    st.caption(ul['note'])
                if ul.get('parts'):
                    df = pd.DataFrame([{"поток": i+1, "Мбит/с": f"{p.get('mbps',0):.2f}", "байт": _human(p.get('bytes',0))} for i,p in enumerate(ul['parts'])])
                    st.dataframe(df, hide_index=True, width='stretch')

        # сводка
        st.divider()
        elapsed = st.session_state.get('st_last_elapsed', 0)
        st.caption(f"Параметры: {res.get('params')} • фактическое время {elapsed:.1f}с")
        # история только в UI — показываем последний результат как JSON
        with st.expander("JSON результата"):
            st.json(res)

        if st.button("↻ Новый тест", key="st_new"):
            st.session_state.pop('st_last_result', None)
            st.session_state.pop('st_run_params', None)
            st.rerun()

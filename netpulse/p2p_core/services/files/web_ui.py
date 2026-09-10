# services/files/web_ui.py — вкладка «Файлы» в веб-панели
#
#  Сценарий: панель подключена к выбранному узлу (= куда скачиваем).
#  Выбираем узел-источник из подключенных, смотрим его шары/файлы,
#  качаем на текущий узел. Статус загрузок — автообновляемый фрагмент.

import os
import time
from pathlib import Path

try:
    import streamlit as st
except ImportError:
    # headless-сборка (Node_P2P_Core.exe): streamlit не установлен
    st = None

if st is not None:

    import pandas as pd

    def _human(n: float) -> str:
        for unit in ('Б', 'КБ', 'МБ', 'ГБ', 'ТБ'):
            if n < 1024 or unit == 'ТБ':
                return f"{n:.0f} {unit}" if unit == 'Б' else f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} ТБ"

    def _fmt_speed(bps) -> str:
        """Скорость в кбит/с или Мбит/с — по величине."""
        if not bps or bps <= 0:
            return ''
        kbps = bps * 8 / 1000
        if kbps < 1000:
            return f"{kbps:.0f} кбит/с"
        return f"{kbps / 1000:.1f} Мбит/с"

    def _status_icon(s: str) -> str:
        return {'running': '🟡', 'done': '🟢', 'error': '🔴',
                'cancelled': '⚪'}.get(s, '⚪')

    def render(rpc):
        st.header("🗂 Файловый транспорт")
        st.caption(
            "Передача файлов между узлами через mesh (`files.stat` → "
            "`files.serve` → push-стрим чанков с ACK). Загрузки выполняет "
            "**выбранный узел**, файлы приходят в `files.download_dir` "
            "из config.yaml."
        )

        _sharing_block(rpc)

        # ---------------- узел-источник ---------------- #
        try:
            detail = rpc.call('system', 'node_detail')
        except Exception as e:
            st.error(f"Нет связи с выбранным узлом: {e}")
            return

        me = detail.get('own', '?')
        # webpanel_* — псевдоузлы (сессии панелей), не источники файлов
        # показываем ВСЕ известные узлы (connected + known via gossip), а не только напрямую подключенные
        _connected = {n.get('node_id'): n for n in detail.get('connected', [])}
        _known = {n.get('node_id'): n for n in detail.get('known', [])}
        # known, которые уже есть в connected — не дублируем
        _all_map = {}
        for nid, info in _connected.items():
            if nid and nid != me and not nid.startswith('webpanel_'):
                _all_map[nid] = info
        for nid, info in _known.items():
            if nid and nid != me and not nid.startswith('webpanel_') and nid not in _all_map:
                _all_map[nid] = info
        peers = list(_all_map.keys())
        # для форматирования: показываем via для known
        def _fmt_peer(nid: str) -> str:
            if nid == me:
                return f"{nid} — этот узел"
            if nid == '(не выбран)':
                return nid
            info = _all_map.get(nid, {})
            via = info.get('via')
            status = info.get('status')
            if via:
                return f"{nid} — через {via} (known)"
            if status == 'known':
                return f"{nid} — known"
            return nid

        c1, c2 = st.columns([2, 1])
        src = c1.selectbox(
            "Узел-источник",
            ['(не выбран)', me] + sorted(peers),
            key="fl_src", format_func=_fmt_peer,
            help="Файл тянем с этого узла на текущий (поддерживается mesh-маршрутизация через via — напрямую или транзитом). Текущий узел тоже "
                 "доступен — файл скопируется в download_dir без сети."
        )
        auto = c2.toggle("Статус: авто (3 сек)", value=True, key="fl_auto")

        if not peers and src in ('(не выбран)', None, me):
            if not peers:
                st.info("Подключенных узлов нет. Можно выбрать текущий узел "
                        "— тогда файл просто скопируется в download_dir.")
            _downloads_block(rpc, auto)
            return

        if src == '(не выбран)':
            _downloads_block(rpc, auto)
            return

        # ---------------- каталог источника ---------------- #
        try:
            shares_res = rpc.call('files', 'list_shares', {}, dst=src,
                                  timeout=30)
        except Exception as e:
            st.warning(f"Узел `{src}` не отвечает на files.list_shares: {e}")
            _downloads_block(rpc, auto)
            return

        shares = shares_res.get('shares', []) if shares_res.get('ok') else []
        if not shares:
            st.info(f"На узле `{src}` нет раздаваемых шар "
                    f"(config.yaml → files.shares).")
            _downloads_block(rpc, auto)
            return

        top = st.columns([2, 2])
        share_pick = top[0].selectbox(
            "Шара", [s['name'] for s in shares], key="fl_share",
            format_func=lambda n: next(
                (f"{n} — {s['files']} файл(ов), {_human(s['bytes'])}"
                 for s in shares if s['name'] == n), n))
        pattern = top[1].text_input(
            "Маска имени", key="fl_pattern", placeholder="*.mp4, report*…")

        if st.button("🔎 Найти файлы", key="fl_find_btn"):
            st.session_state['fl_entries'] = None
        if st.session_state.get('fl_entries') is None or \
           st.session_state.get('fl_src_used') != (src, share_pick):
            try:
                res = rpc.call('files', 'find',
                               {'share': share_pick,
                                'pattern': pattern or '*'},
                               dst=src)
                st.session_state['fl_entries'] = res.get('entries', []) \
                    if res.get('ok') else []
                st.session_state['fl_src_used'] = (src, share_pick)
            except Exception as e:
                st.error(f"Ошибка поиска: {e}")
                return

        entries = st.session_state.get('fl_entries') or []
        if not entries:
            st.info("Ничего не найдено по маске.")
            _downloads_block(rpc, auto)
            return

        df = pd.DataFrame([{
            'Файл': e['path'],
            'Размер': _human(e['size']),
            'Изменён': time.strftime('%Y-%m-%d %H:%M',
                                     time.localtime(e['mtime'])),
        } for e in entries])

        st.markdown("**Файлы источника** — выделите строку:")
        event = st.dataframe(
            df, width='stretch', hide_index=True,
            on_select='rerun', selection_mode='single-row', key='fl_rows',
            height=min(420, 35 * (len(entries) + 1)),
        )
        rows = event.selection.rows

        btn_col, hint_col = st.columns([1, 3])
        pick_disabled = not rows
        picked = entries[rows[0]] if rows else None
        if btn_col.button("⬇ Скачать на этот узел",
                          type="primary", disabled=pick_disabled,
                          key="fl_dl_btn"):
            try:
                res = rpc.call('files', 'download',
                               {'dst': src, 'share': picked['share'],
                                'path': picked['path']})
                if res.get('ok'):
                    if res.get('done'):
                        st.toast(f"Уже скачан и цел: {picked['path']}")
                    else:
                        st.toast(f"Загрузка запущена: {picked['path']}")
                        st.rerun()          # сразу показать ленту загрузок
                else:
                    st.error(res.get('error', 'ошибка запуска'))
            except Exception as e:
                st.error(f"Ошибка: {e}")
        hint_col.caption(
            "Файл придёт в `files.download_dir` текущего узла. Повторный "
            "запуск докачивает `.part` с места обрыва.")

        _downloads_block(rpc, auto)

    # ------------------------------------------------------------------ #

    def _sharing_block(rpc):
        """Расшаривание папок на текущем (выбранном) узле."""
        with st.expander("📂 Расшаривание папок на этом узле", expanded=False):
            # ---- уже расшаренные ----
            try:
                res = rpc.call('files', 'list_shares')
            except Exception as e:
                st.error(f"Нет связи с узлом: {e}")
                return
            shares = res.get('shares', []) if res.get('ok') else []

            if shares:
                df = pd.DataFrame([{
                    'Имя шары': s['name'],
                    'Файлов': s['files'],
                    'Объём': _human(s['bytes']),
                } for s in shares])
                event = st.dataframe(
                    df, width='stretch', hide_index=True,
                    on_select='rerun', selection_mode='single-row',
                    key='fl_share_rows',
                )
                rows = event.selection.rows
                if rows and st.button("✖ Убрать шару", key="fl_unshare"):
                    name = shares[rows[0]]['name']
                    try:
                        r = rpc.call('files', 'remove_share', {'name': name})
                        if r.get('ok'):
                            st.toast(f"Шара {name!r} убрана")
                            st.rerun()
                        else:
                            st.error(r.get('error', 'ошибка'))
                    except Exception as e:
                        st.error(str(e))
            else:
                st.caption("Пока ничего не расшарено.")

            st.divider()

            # ---- браузер каталогов ----
            state = 'fl_br_path'
            if state not in st.session_state:
                st.session_state[state] = ''      # '' = корневые точки

            try:
                br = rpc.call('files', 'list_local_dirs',
                              {'path': st.session_state[state]})
            except Exception as e:
                st.error(f"Ошибка браузера каталогов: {e}")
                return
            if not br.get('ok'):
                st.error(br.get('error', 'каталог недоступен'))
                st.session_state[state] = ''
                return

            nav1, nav2, nav3 = st.columns([2, 2, 5])
            cur = br.get('path') or '(диски / корень ФС)'
            nav3.caption(f"Текущий: `{cur}`")

            dirs = br.get('dirs', [])
            dir_labels = ['(не переходить)'] + [Path(d).name or d for d in dirs]
            pick = nav1.selectbox("Подкаталог", dir_labels, key="fl_br_pick")
            parent = br.get('parent')
            # Fallback для старых узлов / когда бэкенд вернул None в корне диска (C:\):
            # Вверх должен вести к списку дисков ('')
            if parent is None and br.get('path'):
                # любой непустой путь без родителя считаем корнем диска
                parent = ''
            if nav2.button("Открыть ⤵", key="fl_br_open"):
                if pick != '(не переходить)':
                    st.session_state[state] = dirs[dir_labels.index(pick) - 1]
                    st.rerun()
                elif parent is not None:
                    # в корне диска "(не переходить)" работает как «Вверх к дискам»
                    st.session_state[state] = parent
                    st.rerun()
            if parent is not None and nav2.button("⬆ Вверх", key="fl_br_up"):
                st.session_state[state] = parent
                st.rerun()

            # ---- форма добавления ----
            default_name = Path(cur).name if br.get('path') else ''
            form1, form2, form3 = st.columns([2, 2, 2])
            share_name = form1.text_input(
                "Имя шары", value=default_name, key="fl_new_name",
                help="Оставьте пустым — возьмётся имя папки")
            chunk_kb = form2.select_slider(
                "Чанк", options=[64, 128, 256, 512, 1024, 2048],
                value=256, key="fl_new_chunk", format_func=lambda k: f"{k} КБ")
            allow_raw = form3.text_input(
                "Разрешить узлам (через запятую)", key="fl_new_allow",
                help="Пусто = всем подключенным. Пример: Node1, Node2")

            if st.button("✅ Расшарить эту папку", type="primary",
                         key="fl_add_btn"):
                if not br.get('path'):
                    st.warning("Сначала откройте конкретный каталог")
                else:
                    allow = [x.strip() for x in allow_raw.split(',')
                             if x.strip()]
                    try:
                        r = rpc.call('files', 'add_share', {
                            'path': br['path'],
                            'name': share_name or None,
                            'allow': allow,
                            'chunk_size': chunk_kb * 1024,
                        })
                        if r.get('ok'):
                            st.toast(f"Расшарено: {r['share']['name']!r}")
                            st.rerun()
                        else:
                            st.error(r.get('error', 'ошибка'))
                    except Exception as e:
                        st.error(str(e))
            st.caption(
                "Шара сохраняется в config.yaml → files.shares и начинает "
                "действовать сразу. Браузер видит каталоги файловой системы "
                "узла — используйте на доверенных узлах.")

    def _downloads_block(rpc, auto: bool):
        """Лента загрузок текущего узла."""
        st.divider()
        st.subheader("📥 Загрузки этого узла")

        if auto:
            @st.fragment(run_every="3s")
            def view():
                _draw_downloads(rpc)
        else:
            @st.fragment
            def view():
                _draw_downloads(rpc)

        view()

    def _draw_downloads(rpc):
        try:
            res = rpc.call('files', 'downloads')
        except Exception as e:
            st.error(f"Ошибка получения статусов: {e}")
            return
        items = res.get('downloads', []) if res.get('ok') else []
        if not items:
            st.caption("Загрузок нет")
            return

        for d in items:
            icon = _status_icon(d['status'])
            speed = _fmt_speed(d.get('speed_bps'))
            speed_part = f" · {speed}" if (speed and d['status'] == 'running') else ''
            title = (f"{icon} {d['name']} — {_human(d.get('received', 0))} / "
                     f"{_human(d['size'])}{speed_part} ← {d['src']}")
            box = st.expander(title, expanded=(d['status'] == 'error'))
            with box:
                if d['status'] == 'running':
                    st.progress(min(d.get('pct', 0), 100) / 100.0)
                if d.get('error'):
                    st.error(d['error'])
                if d['status'] == 'done':
                    st.success(f"Готово → `{d['path']}`")
                col1, col2, _ = st.columns([1, 1, 4])
                col1.caption(
                    f"sha256 `{str(d.get('id'))[:16]}…`")
                if d['status'] == 'running' and col2.button(
                        "✖ Отменить", key=f"fl_cancel_{d['label']}"):
                    try:
                        rpc.call('files', 'cancel_download',
                                 {'label': d['label']})
                        st.rerun(scope="fragment")
                    except Exception as e:
                        st.error(str(e))

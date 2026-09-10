# services/updater/web_ui.py — вкладка «Обновления» в веб-панели

import time

try:
    import streamlit as st
except ImportError:
    st = None

if st is not None:

    import pandas as pd

    def _human(n: float) -> str:
        for unit in ('Б', 'КБ', 'МБ', 'ГБ', 'ТБ'):
            if n < 1024 or unit == 'ТБ':
                return f"{n:.0f} {unit}" if unit == 'Б' else f"{n:.1f} {unit}"
            n /= 1024
        return f"{n:.1f} ТБ"

    def render(rpc):
        st.header("⬆ Обновления узла")
        st.caption(
            "Проверка и установка версий ядра с узлов-источников "
            "(`update.sources`). Пакет доставляется файловым транспортом, "
            "проверяется sha256 и подписью, ставится rename-trick'ом; "
            "при неудачном старте узел сам откатывается на прежнюю версию."
        )

        try:
            s = rpc.call('updater', 'status')
        except Exception as e:
            st.error(f"Нет связи с узлом: {e}")
            return
        if not s.get('ok'):
            st.error(s.get('error', 'нет данных'))
            return

        # ---------------- текущее состояние ---------------- #
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Версия узла", s.get('current', '?'))
        c2.metric("Режим", 'frozen' if s.get('frozen') else 'dev')
        cfg = s.get('config', {})
        c3.metric("Источники", ', '.join(cfg.get('sources', [])) or '—')
        c4.caption(f"require_signed: {cfg.get('require_signed')}  \n"
                   f"auto_apply: {cfg.get('auto_apply')}  \n"
                   f"allow_downgrade: {cfg.get('allow_downgrade')}")

        state = s.get('state')
        if state:
            if state.get('rolled_back'):
                st.warning(
                    f"⚠ Прошлое обновление на `{state.get('to')}` было "
                    f"ОТКАЧЕНО автоматически ({state.get('from')}). "
                    f"Заблокированные версии: "
                    f"{', '.join(state.get('locked_versions', [])) or '—'}")
            elif state.get('boot_ok'):
                st.success(f"✅ Обновление на `{state.get('to')}` подтверждено.")
            elif state.get('pending_boot_confirm'):
                st.info(f"⏳ Установлена версия `{state.get('to')}`, ожидание "
                        f"подтверждения (попытка {state.get('attempts', '?')})."
                        "Если узел работает стабильно — подтверждение "
                        "пройдёт автоматически.")

        col_a, col_b = st.columns([1, 3])
        if col_a.button("🔍 Проверить обновления", key="upd_check"):
            try:
                with st.spinner('Опрос источников...'):
                    res = rpc.call('updater', 'check', {}, timeout=45)
                if res.get('ok'):
                    errs = res.get('errors') or {}
                    if errs:
                        st.toast(f"Источники с ошибками: {list(errs)}")
                    st.rerun()
                else:
                    st.error(res.get('error', 'ошибка'))
            except Exception as e:
                st.error(str(e))
        if col_b.button("🧹 Очистить состояние обновления",
                        key="upd_clear"):
            try:
                rpc.call('updater', 'clear_state')
                st.toast('Состояние очищено')
                st.rerun()
            except Exception as e:
                st.error(str(e))

        last = s.get('last_check')
        available = (last or {}).get('available', [])
        if not available and not last:
            st.info("Ещё не проверялось — нажмите «Проверить обновления».")
            return
        if not available:
            st.success("Доступных версий нет — у вас последняя.")
            _show_errors(last)
            return

        current = s.get('current')
        df = pd.DataFrame([{
            'Версия': a['version'],
            'Статус': ('🆕 новее' if a['newer']
                       else ('текущая' if a['version'] == current
                             else 'старее')),
            'Источник': a['node'],
            'Размер': _human(a['size']) if a.get('size') else '-',
            'Notes': a.get('notes') or '',
        } for a in available])

        st.markdown("**Доступные версии** — выделите строку:")
        event = st.dataframe(df, width='stretch', hide_index=True,
                             on_select='rerun', selection_mode='single-row',
                             key='upd_rows', height=min(320,
                                                        35 * (len(available)
                                                              + 1)))
        rows = event.selection.rows
        picked = available[rows[0]] if rows else None

        b1, b2, b3 = st.columns([1.2, 1.2, 3])
        can_install = picked is not None and picked['version'] != current
        force = False
        if picked and picked['version'] < current:
            force = b3.checkbox("Разрешить понижение версии",
                                key="upd_force")

        if b1.button("⬇ Скачать", disabled=not picked, key="upd_dl"):
            try:
                with st.spinner('Скачивание через mesh...'):
                    res = rpc.call('updater', 'download',
                                   {'version': picked['version']}, timeout=120)
                (st.success if res.get('ok') else st.error)(
                    res.get('path') or res.get('error', ''))
            except Exception as e:
                st.error(str(e))

        if b2.button("⬆ Установить", type="primary",
                     disabled=not can_install, key="upd_apply"):
            try:
                res = rpc.call('updater', 'apply',
                               {'version': picked['version'],
                                'force': force},
                               timeout=300)
                if res.get('ok'):
                    st.warning(res.get('note', 'устанавливается...'))
                else:
                    st.error(res.get('error', 'ошибка'))
            except Exception as e:
                st.error(f"Ошибка: {e}")

        st.caption(
            "«Установить» скачивает пакет (если ещё не скачан), проверяет "
            "hash/подпись, подменяет exe и перезапускает узел. Первые "
            f"секунды после рестарта — режим подтверждения: при проблемах "
            "узел откатится сам.")

        _show_errors(last)

        # ---------------- автообновление статуса ---------------- #
        @st.fragment(run_every="5s")
        def state_view():
            try:
                s2 = rpc.call('updater', 'status')
            except Exception:
                return
            st2 = s2.get('state') or {}
            if st2.get('pending_boot_confirm') and not st2.get('boot_ok'):
                st.caption(f"⏳ Ожидается подтверждение версии "
                           f"`{st2.get('to')}` "
                           f"(попытка {st2.get('attempts', '?')})")

        state_view()

    def _show_errors(last):
        errs = (last or {}).get('errors') or {}
        for node, err in errs.items():
            st.caption(f"⚠ Источник `{node}`: {err}")

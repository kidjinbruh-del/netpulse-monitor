# services/purge/web_ui.py — веб-интерфейс аварийного удаления узла
# Контракт: функция render(rpc) вызывается streamlit для рендеринга вкладки сервиса

import logging

try:
    import streamlit as st
except ImportError:
    # Если мы в режиме Node без UI, streamlit не доступен
    st = None
import pandas as pd

logging.getLogger("streamlit.runtime.scriptrunner_utils.script_run_context").setLevel(logging.ERROR)
logging.getLogger("streamlit.runtime.state.session_state_proxy").setLevel(logging.ERROR)

# пункты, остановка узла при выборе (панель потеряет связь)
FATAL_ITEMS = {'exe', 'process'}


def _fmt_size(n) -> str:
    if not n:
        return '-'
    for unit in ('Б', 'КБ', 'МБ', 'ГБ'):
        if n < 1024 or unit == 'ГБ':
            return f'{n:.0f} {unit}' if unit == 'Б' else f'{n:.1f} {unit}'
        n /= 1024
    return '-'


def render(rpc):
    if st is None:
        return
    st.subheader("☢️ Аварийное удаление узла")
    st.caption(
        "Полное снятие узла с хоста: автозапуск, конфиг, данные, "
        "исполняемый файл и процесс. Операция **необратима**. Список целей "
        "формирует сам узел (`purge.plan`) — в запрос уходят только id "
        "пунктов, никаких путей. Сервис должен быть включён на узле: "
        "`config.yaml → purge.enabled: true`."
    )

    # ---- результат последней операции (показ после рерана) ----
    last = st.session_state.pop('purge_result', None)
    if last:
        kind, text = last
        (st.success if kind == 'ok' else st.error)(text)

    try:
        plan = rpc.call('purge', 'plan', {})
    except Exception as e:
        st.error(f"Ошибка получения плана: {e}")
        return

    if not isinstance(plan, dict) or not plan.get('ok'):
        st.error(f"Узел ответил ошибкой: {(plan or {}).get('error', 'нет данных')}")
        return

    if not plan.get('enabled'):
        st.warning(
            "Сервис аварийного удаления **отключён** на этом узле. "
            "Включите в config.yaml: `purge: { enabled: true }` и перезапустите узел."
        )
        return

    items = plan.get('items', [])
    if not items:
        st.info("План пуст")
        return

    # ---- таблица целей с мультивыбором ----
    rows = [{
        'Группа': i.get('group', ''),
        'Что': i.get('title', i['id']),
        'Детали': i.get('detail') or i.get('path') or '',
        'Размер': _fmt_size(i.get('size_bytes')),
        'На узле': 'да' if i.get('present', True) else 'нет',
        'Примечание': i.get('note', ''),
    } for i in items]

    event = st.dataframe(
        pd.DataFrame(rows),
        width='stretch', hide_index=True,
        on_select='rerun', selection_mode='multi-row',
        key='purge_sel',
        column_config={
            'Группа': st.column_config.TextColumn(width='small'),
            'Размер': st.column_config.TextColumn(width='small'),
            'Примечание': st.column_config.TextColumn(width='large'),
        },
    )

    selected_rows = event.selection.rows
    selected_ids = [items[r]['id'] for r in selected_rows]

    if selected_ids:
        fatal_selected = sorted(set(selected_ids) & FATAL_ITEMS)
        if fatal_selected:
            titles = [next(i['title'] for i in items if i['id'] == fid)
                      for fid in fatal_selected]
            st.warning(
                "⚠️ В выборе есть необратимо фатальные пункты: **"
                + ', '.join(titles)
                + "**. Узел будет остановлен (~3с), панель потеряет связь."
            )
        else:
            st.caption(f"Выбрано пунктов: {len(selected_ids)}")
    else:
        st.caption("Кликните строки таблицы, чтобы выбрать пункты удаления")

    # ---- подтверждение ----
    confirm = st.checkbox(
        "Я понимаю, что удаление необратимо",
        key='purge_confirm',
    )

    col1, col2, _c3 = st.columns([1.4, 1.2, 3])
    do_selected = col1.button(
        "🗑 Удалить выбранное",
        type="primary",
        disabled=not (selected_ids and confirm),
        key='purge_btn_sel',
    )
    do_all = col2.button(
        "☢️ Удалить ВСЁ",
        type="primary",
        disabled=not confirm,
        key='purge_btn_all',
        help="Все пункты плана, включая остановку процесса и удаление exe",
    )

    if do_selected or do_all:
        target_ids = selected_ids if do_selected else \
            [i['id'] for i in items if i.get('present', True)]
        _run_purge(rpc, target_ids)


def _run_purge(rpc, target_ids):
    """Выполнить purge и показать результат после рерана.

    Потеря связи с узлом здесь — ожидаемый исход (узел останавливается),
    поэтому исключение не показываем как ошибку.
    """
    ids_str = ', '.join(target_ids)
    with st.spinner(f"Удаление ({len(target_ids)} п.)..."):
        result = {'ok': True, 'results': {}}
        error = None
        try:
            result = rpc.call('purge', 'purge',
                              {'items': target_ids, 'confirm': True},
                              timeout=30)
        except Exception as e:
            error = str(e)

    if isinstance(result, dict) and result.get('ok'):
        details = '; '.join(f"{k}: {v}" for k, v in
                            (result.get('results') or {}).items())
        note = result.get('note')
        text = "✅ Выполнено"
        if note:
            text += f" — {note}"
        if details:
            text += f"\n\n{details}"
        st.session_state['purge_result'] = ('ok', text)
    elif error:
        # вероятнее всего узел уже мёртв до отправки RESPONSE
        st.session_state['purge_result'] = (
            'ok',
            f"✅ Команда отправлена; связь с узлом потеряна в процессе "
            f"(ожидаемо при остановке): {error}"
        )
    else:
        st.session_state['purge_result'] = (
            'error', f"❌ {(result or {}).get('error', 'Неизвестная ошибка')}")

    st.rerun()

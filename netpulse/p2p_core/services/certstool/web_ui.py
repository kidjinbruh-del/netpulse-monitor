# services/certstool/web_ui.py — веб-интерфейс управления КриптоПро сертификатами
# Контракт: функция render(rpc) вызывается streamlit для рендеринга вкладки сервиса

import base64
from datetime import datetime, timezone

try:
    import streamlit as st
except ImportError:
    # Если мы в режиме Node без UI, streamlit не доступен
    st = None

# Пороги для подсветки срока сертификата
_WARN_DAYS = 30   # жёлтый — менее 30 дней
_CRIT_DAYS = 7    # красный — менее 7 дней


def _parse_cert_date(s: str) -> datetime | None:
    """Парсинг даты из вывода certmgr: '09/12/2026 13:32:39 UTC' и подобные."""
    for fmt in ('%d/%m/%Y %H:%M:%S UTC', '%d/%m/%Y %H:%M:%S',
                '%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
        try:
            dt = datetime.strptime(s.strip(), fmt)
            if 'UTC' in s:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, AttributeError):
            continue
    return None


def _expiry_badge(valid_to_str: str) -> tuple[str, str]:
    """Возвращает (emoji, label) в зависимости от оставшегося срока."""
    dt = _parse_cert_date(valid_to_str)
    if dt is None:
        return '❓', 'Неизвестно'
    now = datetime.now(timezone.utc) if dt.tzinfo else datetime.now()
    days_left = (dt - now).days
    if days_left < 0:
        return '🔴', f'Истёк ({abs(days_left)}д назад)'
    elif days_left <= _CRIT_DAYS:
        return '🔴', f'{days_left}д — критично!'
    elif days_left <= _WARN_DAYS:
        return '🟡', f'{days_left}д — скоро'
    else:
        return '🟢', f'{days_left}д'


# Поля для удобочитаемого отображения подробностей
_DETAIL_LABELS = {
    'Subject':           'Subject (Владелец)',
    'Issuer':            'Issuer (Удостоверяющий)',
    'Thumbprint':        'Thumbprint (Отпечаток)',
    'SHA1 Thumbprint':   'SHA1 Thumbprint (Отпечаток)',
    'Serial':            'Serial (Серийный номер)',
    'Container':         'Container (Контейнер)',
    'ContainerType':     'Container Type (Тип хранилища)',
    'ValidFrom':         'Valid From (Действует с)',
    'ValidTo':           'Valid To (Действует до)',
    'Not valid before':  'Not valid before',
    'Not valid after':   'Not valid after',
    'Действителен с':    'Действителен с',
    'Действителен до':   'Действителен до',
    'SHA1 Hash':         'SHA1 Hash',
    'Hash':              'Hash',
    'Отпечаток':         'Отпечаток',
    'PrivateKey':        'Private Key (Закрытый ключ)',
    'PrivateKey Link':   'PrivateKey Link (Привязка закрытого ключа)',
    'CertType':          'Тип сертификата',
    'ProvType':          'Тип провайдера',
    'KeyProvInfo':       'Информация о ключе',
    'Provider Name':     'Provider Name (Провайдер)',
    'Provider Info':     'Provider Info (Информация о провайдере)',
    'Identification Kind': 'Identification Kind (Тип идентификации)',
    'SubjectKeyID':      'Subject Key ID',
    'Signature Algorithm': 'Signature Algorithm (Алгоритм подписи)',
    'PublicKey Algorithm': 'PublicKey Algorithm (Алгоритм открытого ключа)',
    'Extended Key Usage': 'Extended Key Usage (Расширенное использование)',
}

# Поля, которые уже отображены в основной строке — не дублировать
_SUMMARY_FIELDS = {'Subject', 'Subject_CN', 'Issuer', 'Issuer_CN',
                   'Thumbprint', 'SHA1 Thumbprint', 'Container', 'ContainerType',
                   'ValidFrom', 'ValidTo',
                   'Not valid before', 'Not valid after',
                   'Действителен с', 'Действителен до'}


def _render_cert_detail(cert: dict, idx: int):
    """Рендерит развёрнутую панель подробностей сертификата."""
    raw = cert.get('raw', {})

    with st.container():
        col_close, col_title = st.columns([1, 10])
        with col_close:
            if st.button("✕", key=f"cert_detail_close_{idx}"):
                st.session_state.pop(f'cert_detail_{idx}', None)
                st.rerun()
        with col_title:
            st.markdown(f"**📋 Подробности: {cert.get('subject_cn', '?')}**")

        thumbprint = cert.get('thumbprint', '')

        # Ключевые данные — крупно
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown(f"**Thumbprint:** `{thumbprint or '—'}`")
            st.markdown(f"**Контейнер:** `{cert.get('container', '—')}`")
            st.markdown(f"**Серийный номер:** `{cert.get('serial', '—')}`")
        with c2:
            st.markdown(f"**Действует с:** {cert.get('valid_from', '—')}")
            st.markdown(f"**Действует до:** {cert.get('valid_to', '—')}")
            exp_emoji, exp_label = _expiry_badge(cert.get('valid_to', ''))
            st.markdown(f"**Срок:** {exp_emoji} {exp_label}")
        with c3:
            # Кнопка "Починить" в деталях
            if st.button("🔧 Починить связку", width='stretch',
                         help="Перепривязать закрытый ключ к сертификату",
                         key=f"fix_detail_{idx}"):
                try:
                    res = rpc.call('certstool', 'fix_certificate_link', {
                        'thumbprint': thumbprint,
                        'password': '00000000',
                    })
                    if res.get('success'):
                        st.success("Связка починена ✓")
                        st.session_state.pop(f'cert_detail_{idx}', None)
                        st.session_state.pop('certs_dashboard', None)
                        st.rerun()
                    else:
                        st.error(f"Ошибка: {res.get('error', 'не удалось')}")
                except Exception as e:
                    st.error(f"Ошибка: {e}")

        # Чекбокс для массового удаления (в деталях)
        batch_mode_active = st.session_state.get('certs_batch_mode_toggle', False)
        if batch_mode_active and thumbprint:
            st.divider()
            is_selected = thumbprint in st.session_state.get('certs_batch_queue', [])
            if st.checkbox(
                "✓ Выбрано для массового удаления",
                value=is_selected,
                key=f"detail_select_{idx}",
            ):
                queue = st.session_state.certs_batch_queue
                if thumbprint not in queue:
                    queue.append(thumbprint)
                else:
                    queue.remove(thumbprint)
                    st.session_state.certs_batch_queue = queue

        st.divider()

        # Subject / Issuer — отдельно для наглядности
        if cert.get('subject'):
            st.markdown("**Subject:**")
            for part in cert['subject'].split(', '):
                if '=' in part:
                    k, v = part.split('=', 1)
                    st.markdown(f"&nbsp;&nbsp;`{k}` = `{v}`")
        if cert.get('issuer') and cert['issuer'] != cert.get('subject'):
            st.markdown("**Issuer:**")
            for part in cert['issuer'].split(', '):
                if '=' in part:
                    k, v = part.split('=', 1)
                    st.markdown(f"&nbsp;&nbsp;`{k}` = `{v}`")

        # Остальные поля из raw, не показанные выше
        other_fields = {k: v for k, v in raw.items()
                        if k not in _SUMMARY_FIELDS and not k.startswith('Subject_')
                        and not k.startswith('Issuer_') and v}
        if other_fields:
            st.divider()
            st.markdown("**Дополнительные поля:**")
            for k, v in other_fields.items():
                label = _DETAIL_LABELS.get(k, k)
                st.markdown(f"**{label}:** `{v}`")

        st.divider()


def render(rpc):
    if st is None:
        return
    tab_list, tab_install, tab_net, tab_export, tab_search = st.tabs(
        ["Сертификаты", "Установка", "🌐 Сетевая установка", "Экспорт", "Поиск"]
    )

    # ------------------------------------------------------------------ #
    #  Tab 1: Сертификаты — построчный рендер с действиями
    # ------------------------------------------------------------------ #
    with tab_list:
        col_refresh, col_count = st.columns([1, 4])
        with col_refresh:
            if st.button("🔄 Обновить", key="certs_refresh"):
                st.session_state.pop('certs_dashboard', None)
                st.session_state.pop('certs_batch_queue', None)

        if 'certs_dashboard' not in st.session_state:
            with st.spinner("Загрузка сертификатов..."):
                try:
                    st.session_state.certs_dashboard = rpc.call(
                        'certstool', 'get_dashboard_data'
                    )
                except Exception as e:
                    st.error(f"Ошибка: {e}")
                    return

        dash = st.session_state.certs_dashboard
        certs = dash.get('certificates', [])
        col_count.metric("Всего сертификатов", dash.get('total_certificates', 0))

        if not certs:
            st.info("Нет установленных сертификатов")
        else:
            # --- Режим пакетного удаления ---
            if 'certs_batch_queue' not in st.session_state:
                st.session_state.certs_batch_queue = []

            batch_mode = st.checkbox(
                "🗂️ Режим массового удаления",
                value=False,
                key="certs_batch_mode_toggle",
                help="Отметьте сертификаты галочками для пакетного удаления"
            )

            if batch_mode:
                st.caption(f"Выбрано: {len(st.session_state.certs_batch_queue)} шт.")
                cols_actions = st.columns([1, 4])
                with cols_actions[0]:
                    if st.button("🗑️ Удалить выбранные", width='stretch'):
                        deleted = 0
                        failed = 0
                        for thumbprint in list(st.session_state.certs_batch_queue):
                            try:
                                res = rpc.call('certstool', 'delete_certificate', {
                                    'thumbprint': thumbprint,
                                })
                                if res.get('success'):
                                    deleted += 1
                                else:
                                    failed += 1
                                    st.warning(f"❌ {thumbprint[:16]}…: {res.get('error', '?')}")
                            except Exception as e:
                                failed += 1
                                st.warning(f"❌ {thumbprint[:16]}…: {e}")
                        st.session_state.certs_batch_queue = []
                        st.session_state.pop('certs_dashboard', None)
                        st.success(f"Готово: ✅ {deleted} удалено, ❌ {failed} ошибок")
                        st.rerun()
                with cols_actions[1]:
                    if st.button("✕ Отменить выбор", width='stretch'):
                        st.session_state.certs_batch_queue = []
                        st.rerun()
                st.divider()

            for i, c in enumerate(certs):
                cn = c.get('subject_cn', 'Неизвестно')
                container = c.get('container', '')
                thumbprint = c.get('thumbprint', '')
                valid_to = c.get('valid_to', '')
                valid_from = c.get('valid_from', '')
                issuer_cn = c.get('issuer_cn', '')

                has_container = bool(container)
                exp_emoji, exp_label = _expiry_badge(valid_to)

                with st.container():
                    # Чекбокс для массового удаления
                    if batch_mode:
                        is_selected = thumbprint in st.session_state.certs_batch_queue
                        if st.checkbox(
                            "✓",
                            value=is_selected,
                            key=f"cert_select_{i}",
                            help=f"Выбрать {cn} для удаления"
                        ):
                            if thumbprint not in st.session_state.certs_batch_queue:
                                st.session_state.certs_batch_queue.append(thumbprint)
                        st.session_state[f'selected_{i}'] = True
                    else:
                        st.write("")  # Заполнитель для выравнивания

                    # Диалог экспорта PFX (для всех)
                    if st.session_state.get(f'pfx_trigger_{i}'):
                        pfx_pwd = st.text_input(
                            "Пароль PFX", value="00000000", type="password",
                            key=f"pfx_pwd_{i}",
                        )
                        pfx_cols = st.columns([1, 1, 4])
                        with pfx_cols[0]:
                            if st.button("📦 Экспорт PFX", key=f"pfx_go_{i}"):
                                with st.spinner("Экспорт PFX..."):
                                    try:
                                        res = rpc.call('certstool', 'export_certificate_pfx', {
                                            'container_name': container,
                                            'thumbprint': thumbprint,
                                            'password': pfx_pwd,
                                        })
                                        if res.get('success'):
                                            st.session_state[f'pfx_dl_{i}'] = res['pfx_base64']
                                            st.session_state[f'pfx_name_{i}'] = cn
                                            st.session_state.pop(f'pfx_trigger_{i}', None)
                                            st.rerun()
                                        else:
                                            st.error(f"PFX: {res.get('error', 'ошибка')}")
                                    except Exception as e:
                                        st.error(f"Ошибка: {e}")
                        with pfx_cols[1]:
                            if st.button("Отмена", key=f"pfx_cancel_{i}"):
                                st.session_state.pop(f'pfx_trigger_{i}', None)
                                st.rerun()
                        st.divider()
                    else:
                        cols = st.columns([3, 2, 1, 1, 1, 1, 1])
                        with cols[0]:
                            st.markdown(f"**{cn}**")
                            st.caption(f"Контейнер: `{container or '—'}`")
                        with cols[1]:
                            st.caption(f"Удостоверяющий: {issuer_cn}")
                            st.caption(f"Действует: {valid_from} → {valid_to}")
                        with cols[2]:
                            st.markdown(f"{exp_emoji} **{exp_label}**")
                        with cols[3]:
                            st.caption(f"`{thumbprint[:16]}…`")
                        with cols[4]:
                            # Кнопка "Починить" — перепривязка закрытого ключа
                            if st.button("🔧", key=f"fix_{i}",
                                         help="Починить связку сертификата с закрытым ключом"):
                                try:
                                    res = rpc.call('certstool', 'fix_certificate_link', {
                                        'thumbprint': thumbprint,
                                        'password': '00000000',
                                    })
                                    if res.get('success'):
                                        st.success("Связка починена ✓")
                                        st.session_state.pop('certs_dashboard', None)
                                        st.rerun()
                                    else:
                                        st.error(f"Ошибка: {res.get('error', 'не удалось')}")
                                except Exception as e:
                                    st.error(f"Ошибка: {e}")
                        with cols[5]:
                            if st.button("🔍", key=f"detail_{i}"):
                                st.session_state[f'cert_detail_{i}'] = True
                                st.rerun()
                        with cols[6]:
                            if st.button("🗑️", key=f"del_{i}"):
                                try:
                                    res = rpc.call('certstool', 'delete_certificate', {
                                        'thumbprint': thumbprint,
                                    })
                                    if res.get('success'):
                                        st.success("Удалён")
                                        st.session_state.pop('certs_dashboard', None)
                                        st.rerun()
                                    else:
                                        st.error(f"Ошибка: {res.get('error', 'не удалось')}")
                                except Exception as e:
                                    st.error(f"Ошибка: {e}")


                        # Кнопки экспорта — под основной строкой
                        export_row = st.columns([1, 1, 4])
                        with export_row[0]:
                            if has_container and st.button("📦 PFX", key=f"exp_pfx_{i}"):
                                st.session_state[f'pfx_trigger_{i}'] = True
                                st.rerun()
                        with export_row[1]:
                            if st.button("📄 CER", key=f"exp_cer_{i}"):
                                with st.spinner("Экспорт CER..."):
                                    try:
                                        res = rpc.call('certstool', 'export_certificate_cer', {
                                            'container_name': container,
                                            'thumbprint': thumbprint,
                                        })
                                        if res.get('success'):
                                            st.session_state[f'cer_dl_{i}'] = res['cer_base64']
                                            st.session_state[f'cer_name_{i}'] = cn
                                        else:
                                            st.error(f"CER: {res.get('error', 'ошибка')}")
                                    except Exception as e:
                                        st.error(f"Ошибка: {e}")

                    # Подробности сертификата
                    if st.session_state.get(f'cert_detail_{i}'):
                        _render_cert_detail(c, i)

                    # Download buttons if export completed
                    if f'pfx_dl_{i}' in st.session_state:
                        safe_name = st.session_state.get(f'pfx_name_{i}', 'cert').replace('"', '')
                        st.download_button(
                            f"⬇ Скачать {safe_name}.pfx",
                            data=base64.b64decode(st.session_state[f'pfx_dl_{i}']),
                            file_name=f"{safe_name}.pfx",
                            mime="application/x-pkcs12",
                            key=f"pfx_dl_btn_{i}",
                        )
                    if f'cer_dl_{i}' in st.session_state:
                        safe_name = st.session_state.get(f'cer_name_{i}', 'cert').replace('"', '')
                        st.download_button(
                            f"⬇ Скачать {safe_name}.cer",
                            data=base64.b64decode(st.session_state[f'cer_dl_{i}']),
                            file_name=f"{safe_name}.cer",
                            mime="application/x-x509-ca-cert",
                            key=f"cer_dl_btn_{i}",
                        )

                    st.divider()

    # ------------------------------------------------------------------ #
    #  Tab 2: Установка PFX
    # ------------------------------------------------------------------ #
    with tab_install:
        st.subheader("Установка из PFX файла")

        pfx_file = st.file_uploader("PFX файл", type=['pfx'], key="certs_upload_pfx")
        pfx_password = st.text_input("Пароль PFX", value="00000000", key="certs_pfx_pwd")

        if pfx_file is not None and st.button("Установить", key="certs_install_btn"):
            pfx_b64 = base64.b64encode(pfx_file.read()).decode('utf-8')
            try:
                result = rpc.call('certstool', 'install_pfx_from_base64', {
                    'pfx_base64': pfx_b64,
                    'password': pfx_password,
                    'filename': pfx_file.name,
                })
                if result.get('success'):
                    st.success(f"Установлен, контейнер: {result.get('container', '?')}")
                    st.session_state.pop('certs_dashboard', None)
                else:
                    st.error(f"Ошибка: {result.get('error', 'unknown')}")
            except Exception as e:
                st.error(f"Ошибка: {e}")

        st.divider()
        st.subheader("Пакетная установка")
        st.caption("Загрузите несколько PFX файлов для пакетной установки")
        batch_files = st.file_uploader("PFX файлы", type=['pfx'],
                                        accept_multiple_files=True, key="certs_batch_pfx")
        batch_pwd = st.text_input("Текущий пароль", value="00000000", key="certs_batch_pwd")
        batch_new_pwd = st.text_input("Новый пароль (необязательно)", key="certs_batch_new_pwd")

        if batch_files and st.button("Установить все", key="certs_batch_btn"):
            pfx_list = []
            for f in batch_files:
                pfx_list.append({
                    'pfx_base64': base64.b64encode(f.read()).decode('utf-8'),
                    'filename': f.name,
                })
            try:
                result = rpc.call('certstool', 'batch_install_pfx_from_bytes', {
                    'pfx_list': pfx_list,
                    'current_password': batch_pwd,
                    'new_password': batch_new_pwd or None,
                })
                st.write(f"Успешно: {result.get('success_count', 0)} / {result.get('total', 0)}")
                for r in result.get('results', []):
                    if r.get('success'):
                        st.success(f"✅ {r.get('filename')}")
                    else:
                        st.error(f"❌ {r.get('filename')}: {r.get('error', '')}")
                st.session_state.pop('certs_dashboard', None)
            except Exception as e:
                st.error(f"Ошибка: {e}")

    # ------------------------------------------------------------------ #
    #  Tab 3: Сетевая установка (CERT_SYNC)
    # ------------------------------------------------------------------ #
    with tab_net:
        col_refresh_net, col_count_net = st.columns([1, 4])
        with col_refresh_net:
            if st.button("🔄 Обновить сеть", key="net_certs_refresh"):
                st.session_state.pop('net_certs_data', None)
        with col_count_net:
            st.caption("Сертификаты, доступные с других узлов сети")

        if 'net_certs_data' not in st.session_state:
            with st.spinner("Загрузка сетевых сертификатов..."):
                try:
                    st.session_state.net_certs_data = rpc.call(
                        'certstool', 'network_certs'
                    )
                except Exception as e:
                    st.error(f"Ошибка: {e}")
                    st.session_state.net_certs_data = {'groups': {}, 'total': 0}

        net_data = st.session_state.net_certs_data
        groups = net_data.get('groups', {})
        total = net_data.get('total', 0)

        st.metric("Доступно для установки", total)

        if not groups:
            st.info("Нет сертификатов от других узлов. Убедитесь, что в сети есть узлы с CertsTool.")
        else:
            # Фильтр: скрыть конфликтующие (один CN — разные thumbprint)
            show_conflicts = st.checkbox("Показать конфликты (один CN → разные отпечатки)", value=False, key="net_show_conflicts")

            # Пароль для новых контейнеров
            new_pwd = st.text_input("Пароль контейнера после установки", value="00000000", key="net_new_pwd")

            # Собрать выбранные для пакетной установки
            if 'net_batch_queue' not in st.session_state:
                st.session_state.net_batch_queue = []

            for cn, entries in sorted(groups.items()):
                has_conflict = len(entries) > 1
                if has_conflict and not show_conflicts:
                    # Для конфликтов — показываем пометку, но не скрываем полностью
                    pass

                with st.expander(
                    f"{'⚠️ ' if has_conflict else ''}{cn} ({len(entries)})",
                    expanded=(not has_conflict)
                ):
                    if has_conflict:
                        st.warning("Несколько сертификатов с одним CN — выберите нужный по отпечатку")

                    for entry in entries:
                        tp = entry.get('thumbprint', '')
                        valid_to = entry.get('valid_to', '')
                        available_on = entry.get('available_on', [])
                        exp_emoji, exp_label = _expiry_badge(valid_to)

                        cols = st.columns([3, 1, 2, 1])
                        with cols[0]:
                            st.markdown(f"`{tp[:16]}…`")
                            st.caption(f"CN: {cn}")
                        with cols[1]:
                            st.markdown(f"{exp_emoji} **{exp_label}**")
                        with cols[2]:
                            # Выбор источника если несколько узлов
                            if len(available_on) > 1:
                                source = st.selectbox(
                                    "Источник",
                                    options=available_on,
                                    key=f"src_{tp[:12]}",
                                    label_visibility="collapsed",
                                )
                            else:
                                source = available_on[0] if available_on else ''
                                st.caption(f"От: {source}")

                        with cols[3]:
                            if st.button("📥 Установить", key=f"net_install_{tp[:12]}"):
                                with st.spinner(f"Установка с {source}..."):
                                    try:
                                        result = rpc.call('certstool', 'install_from_node', {
                                            'thumbprint': tp,
                                            'source_node': source,
                                            'new_password': new_pwd,
                                        })
                                        if result.get('success'):
                                            st.success(f"✅ Установлен: {result.get('container', '')}")
                                            st.session_state.pop('certs_dashboard', None)
                                            st.session_state.pop('net_certs_data', None)
                                            st.rerun()
                                        else:
                                            st.error(f"❌ {result.get('error', 'ошибка')}")
                                    except Exception as e:
                                        st.error(f"Ошибка: {e}")

                        # Кнопка добавления в пакетную очередь
                        if st.button(f"➕ В очередь", key=f"net_queue_{tp[:12]}"):
                            item = {'thumbprint': tp, 'source_node': source, 'cn': cn}
                            # Не добавлять дубликаты
                            if not any(q['thumbprint'] == tp for q in st.session_state.net_batch_queue):
                                st.session_state.net_batch_queue.append(item)

            # Пакетная установка
            st.divider()
            queue = st.session_state.net_batch_queue
            if queue:
                st.subheader(f"Пакетная установка ({len(queue)} шт.)")
                for idx, item in enumerate(queue):
                    cols = st.columns([4, 1])
                    with cols[0]:
                        st.text(f"{item['cn']} ← {item['source_node']} ({item['thumbprint'][:12]}…)")
                    with cols[1]:
                        if st.button("✕", key=f"net_q_del_{idx}"):
                            st.session_state.net_batch_queue.pop(idx)
                            st.rerun()

                if st.button("🚀 Установить все из очереди", key="net_batch_install"):
                    ok, fail = 0, 0
                    progress = st.progress(0)
                    for idx, item in enumerate(queue):
                        try:
                            result = rpc.call('certstool', 'install_from_node', {
                                'thumbprint': item['thumbprint'],
                                'source_node': item['source_node'],
                                'new_password': new_pwd,
                            })
                            if result.get('success'):
                                ok += 1
                            else:
                                fail += 1
                                st.warning(f"❌ {item['cn']}: {result.get('error', '?')}")
                        except Exception as e:
                            fail += 1
                            st.warning(f"❌ {item['cn']}: {e}")
                        progress.progress((idx + 1) / len(queue))

                    st.info(f"Готово: ✅ {ok} установлено, ❌ {fail} ошибок")
                    st.session_state.net_batch_queue = []
                    st.session_state.pop('certs_dashboard', None)
                    st.session_state.pop('net_certs_data', None)

            # История установки
            st.divider()
            st.subheader("История сетевой установки")
            if st.button("📋 Показать историю", key="net_show_history"):
                try:
                    history = rpc.call('certstool', 'get_install_history')
                    if history:
                        for rec in reversed(history):
                            st.text(f"{rec.get('installed_at', '?')} | {rec.get('thumbprint', '?')[:16]}… | от {rec.get('source_node', '?')}")
                    else:
                        st.info("Пока нет записей")
                except Exception as e:
                    st.error(f"Ошибка: {e}")

    # ------------------------------------------------------------------ #
    #  Tab 4: Экспорт
    # ------------------------------------------------------------------ #
    with tab_export:
        st.subheader("Экспорт по Subject")
        export_pattern = st.text_input("Паттерн Subject", key="certs_export_subj")
        export_pwd = st.text_input("Пароль PFX", value="00000000", key="certs_export_pwd")

        if st.button("Экспортировать", key="certs_export_btn") and export_pattern:
            with st.spinner("Экспорт..."):
                try:
                    result = rpc.call('certstool', 'export_certificate_by_subject', {
                        'subject_pattern': export_pattern,
                        'password': export_pwd,
                    })
                    pfx = result.get('pfx', {})
                    cer = result.get('cer', {})

                    if pfx.get('success'):
                        st.download_button(
                            "📥 Скачать PFX",
                            data=base64.b64decode(pfx['pfx_base64']),
                            file_name=f"{export_pattern}.pfx",
                            mime="application/x-pkcs12",
                        )
                    else:
                        st.warning(f"PFX: {pfx.get('error', 'не найден')}")

                    if cer.get('success'):
                        st.download_button(
                            "📥 Скачать CER",
                            data=base64.b64decode(cer['cer_base64']),
                            file_name=f"{export_pattern}.cer",
                            mime="application/x-x509-ca-cert",
                        )
                    else:
                        st.warning(f"CER: {cer.get('error', 'не найден')}")

                except Exception as e:
                    st.error(f"Ошибка: {e}")

        st.divider()
        st.subheader("Экспорт по контейнеру")
        exp_container = st.text_input("Имя контейнера", key="certs_exp_container")
        exp_pwd2 = st.text_input("Пароль PFX", value="00000000", key="certs_exp_pwd2")

        if st.button("Экспортировать PFX", key="certs_exp_pfx_btn") and exp_container:
            try:
                result = rpc.call('certstool', 'export_certificate_pfx', {
                    'container_name': exp_container,
                    'password': exp_pwd2,
                })
                if result.get('success'):
                    st.download_button(
                        "📥 Скачать PFX",
                        data=base64.b64decode(result['pfx_base64']),
                        file_name=f"{exp_container}.pfx",
                        mime="application/x-pkcs12",
                    )
                else:
                    st.error(f"Ошибка: {result.get('error', 'unknown')}")
            except Exception as e:
                st.error(f"Ошибка: {e}")

    # ------------------------------------------------------------------ #
    #  Tab 5: Поиск
    # ------------------------------------------------------------------ #
    with tab_search:
        search_pattern = st.text_input("Паттерн Subject для поиска", key="certs_search")
        if st.button("Найти", key="certs_search_btn") and search_pattern:
            try:
                results = rpc.call('certstool', 'find_certificates_by_subject', {
                    'subject_pattern': search_pattern,
                })
                if results:
                    st.success(f"Найдено: {len(results)}")
                    for cert in results:
                        with st.expander(cert.get('Subject_CN', cert.get('Subject', '?'))):
                            st.json(cert)
                else:
                    st.warning("Сертификаты не найдены")
            except Exception as e:
                st.error(f"Ошибка: {e}")

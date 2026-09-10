# services/demo/web_ui.py
# =============================================================================
#  Веб-интерфейс сервиса — «вкладка» в общей панели (Streamlit).
#
#  Контракт простой:
#    * файл называется web_ui.py и лежит рядом с service.py;
#    * внутри — функция render(rpc), панель сама её найдёт и вызовет;
#    * rpc — это RPCProxy. rpc.call(service, method, data={}, timeout=10)
#      уходит на УЗЕЛ, выбранный в сайдбаре панели: если выбрана другая
#      нода, proxy сам подставит dst, и вызов доедет через mesh.
#    * rpc.call синхронный (блокирующий) — обычный стиль Streamlit.
#
#  Не забудьте добавить запись в реестр панели:
#    services/webpanel/service_meta.py ->
#    'demo': ('🎓', 'Примеры', 'Эталонный сервис: все возможности')
#
#  ВАЖНО: вкладку могут открыть на узле без этого сервиса или в headless-
#  сборке — поэтому каждый вызов оборачиваем в try/except.
# =============================================================================

try:
    import streamlit as st
except ImportError:
    # headless-сборка (Node_P2P_Core.exe): streamlit не установлен,
    # модуль просто не должен ломать импорт при hot-reload
    st = None

if st is not None:

    def render(rpc):
        st.header("🎓 Demo — эталонный сервис")
        st.caption(
            "Живой пример того, что умеет сервис: простые RPC, mesh-вызовы "
            "между узлами, потоковая передача и распределённые вычисления. "
            "Код с пояснениями: `services/demo/service.py`."
        )

        tab_basics, tab_stream, tab_spawn = st.tabs(
            ["Проверка связи", "Стрим между узлами", "Распределённые вычисления"]
        )

        # -------------------------------------------------------------- #
        #  Вкладка 1: простые RPC
        # -------------------------------------------------------------- #
        with tab_basics:
            st.markdown("**1. `ping`** — эхо-вызов: проверка, что сервис отвечает.")
            msg = st.text_input("Что передать в data.message", "hello", key="demo_ping_msg")
            if st.button("▶ ping", key="demo_ping_btn"):
                try:
                    st.json(rpc.call("demo", "ping", {"message": msg}))
                except Exception as e:
                    st.error(f"Ошибка: {e}")

            st.divider()
            st.markdown(
                "**2. `node_info`** — доступ к состоянию узла из сервиса: "
                "имя узла, локальные сервисы, соседи по сети."
            )
            if st.button("▶ node_info", key="demo_info_btn"):
                try:
                    st.json(rpc.call("demo", "node_info", {}))
                except Exception as e:
                    st.error(f"Ошибка: {e}")

            st.divider()
            st.markdown(
                "**3. `call_remote`** — сервис сам находит в сети узел с нужным "
                "сервисом (`neighbor_table.find_by_service`) и вызывает на нём "
                "`ping` через mesh. Маршрут через промежуточные узлы строится "
                "автоматически."
            )
            if st.button("▶ call_remote → сосед", key="demo_remote_btn"):
                with st.spinner("Ищем соседей..."):
                    try:
                        st.json(rpc.call("demo", "call_remote", {"service": "demo"}, timeout=15))
                    except Exception as e:
                        st.error(f"Ошибка: {e}")

        # -------------------------------------------------------------- #
        #  Вкладка 2: стрим
        # -------------------------------------------------------------- #
        with tab_stream:
            st.markdown(
                "**`start_stream`** — этот узел генерирует числа и передаёт их "
                "потоком выбранному соседу. На том узле демо-сервис принимает "
                "чанки (`@stream_consumer`), подтверждает получение ACK'ами — "
                "это и есть backpressure: генератор не убежит вперёд от приёмника."
            )

            detail = {}
            connected = []
            try:
                detail = rpc.call("system", "node_detail", {}) or {}
                connected = [n.get("node_id") for n in detail.get("connected", [])
                             if n.get("node_id")]
            except Exception:
                pass

            if not connected:
                st.info("Нет подключенных узлов — подключите соседа во вкладке «Система».")
            else:
                target = st.selectbox("Куда слать поток", connected, key="demo_target")
                count = st.slider("Сколько элементов передать", 5, 100, 20, key="demo_count")
                buff = st.slider("Буфер (размер окна backpressure)", 1, 10, 3, key="demo_buff")

                if st.button("▶ start_stream", type="primary", key="demo_stream_btn"):
                    with st.spinner(f"Стримим {count} элементов → {target}"):
                        try:
                            result = rpc.call("demo", "start_stream",
                                              {"target": target, "count": count, "buff": buff})
                            if result.get("ok"):
                                st.success(
                                    f"Поток запущен (label `{result['label'][:8]}…`). "
                                    f"Результаты смотрите в логе узла {target}."
                                )
                            else:
                                st.error(result.get("error", "неизвестная ошибка"))
                        except Exception as e:
                            st.error(f"Ошибка: {e}")

            st.caption(
                "Приёмник копит статистику (количество, сумму квадратов) и пишет "
                "её в лог своего узла — откройте консоль целевой машины."
            )

        # -------------------------------------------------------------- #
        #  Вкладка 3: Spawner
        # -------------------------------------------------------------- #
        with tab_spawn:
            st.markdown(
                "**`spawn_workers`** — Spawner раздаёт элементы локального "
                "генератора всем подключенным рабочим узлам сразу; каждый "
                "обрабатывает свою часть через тот же `process_numbers`. "
                "Одна команда — параллельные вычисления на всей сети."
            )
            workers = st.slider("Число воркеров (= число подключенных узлов)", 1, 10, 2, key="demo_workers")
            if st.button("▶ spawn_workers", key="demo_spawn_btn"):
                with st.spinner("Раздаём работу по сети..."):
                    try:
                        st.json(rpc.call("demo", "spawn_workers",
                                         {"workers_count": workers}, timeout=20))
                    except Exception as e:
                        st.error(f"Ошибка: {e}")
            st.caption("Логи обработки — на каждом задействованном узле.")

# services/demo/service.py
# =============================================================================
#  ЭТАЛОННЫЙ СЕРВИС — образец разработки сервисов для P2P_Core.
#
#  Как устроен сервис:
#    services/demo/
#    ├── __init__.py   # пустой (обязателен — признак python-пакета)
#    ├── service.py    # этот файл: класс-наследник ModuleGeneric
#    └── web_ui.py     # (опционально) вкладка в веб-панели, см. ниже в файле
#
#  Что происходит автоматически (ServiceLoader):
#    1. Сканирует services/ — каждая директория БЕЗ префикса "_" становится сервисом.
#       Имя сервиса = имя директории (здесь — 'demo').
#    2. Ищет в service.py классы-наследники ModuleGeneric и создаёт экземпляр.
#    3. Регистрирует все методы с декоратором @rpc — их можно вызывать по сети
#       с любого узла:  rpc.call('demo', 'ping', data={})  или из кода через
#       ctx.network.call(dst=..., service='demo', method='ping', data={...}).
#    4. Вызывает ctx.register(instance) — фреймворк сам вызовет start()/stop().
#    5. Следит за файлами (watchdog): правки подхватываются без перезапуска узла.
#
#  Контракт RPC-метода:  принимает data: dict, ВОЗВРАЩАЕТ dict (JSON-совместимый).
#  Ошибки принято возвращать как {'ok': False, 'error': '<текст>'} — так их
#  удобно показывать в веб-панели. Исключение тоже долетит до вызывающего,
#  но словарь даёт контроль над форматом.
# =============================================================================

import asyncio
import uuid

from netpulse.p2p_core.internal_modules.base import ModuleGeneric
from netpulse.p2p_core.networking.protocol import MsgPack
from netpulse.p2p_core.internal_modules.memory import Pipe
from netpulse.p2p_core.services.rpc import rpc, generator, stream_wrapper, stream_consumer


class Demo(ModuleGeneric):
    """
    Демонстрация всех возможностей, доступных сервису.

    Шпаргалка по self.ctx (контекст приложения) — главное, что нужно сервису:

        self.ctx.NODE                     имя этого узла ('Node0', hostname, ...)
        self.ctx.config_manager           конфигурация (.get('network.port'), .add_peer...)
        self.ctx.services                 реестр сервисов этого узла
        self.ctx.memory                   фабрика стримов: create_pipe / create_dispatcher /
                                          attach_transport
        self.ctx.network.call(dst=..., service=..., method=..., data=...)   RPC по mesh
        self.ctx.network.stream(...)      открыть mesh-стрим (см. glm.md, раздел 7)
        self.ctx.network.router           маршрутизатор (низкоуровневые операции)
        self.ctx.network.neighbor_table   кто в сети: .connected() .known() .find_by_service()
        self.ctx.spawn                    Spawner — распределённые вычисления
        self.log                          обычный logging.Logger с именем сервиса
    """

    def __init__(self, name: str, context):
        super().__init__(name, context)
        # здесь можно создать собственное состояние сервиса (кэши, настройки),
        # но НЕ открывать ресурсы — для этого есть start()
        self._started_at = None

    # ------------------------------------------------------------------ #
    #  Жизненный цикл
    # ------------------------------------------------------------------ #
    #  start() вызывается при поднятии узла (и после hot-reload файла),
    #  stop() — при выключении. Порядок = порядку регистрации модулей,
    #  остановка — в обратном порядке. Тяжёлые ресурсы открываем тут,
    #  а не в __init__.

    async def start(self):
        self._started_at = asyncio.get_event_loop().time()
        self.log.info('Demo service started')

    async def stop(self):
        self.log.info('Demo service stopped')

    # ------------------------------------------------------------------ #
    #  1. Простейший @rpc: синхронный метод
    # ------------------------------------------------------------------ #
    #  data — всегда dict (то, что вызвавший передал в data={...}).
    #  Возврат dict уходит обратно вызывающему, даже если тот на другом узле.

    @rpc
    def ping(self, data: dict) -> dict:
        return {
            'ok': True,
            'service': self.name,
            'node': self.ctx.NODE,
            'echo': data,
        }

    # ------------------------------------------------------------------ #
    #  2. Асинхронный @rpc + доступ к состоянию узла и сети
    # ------------------------------------------------------------------ #

    @rpc
    async def node_info(self, data: dict) -> dict:
        nt = self.ctx.network.neighbor_table
        return {
            'ok': True,
            'node': self.ctx.NODE,
            'uptime_sec': round(asyncio.get_event_loop().time() - (self._started_at or 0)),
            'services_here': list(self.ctx.services.services.keys()),
            'connected': [n.node_id for n in nt.connected()],
            'known': [n.node_id for n in nt.known()],
        }

    # ------------------------------------------------------------------ #
    #  3. Межузловой вызов (mesh RPC) из кода сервиса
    # ------------------------------------------------------------------ #
    #  ctx.network.call() сам построит маршрут: если dst — этот узел,
    #  выполнит локально; если удалённый и нет прямого соединения —
    #  пошлёт через соседей. Ответ вернётся как dict.
    #
    #  Здесь: находим ЛЮБОЙ узел сети, где живёт заданный сервис,
    #  и дёргаем на нём метод ping.

    @rpc
    async def call_remote(self, data: dict) -> dict:
        target_service = data.get('service', 'demo')

        candidates = [
            n for n in self.ctx.network.neighbor_table.find_by_service(target_service)
            if n.node_id != self.ctx.NODE and n.status.value == 'connected'
        ]
        if not candidates:
            return {'ok': False, 'error': f'нет подключенных узлов с сервисом {target_service!r}'}

        dst = candidates[0].node_id
        result = await self.ctx.network.call(
            dst=dst,
            service=target_service,
            method='ping',
            data={'from': self.ctx.NODE},
            timeout=10,
        )
        return {'ok': True, 'asked_node': dst, 'answer': result}

    # ------------------------------------------------------------------ #
    #  4. Генератор данных (@generator)
    # ------------------------------------------------------------------ #
    #  Обычный python-генератор. Сам по себе он ничего не передаёт по сети —
    #  это «источник» для стримов и Spawner'а (см. ниже). Регистрируется
    #  автоматически, Spawner найдёт его по имени 'demo.numbers'.

    @generator
    def numbers(self, data: dict):
        # ВНИМАНИЕ: это синхронный генератор — никаких await внутри.
        # Нужна пауза между элементами — делайте её на стороне потребителя.
        count = data.get('count', 10)
        for i in range(count):
            yield {'n': i, 'square': i * i}

    # ------------------------------------------------------------------ #
    #  5. Стрим «отсюда туда»: запускаем передачу данных удалённому узлу
    # ------------------------------------------------------------------ #
    #  Канонический паттерн отправки потока (так же работает compute_full):
    #
    #    Pipe          — буфер с ограничением размера (= backpressure:
    #                    если приёмник не успевает, генератор притормозит)
    #    Dispatcher    — раздаёт элементы генератора в один/несколько Pipe
    #    MsgPack-шаблон— кому доставить: dst-узел, сервис и ИМЯ СТРИМА
    #                    (method = stream_name потребителя!)
    #    attach_transport(pipe, template, router) — включить mesh-доставку.
    #
    #  На принимающей стороне должен существовать обработчик стрима
    #  с именем template.method — пара @stream_wrapper/@stream_consumer,
    #  у нас это 'process_numbers' (см. раздел 6).

    @rpc
    async def start_stream(self, data: dict) -> dict:
        target = data.get('target')                 # имя узла-получателя
        count = data.get('count', 10)
        buff = data.get('buff', 3)                  # размер буфера Pipe

        if not target or target == self.ctx.NODE:
            return {'ok': False, 'error': 'укажите target — другой узел сети'}
        if not self.ctx.network.router.get_transport_to(target):
            return {'ok': False, 'error': f'узел {target} недоступен'}

        pipe = self.ctx.memory.create_pipe(buff=buff)
        dispatcher = self.ctx.memory.create_dispatcher([pipe])

        template = MsgPack(
            source=self.ctx.NODE,
            dst=target,
            service='demo',
            method='process_numbers',               # ← stream_name потребителя
            label=str(uuid.uuid4()),
            data={'source_node': self.ctx.NODE},
        )

        # transport убран из сигнатуры — доставка всегда через Router,
        # поэтому стрим доходит даже через промежуточные узлы mesh
        self.ctx.memory.attach_transport(pipe, template, self.ctx.network.router)

        dispatcher.start(lambda: self.numbers({'count': count}))

        return {'ok': True, 'status': 'started', 'label': template.label, 'count': count}

    # ------------------------------------------------------------------ #
    #  6. Приём стрима: @stream_wrapper + @stream_consumer
    # ------------------------------------------------------------------ #
    #  Эти декораторы работают В ПАРЕ и связываются по имени стрима.
    #  Когда на этот узел приходит STREAM_OPEN c method='process_numbers':
    #
    #    1) wrapper(data) готовит контекст — его возврат станет ctx;
    #    2) framework кладёт в ctx служебное ctx['label'] — id потока,
    #       по которому отправляются ACK обратно генератору;
    #    3) consumer(pipe, ctx) читает чанки: async for chunk in pipe.
    #
    #  Backpressure по ACK: пока потребитель не подтвердил получение
    #  (send_stream_ack), отправитель держит паузу. Правило простое:
    #  первый ACK сразу после старта, дальше — prefetch, когда в буфере
    #  меньше buff элементов.

    @stream_wrapper('process_numbers')
    async def prepare_processing(self, data: dict) -> dict:
        return {
            'received': 0,
            'sum_squares': 0,
            'buff': 3,           # должен совпадать с buff трубы отправителя
            'source_node': (data or {}).get('source_node'),
        }

    @stream_consumer('process_numbers')
    async def consume_numbers(self, pipe: Pipe, ctx: dict):
        router = self.ctx.network.router
        label = ctx.get('label')
        buff = ctx['buff']

        # разрешить первую порцию данных
        if label:
            await router.send_stream_ack(label, buff)

        async for chunk in pipe:
            ctx['received'] += 1
            ctx['sum_squares'] += chunk.get('square', 0)

            self.log.info(f"chunk #{ctx['received']}: {chunk}")

            # prefetch — просим следующую порцию, пока обрабатываем текущую
            if label and pipe.size < buff:
                await router.send_stream_ack(label, buff)

        self.log.info(f"стрим завершён: получено {ctx['received']}, сумма квадратов {ctx['sum_squares']}")

    # ------------------------------------------------------------------ #
    #  7. Распределённые вычисления через Spawner
    # ------------------------------------------------------------------ #
    #  Spawner берёт локальный @generator и раздаёт его элементы всем
    #  подключенным рабочим узлам, где данные обрабатывает указанный
    #  обработчик стрима. Выше — наш же generator 'numbers' + потребитель
    #  'process_numbers'. Итог: одна команда — и все соседи считают параллельно.
    #
    #  Вызов делаем через сеть на самого себя (dst=self) — это одновременно
    #  демонстрация «локального шортката» mesh-RPC.

    @rpc
    async def spawn_workers(self, data: dict) -> dict:
        workers = data.get('workers_count', 2)
        return await self.ctx.network.call(
            dst=self.ctx.NODE,
            service='spawner',
            method='spawn',
            data={
                'generator_service': 'demo',
                'generator': 'numbers',
                'service': 'demo',
                'method': 'process_numbers',
                'workers_count': workers,
                'buff': 3,
            },
            timeout=15,
        )

    # ------------------------------------------------------------------ #
    #  Памятка по конвенциям
    # ------------------------------------------------------------------ #
    #  * один сервис = одна директория в services/, имя = имя каталога;
    #  * файлы/папки с префиксом "_" ServiceLoader игнорирует;
    #  * методы без @rpc НЕ видны из сети — всё остальное приватно;
    #  * сигнатура RPC-метода: (self, data: dict) -> dict | None;
    #  * ошибки: {'ok': False, 'error': '...'};
    #  * UI сервиса описывается в web_ui.py рядом (функция render(rpc))
    #    и добавляется в SERVICE_META (services/webpanel/service_meta.py);
    #  * логируйте через self.log — имя сервиса уже внутри.

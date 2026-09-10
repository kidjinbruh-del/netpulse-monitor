# GRID/spawner.py

import uuid

from netpulse.p2p_core.internal_modules.base import ModuleGeneric
from netpulse.p2p_core.networking.protocol import MsgPack
from netpulse.p2p_core.services.rpc import rpc


class Spawner(ModuleGeneric):
    def __init__(self, name, context):
        super().__init__(name, context)
        self.log.info('Spawner registered')

    @rpc
    async def spawn(self, data: dict):
        service_name = data.get('generator_service')
        generator_name = data.get('generator')
        target_service = data.get('service')
        target_method = data.get('method')
        workers_count = data.get('workers_count', 1)
        buff = data.get('buff', 3)
        init_data = data.get('init_data', {})

        gen_fn = self.ctx.services.get_generator(service_name, generator_name)
        if not gen_fn:
            available = self.ctx.services.list_generators(service_name)
            return {
                'error': f'generator not found: {service_name}.{generator_name}',
                'available': available,
            }

        def _generator():
            yield from gen_fn(init_data)

        # B8: берём connected из таблицы соседей и проверяем транспорт через
        # Router — client-side соседи раньше считались «not found»
        router = self.ctx.network.router
        reachable = [
            n.node_id for n in self.ctx.network.neighbor_table.connected()
            if router.get_transport_to(n.node_id)
        ]
        if len(reachable) < workers_count:
            return {'error': f'need {workers_count} nodes, have {len(reachable)}'}

        targets = reachable[:workers_count]
        pipes = [self.ctx.memory.create_pipe(buff=buff) for _ in range(workers_count)]
        dispatcher = self.ctx.memory.create_dispatcher(pipes)
        labels = []

        for index, node_id in enumerate(targets):
            label = str(uuid.uuid4())
            template = MsgPack(
                source=self.ctx.NODE,
                dst=node_id,
                service=target_service,
                method=target_method,
                label=label,
                data=init_data,
            )
            # PipeTransport через Router (mesh-маршрутизация)
            self.ctx.memory.attach_transport(
                pipes[index], template, self.ctx.network.router
            )
            labels.append(label)
            self.log.info(f'Pipe → {node_id} gen={service_name}.{generator_name}')

        dispatcher.start(_generator)
        self.log.info(f'Spawned {workers_count} workers')
        return {'status': 'started', 'labels': labels, 'count': workers_count}

    @rpc
    def list_generators(self, data: dict):
        """Список доступных генераторов для отладки."""
        service_name = data.get('service') if isinstance(data, dict) else None
        if service_name:
            return {service_name: self.ctx.services.list_generators(service_name)}
        # все сервисы
        return {
            name: self.ctx.services.list_generators(name)
            for name in self.ctx.services.services
        }
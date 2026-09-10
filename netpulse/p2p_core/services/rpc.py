# GRID/services/rpc.py

import inspect
from typing import Callable


def rpc(method):
    """Обычный RPC метод."""
    method._is_rpc = True
    return method


def generator(method):
    """Генератор данных для Dispatcher/Spawner."""
    method._is_generator = True
    return method


def get_generators(instance) -> dict:
    """Возвращает {name: bound_method} для всех @generator методов."""
    result = {}
    for name in dir(type(instance)):
        if name.startswith('_'):
            continue
        attr = getattr(type(instance), name, None)
        if callable(attr) and getattr(attr, '_is_generator', False):
            result[name] = getattr(instance, name)
    return result

def stream_wrapper(stream_name: str):
    """
    Обёртка над потребителем.
    Запускается первой, подготавливает контекст и передаёт pipe потребителю.
    Возвращаемое значение становится ctx для consumer.
    """

    def decorator(method):
        method._is_stream_wrapper = True
        method._stream_name = stream_name
        return method

    return decorator


def stream_consumer(stream_name: str):
    """
    Потребитель стрима.
    Получает (pipe, ctx) — ctx от wrapper или None если wrapper нет.
    Должен содержать цикл async for chunk in pipe.
    """

    def decorator(method):
        method._is_stream_consumer = True
        method._stream_name = stream_name
        return method

    return decorator


def get_rpc_methods(instance) -> dict:
    result = {}
    for name in dir(type(instance)):
        if name.startswith('_'):
            continue
        attr = getattr(type(instance), name, None)
        if callable(attr) and getattr(attr, '_is_rpc', False):
            result[name] = getattr(instance, name)
    return result


def get_stream_handlers(instance) -> dict:
    """
    Возвращает {stream_name: {'wrapper': method|None, 'consumer': method}}
    """
    handlers = {}
    for name in dir(type(instance)):
        if name.startswith('_'):
            continue
        attr = getattr(type(instance), name, None)
        if not callable(attr):
            continue
        bound = getattr(instance, name)
        if getattr(attr, '_is_stream_wrapper', False):
            sname = attr._stream_name
            handlers.setdefault(sname, {})['wrapper'] = bound
        if getattr(attr, '_is_stream_consumer', False):
            sname = attr._stream_name
            handlers.setdefault(sname, {})['consumer'] = bound
    return handlers

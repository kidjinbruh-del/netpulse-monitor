# Исключения
class MethodNotFound(Exception):
    def __init__(self, service, method):
        super().__init__(f'Method not found: {service}.{method}')


class RPCTimeout(Exception):
    def __init__(self, label, timeout):
        super().__init__(f'RPC timeout ({timeout}s): {label}')

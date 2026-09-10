import logging


class ModuleGeneric:
    def __init__(self, name: str, context):
        self.name = name
        self.ctx = context
        self.log = logging.getLogger(f"{name}")

    async def start(self): pass
    async def stop(self): pass
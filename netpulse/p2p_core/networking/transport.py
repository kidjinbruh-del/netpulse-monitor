# GRID/transport.py

import logging

from netpulse.p2p_core.networking.protocol import MsgPack, encode_pack

log = logging.getLogger('Transport')


class WebSocketTransport:
    """
    Универсальный транспорт — работает с обоими типами WS:
    - FastAPI WebSocket (server-side) — send_bytes()
    - websockets ClientConnection (client-side) — send(bytes → binary frame)

    Wire-формат: 1 binary WS frame = 1 msgpack dict (encode_pack).
    """
    def __init__(self, websocket):
        self.ws = websocket
        # определяем тип один раз при создании
        self._is_fastapi = hasattr(websocket, 'send_json')

    async def send(self, pack: MsgPack):
        payload = encode_pack(pack)
        if self._is_fastapi:
            await self.ws.send_bytes(payload)
        else:
            await self.ws.send(payload)
        log.debug(f'→ {pack.type} [{pack.label[:8]}] to {pack.dst}')

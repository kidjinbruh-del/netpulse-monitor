# GRID/local_ip.py

import logging
import socket
import time
from urllib.parse import urlparse

import psutil

log = logging.getLogger('LocalIP')

_LOOPBACK = '127.0.0.1'


class LocalIPResolver:
    """Локальный IP интерфейса mesh — вычисляется по запросу, кэш на TTL.

    Приоритет источников:
      1. Живые WS-подключения — фактический интерфейс, выбранный ОС.
         Клиентские: sockname транспорта websockets. Серверные: ASGI
         сокет не отдаёт, ищем соединение по удалённому адресу в TCP-таблице.
      2. UDP-трюк к хосту пира из конфига — ОС выберет тот же интерфейс,
         что и для будущего подключения к нему.
      3. Фолбэк psutil: поднятый не-loopback IPv4 (без APIPA), через
         который есть маршрут наружу (bind+connect, пакеты не ходят).
    """

    def __init__(self, context):
        self.ctx = context
        self._cached: str | None = None
        self._expires_at: float = 0.0

    def get(self) -> str:
        now = time.monotonic()
        if self._cached and now < self._expires_at:
            return self._cached

        ip = (
            self._from_live_connections()
            or self._via_peer_route()
            or self._psutil_fallback()
            or _LOOPBACK
        )

        ttl = self.ctx.config.network.ip_ttl_sec
        self._cached = ip
        self._expires_at = now + ttl
        log.debug(f'Local IP: {ip} (cached {ttl}s)')
        return ip

    # ------------------------------------------------------------------ #
    #  1. Живые WS-подключения
    # ------------------------------------------------------------------ #

    def _from_live_connections(self) -> str | None:
        net = getattr(self.ctx, 'network', None)
        if net is None:
            return None

        loopback_only = None

        # клиентские подключения: сокет websockets доступен напрямую
        for ws in list(net.router._client_ws.values()):
            ip = self._client_sock_ip(ws)
            if not ip:
                continue
            if not ip.startswith('127.'):
                return ip
            loopback_only = ip

        # серверные подключения: ищем установленное соединение по паре
        # (наш порт, удалённый адрес из websocket.client)
        remotes = {
            (c[0], c[1]) for c in (
                getattr(node.ws, 'client', None)
                for node in list(net.nodes_manager.nodes.values())
            ) if c
        }
        if remotes:
            for conn in psutil.net_connections(kind='tcp'):
                if (conn.status != psutil.CONN_ESTABLISHED
                        or not conn.raddr or not conn.laddr):
                    continue
                if conn.laddr.port != net.port:
                    continue
                if (conn.raddr.ip, conn.raddr.port) not in remotes:
                    continue
                if not conn.laddr.ip.startswith('127.'):
                    return conn.laddr.ip
                loopback_only = conn.laddr.ip

        return loopback_only

    @staticmethod
    def _client_sock_ip(ws) -> str | None:
        try:
            sockname = ws.transport.get_extra_info('sockname')
            return sockname[0] if sockname else None
        except Exception:
            return None

    # ------------------------------------------------------------------ #
    #  2. Маршрут к настраиваемому пиру
    # ------------------------------------------------------------------ #

    def _via_peer_route(self) -> str | None:
        for peer in self.ctx.config.local.peers:
            host = urlparse(peer.uri).hostname
            if not host:
                continue
            ip = self._udp_source(host)
            if ip and not ip.startswith('127.'):
                return ip
        return None

    @staticmethod
    def _udp_source(host: str) -> str | None:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((host, 80))
            return s.getsockname()[0]
        except OSError:
            return None
        finally:
            s.close()

    # ------------------------------------------------------------------ #
    #  3. Фолбэк psutil
    # ------------------------------------------------------------------ #

    def _psutil_fallback(self) -> str | None:
        try:
            addrs = psutil.net_if_addrs()
            stats = psutil.net_if_stats()
        except Exception:
            return None

        candidates = []
        for name, infos in addrs.items():
            if name.lower().startswith('lo'):
                continue
            if name not in stats or not stats[name].isup:
                continue
            for info in infos:
                if info.family != socket.AF_INET:
                    continue
                ip = info.address
                # 169.254.x.x (APIPA) — признак адаптера без шлюза/DHCP
                if ip.startswith('127.') or ip.startswith('169.254.'):
                    continue
                candidates.append(ip)

        for ip in candidates:
            if self._has_outbound_route(ip):
                return ip
        return candidates[0] if candidates else None

    @staticmethod
    def _has_outbound_route(source_ip: str) -> bool:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.bind((source_ip, 0))
            s.connect(('8.8.8.8', 80))
            return True
        except OSError:
            return False
        finally:
            s.close()

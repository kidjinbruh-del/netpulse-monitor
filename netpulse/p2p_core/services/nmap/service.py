"""Service: Nmap integration — LAN discovery, port scan, OS detection.

RPC-методы:
    status()              — доступность nmap, версия, путь к бинарнику
    ping_sweep(data)      — живые хосты в подсети/диапазоне (-sn)
    ports(data)           — сканирование портов одного хоста (-sT/-sV)
    scan(data)            — комбинированный: живые хосты + порты + ОС

Nmap ищется в путях по умолчанию (Windows: Program Files) и в PATH.
Все сетевые операции асинхронные (create_subprocess_exec) — event loop
ноды не блокируется. XML-парсинг вынесен в чистые функции для юнит-тестов.
"""

import asyncio
import logging
import os
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

from netpulse.p2p_core.internal_modules.base import ModuleGeneric
from netpulse.p2p_core.services.rpc import rpc

log = logging.getLogger('NmapService')

# стандартные пути установки
_NMAP_CANDIDATES = [
    r"C:\Program Files (x86)\Nmap\nmap.exe",
    r"C:\Program Files\Nmap\nmap.exe",
    r"C:\Nmap\nmap.exe",
    "/usr/bin/nmap",
    "/usr/local/bin/nmap",
    "/opt/homebrew/bin/nmap",
]

# версии скан-таймаутов по умолчанию, сек
_SWEEP_TIMEOUT = 120
_PORTS_TIMEOUT = 300
_SCAN_TIMEOUT = 360

# порты по умолчанию для комбинированного scan()
_DEFAULT_PORTS = "22,80,443,445,3389,5900,8000,8080,8443,9000,9001,9100"


def find_nmap() -> str | None:
    """Найти исполняемый файл nmap: стандартные пути → PATH."""
    for p in _NMAP_CANDIDATES:
        if os.path.isfile(p):
            return p
    return shutil.which('nmap')


def nmap_version(path: str) -> str:
    """Версия nmap. Безопасно по умолчанию ''."""
    try:
        out = os.popen(f'"{path}" --version').read()  # первый 2 строки
        for line in out.splitlines():
            line = line.strip()
            if line.lower().startswith('nmap version'):
                return line.split('version', 1)[1].strip()
    except Exception:
        pass
    return ''


# ------------------------------------------------------------------ #
#  Парсеры XML-вывода  (-oX -)  — чистые функции, тестируемые без nmap
# ------------------------------------------------------------------ #

def _child_attr(parent, path, attr, default=''):
    """Безопасное чтение атрибута дочернего элемента (ElementTree не
    поддерживает XPath 'tag/@attr' — только предикаты в скобках)."""
    el = parent.find(path)
    if el is None:
        return default
    return el.get(attr, default)


def _host_state(host) -> str:
    st = host.find('status')
    return st.get('state', 'down') if st is not None else 'down'


def _mac_addr(host) -> tuple[str, str]:
    """(addr, vendor) для MAC-address элемента."""
    a = host.find('address[@addrtype="mac"]')
    if a is None:
        return '', ''
    return a.get('addr', ''), a.get('vendor', '')


def parse_sweep_xml(xml_text: str) -> list[dict]:
    """Разобрать вывод `nmap -sn -oX -`: живые хосты с MAC и hostname."""
    hosts = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts
    for host in root.findall('host'):
        if _host_state(host) != 'up':
            continue
        addrs = {
            a.get('addrtype'): a.get('addr')
            for a in host.findall('address')
        }
        mac, vendor = _mac_addr(host)
        hostname = ''
        names = host.findall('hostnames/hostname')
        if names:
            hostname = names[0].get('name', '')
        hosts.append({
            'ip':        addrs.get('ipv4', ''),
            'ipv6':      addrs.get('ipv6', ''),
            'mac':       mac,
            'vendor':    vendor,
            'hostname':  hostname,
            'uptime':    host.findtext('uptime/seconds', ''),
            'os':        _extract_os(host),
        })
    return hosts


def parse_ports_xml(xml_text: str) -> dict:
    """Разобрать вывод `nmap -sT -sV -oX -` для ОДНОГО хоста.

    Возвращает {host, state, ports:[{port, proto, state, service, product, version}],
    os, mac, hostname, uptime}.
    """
    result = {'host': '', 'state': 'down', 'ports': [],
              'os': [], 'mac': '', 'hostname': '', 'uptime': ''}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return result
    host = root.find('host')
    if host is None:
        return result
    result['state'] = _host_state(host)
    addrs = {a.get('addrtype'): a.get('addr') for a in host.findall('address')}
    result['host'] = addrs.get('ipv4', addrs.get('ipv6', ''))
    result['mac'], _ = _mac_addr(host)
    nm_el = host.find('hostnames/hostname')
    result['hostname'] = nm_el.get('name', '') if nm_el is not None else ''
    result['uptime'] = host.findtext('uptime/seconds', '')
    result['os'] = _extract_os(host)

    for port in host.findall('ports/port'):
        ps = _child_attr(port, 'state', 'state', 'closed')
        result['ports'].append({
            'port':      int(port.get('portid', 0)),
            'proto':     port.get('protocol', ''),
            'state':     ps,
            'service':   _child_attr(port, 'service', 'name', ''),
            'product':   _child_attr(port, 'service', 'product', ''),
            'version':   _child_attr(port, 'service', 'version', ''),
            'extra':     _child_attr(port, 'service', 'extrainfo', ''),
        })
    return result


def _extract_os(host) -> list[dict]:
    """Определения ОС из <os>: osmatch-блоки с точностью."""
    out = []
    for m in host.findall('os/osmatch'):
        out.append({
            'name':    m.get('name', ''),
            'accuracy': int(m.get('accuracy', 0) or 0),
            'classes': [c.get('type', '') for c in m.findall('osclass')],
        })
    return out


# ------------------------------------------------------------------ #
#  Сервис
# ------------------------------------------------------------------ #

class Nmap(ModuleGeneric):
    def __init__(self, name, context):
        super().__init__(name, context)
        self._nmap = find_nmap()
        self._version = nmap_version(self._nmap) if self._nmap else ''

    # ------------------------------------------------------------------ #
    #  Утилиты
    # ------------------------------------------------------------------ #

    async def _run(self, args: list[str], timeout: int):
        """Запустить nmap, вернуть stdout (для -oX -)."""
        if not self._nmap:
            raise RuntimeError('nmap не установлен (или не найден в PATH)')
        cmd = [self._nmap, *args]
        log.info(f'nmap: {" ".join(cmd)}')
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise RuntimeError(
                f'nmap {timeout}с timeout: {" ".join(args)}')
        if proc.returncode not in (0, None):
            raise RuntimeError(
                f'nmap exited {proc.returncode}: {" ".join(args)}')
        return out.decode('utf-8', errors='replace')

    async def _target_hosts(self, data: dict) -> list[str]:
        """Живые хосты в цели (работает и на одиночном хосте, и на подсети)."""
        xml = await self._run(
            ['-sn', '-oX', '-', str(data.get('target'))],
            int(data.get('timeout', _SWEEP_TIMEOUT)),
        )
        return [h['ip'] for h in parse_sweep_xml(xml) if h['ip']]

    # ------------------------------------------------------------------ #
    #  RPC
    # ------------------------------------------------------------------ #

    @rpc
    def status(self, data=None):
        """Доступность nmap."""
        if not self._nmap:
            return {'ok': False, 'error': 'nmap не найден в системе',
                    'available': False}
        return {'ok': True, 'available': True,
                'path': self._nmap, 'version': self._version}

    @rpc
    async def ping_sweep(self, data: dict):
        """Обнаружение живых хостов: {target: '192.168.1.0/24|host|range'}."""
        data = data or {}
        target = str(data.get('target') or '').strip()
        if not target:
            return {'ok': False, 'error': 'укажите target (host/подсеть/диапазон)'}
        try:
            xml = await self._run(
                ['-sn', '-oX', '-', target],
                int(data.get('timeout', _SWEEP_TIMEOUT)),
            )
        except Exception as e:
            log.warning(f'ping_sweep {target} failed: {e}')
            return {'ok': False, 'error': str(e)}
        hosts = parse_sweep_xml(xml)
        return {'ok': True, 'target': target, 'total': len(hosts),
                'hosts': hosts}

    @rpc
    async def ports(self, data: dict):
        """Сканирование портов одного хоста.

        data: {target, ports?: '22,80'|None(общий скан), timeout?, version_detect: true}
        """
        data = data or {}
        target = str(data.get('target') or '').strip()
        if not target:
            return {'ok': False, 'error': 'укажите target'}

        args = ['-Pn', '-oX', '-']
        if data.get('version_detect', True):
            args.append('-sV')          # определение версий сервисов
        args.append('-sT')              # TCP-connect (не требует прав)
        ports = str(data.get('ports') or '').strip()
        if ports:
            args += ['-p', ports]
        args.append(target)

        try:
            xml = await self._run(args, int(data.get('timeout', _PORTS_TIMEOUT)))
        except Exception as e:
            log.warning(f'ports {target} failed: {e}')
            return {'ok': False, 'error': str(e)}
        info = parse_ports_xml(xml)
        open_ports = [p for p in info['ports'] if p['state'] == 'open']
        return {'ok': True, 'target': target, 'state': info['state'],
                'os': info['os'], 'mac': info['mac'], 'hostname': info['hostname'],
                'open': len(open_ports), 'ports': info['ports']}

    @rpc
    async def scan(self, data: dict):
        """Комбинированный скан: живые хосты → базовые порты + ОС каждого.

        data: {target?, ports?: '22,80'|None, timeout?, sweep_only?: bool}
        target не задан — сканируется локальная default-подсеть? Нет: только
        явная цель (безопасность). Выбор цели — ответственность оператора.
        """
        data = data or {}
        target = str(data.get('target') or '').strip()
        if not target:
            return {'ok': False, 'error': 'укажите target'}
        ports = str(data.get('ports') or _DEFAULT_PORTS).strip()
        try:
            hosts = await self._target_hosts(data)
        except Exception as e:
            return {'ok': False, 'error': str(e)}

        if not hosts:
            return {'ok': True, 'target': target, 'total': 0, 'hosts': [],
                    'error': 'живых хостов не найдено'}

        if data.get('sweep_only'):
            return {'ok': True, 'target': target, 'total': len(hosts),
                    'hosts': [{'ip': h} for h in hosts]}

        timeout = int(data.get('timeout', _SCAN_TIMEOUT))

        async def _scan_one(ip: str):
            try:
                xml = await self._run(
                    ['-Pn', '-sV', '-sT', '-p', ports, '-oX', '-', ip],
                    max(30, timeout),
                )
                return parse_ports_xml(xml)
            except Exception as e:
                return {'host': ip, 'state': 'error', 'error': str(e),
                        'ports': [], 'os': []}

        results = await asyncio.gather(*[_scan_one(h) for h in hosts])
        return {'ok': True, 'target': target, 'total': len(results),
                'ports': ports, 'hosts': results}
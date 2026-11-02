"""Local IPv4 interface selection and bounded LAN discovery helpers."""
import ipaddress
import re
import socket
import psutil

VIRTUAL = ('vpn', 'xray', 'tun', 'tap', 'wireguard', 'wintun', 'tailscale',
           'zerotier', 'virtual', 'vmware', 'vethernet', 'docker', 'loopback')


def interfaces():
    stats = psutil.net_if_stats()
    result = []
    for name, addresses in psutil.net_if_addrs().items():
        stat = stats.get(name)
        if stat and not stat.isup:
            continue
        for address in addresses:
            if address.family != socket.AF_INET or not address.netmask:
                continue
            try:
                iface = ipaddress.IPv4Interface(address.address + '/' + address.netmask)
            except ValueError:
                continue
            if iface.ip.is_loopback or iface.ip.is_link_local or iface.ip.is_unspecified:
                continue
            virtual = any(word in name.casefold() for word in VIRTUAL)
            result.append({'id': name + '|' + str(iface.ip), 'name': name,
                'ip': str(iface.ip), 'subnet': str(iface.network), 'virtual': virtual,
                'hosts': max(0, iface.network.num_addresses - (2 if iface.network.prefixlen < 31 else 0)),
                'speed': stat.speed if stat else 0})
    return sorted(result, key=lambda item: (item['virtual'], -item['speed'], item['name'], item['ip']))


def select(identifier=None):
    available = interfaces()
    if not available:
        raise ValueError('Нет активного IPv4-интерфейса локальной сети')
    if identifier:
        choice = next((item for item in available if item['id'] == identifier), None)
        if not choice:
            raise ValueError('Выбранный сетевой интерфейс больше недоступен')
        return choice
    return available[0]


def valid_mac(value):
    value = value.lower().replace('-', ':')
    if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', value):
        return ''
    if int(value[:2], 16) & 1 or value == '00:00:00:00:00:00':
        return ''
    return value


def arp_entries(text, subnet):
    network = ipaddress.ip_network(subnet)
    output = {}
    for line in text.splitlines():
        match = re.search(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b.*?([0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5})', line)
        if not match:
            continue
        try:
            address = ipaddress.IPv4Address(match[1])
        except ValueError:
            continue
        mac = valid_mac(match[2])
        endpoint = network.prefixlen < 31 and address in (network.network_address, network.broadcast_address)
        if mac and address in network and not endpoint:
            output[str(address)] = mac
    return output


def ping_reply(returncode, text):
    # Windows can return 0 for an ICMP destination-unreachable response.
    if returncode != 0:
        return False
    return bool(re.search(r'\bttl\s*[=:]\s*\d+', text, re.IGNORECASE))

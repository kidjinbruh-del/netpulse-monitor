"""Unit: l2map (mac_iso, find_switches, resolve_ptrs) + proxmox (disabled)."""
import sqlite3

import pytest

from netpulse import l2map as L2
from netpulse.proxmox import ProxmoxClient


class FakeDB:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
            CREATE TABLE hosts (id INTEGER PRIMARY KEY, name TEXT, ip TEXT,
                os TEXT, online INTEGER DEFAULT 1,
                health_score INTEGER DEFAULT 100,
                first_seen TEXT, last_seen TEXT, updated_at TEXT);
            CREATE TABLE lan_devices (
                mac TEXT, ip TEXT, hostname TEXT, alias TEXT, vendor TEXT,
                first_seen TEXT, last_seen TEXT);
            CREATE TABLE l2_ports (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
                mac TEXT, switch_ip TEXT, if_index INTEGER, if_name TEXT,
                UNIQUE(mac, switch_ip));
            CREATE TABLE proxmox_status (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT,
                nodes TEXT, vms TEXT);
        """)

    def execute(self, sql, params=(), fetch=False):
        cur = self.conn.execute(sql, params)
        self.conn.commit()
        if fetch:
            return [dict(r) for r in cur.fetchall()]
        return cur.rowcount


class FakeSvc:
    def __init__(self, cfg=None):
        self.cfg = cfg or {}
        self.db = FakeDB()
        from netpulse.inventory import Inventory
        self.inventory = Inventory(self)


def test_mac_iso():
    assert L2.mac_iso("001122334455") == "00:11:22:33:44:55"
    assert L2.mac_iso("00:11:22:33:44:55") == "00:11:22:33:44:55"
    assert L2.mac_iso("00-11-22-33-44-55") == "00:11:22:33:44:55"
    # десятичные суб-идентификаторы OID (список) → корректный MAC
    assert L2.mac_iso([0, 17, 34, 51, 68, 85]) == "00:11:22:33:44:55"
    assert L2.mac_iso("zzzzzzzzzzzz") is None
    assert L2.mac_iso("short") is None
    assert L2.mac_iso(None) is None


def test_find_switches():
    svc = FakeSvc()
    lm = L2.L2Map(svc)
    # пустой парк → заглушка шлюза
    assert lm.find_switches() == [{"name": "192.168.1.1", "ip": "192.168.1.1"}]
    svc.db.execute("INSERT INTO hosts (name, ip, online) VALUES (?,?,?)",
                   ("sw1", "10.0.0.2", 1))
    assert lm.find_switches() == [{"name": "sw1", "ip": "10.0.0.2"}]
    assert lm.status() == {"ports": 0, "lldp": 0, "scanning": False}


def test_ports_for_normalizes():
    svc = FakeSvc()
    lm = L2.L2Map(svc)
    svc.db.execute(
        "INSERT INTO l2_ports (timestamp, mac, switch_ip) VALUES (?,?,?)",
        ("2024-01-01", "aa:bb:cc:dd:ee:ff", "10.0.0.2"))
    rows = lm.ports_for("AA-BB-CC-DD-EE-FF")
    assert len(rows) == 1 and rows[0]["switch_ip"] == "10.0.0.2"
    assert lm.ports_for("bad") == []


def test_resolve_ptrs_skips(monkeypatch):
    svc = FakeSvc()
    svc.db.execute("INSERT INTO lan_devices (mac, ip, hostname) VALUES (?,?,?)",
                   ("aa:bb:cc:dd:ee:ff", "10.255.255.254", "-"))
    lm = L2.L2Map(svc)
    monkeypatch.setattr("socket.gethostbyaddr", lambda ip: (_ for _ in ()).throw(
        OSError("no ptr")))
    assert lm.resolve_ptrs() == 0


def test_proxmox_disabled():
    client = ProxmoxClient(FakeSvc({"proxmox": {"enabled": False}}))
    res = client.poll()
    assert res["ok"] is False and "отключ" in res["error"]
    assert client.status()["ok"] is False


def test_proxmox_url_build():
    svc = FakeSvc({"proxmox": {"enabled": True, "host": "pve.local",
                               "token_id": "u@t", "token_secret": "s"}})
    client = ProxmoxClient(svc)
    assert client._base_url() == "https://pve.local:8006/api2/json"
    assert client._fmt_vm({"type": "qemu", "cpu": 0.5, "mem": 1073741824,
                           "maxmem": 2147483648, "disk": 1073741824,
                           "vmid": 100})["type"] == "vm"

"""Unit: infra (BER-кодек, парсинг SNMP, diff, классификация)."""
import sqlite3

import pytest

from netpulse import infra as I


class FakeDB:
    def __init__(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
            CREATE TABLE hosts (
                id INTEGER PRIMARY KEY, name TEXT, ip TEXT, dtype TEXT,
                dtype_manual INTEGER DEFAULT 0, online INTEGER DEFAULT 1,
                health_score INTEGER DEFAULT 100, sys_name TEXT,
                sys_descr TEXT, uptime_h REAL, snmp_at TEXT, os TEXT,
                last_seen TEXT);
            CREATE TABLE infra_snaps (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT,
                host_id INTEGER, snapshot TEXT);
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


def test_ber_oid_roundtrip():
    for oid in ["1.3.6.1.2.1.1.1.0", "1.3.6.1.4.1.311", "1.3.6.1.2.1.1.3.0"]:
        tag, content, _ = I.ber_parse(I.ber_oid(oid), 0)
        assert tag == 0x06
        assert I.oid_decode(content) == oid


def test_ber_int_roundtrip():
    for v in [0, 1, 127, 128, 300, 360000]:
        tag, content, _ = I.ber_parse(I.ber_int(v), 0)
        assert tag == 0x02
        assert I.value_convert(tag, content) == v


def _fake_response():
    """Минимальный SNMP Response c sysName=TEST + sysUpTime."""
    vb1 = I.ber_tlv(0x30, I.ber_oid("1.3.6.1.2.1.1.5.0") + I.ber_tlv(0x04, b"TEST"))
    vb2 = I.ber_tlv(0x30, I.ber_oid("1.3.6.1.2.1.1.3.0") + I.ber_tlv(0x43, b"\x01\x02"))
    vblist = I.ber_tlv(0x30, vb1 + vb2)
    pdu = I.ber_tlv(0xA2, I.ber_int(1) + I.ber_tlv(0x02, b"\x00")
                    + I.ber_tlv(0x02, b"\x00") + vblist)
    return I.ber_tlv(0x30, I.ber_int(1) + I.ber_octet("public") + pdu)


def test_parse_snmp_response():
    out = I.parse_snmp_response(_fake_response())
    assert out["sysName"] == "TEST"
    assert out["sysUpTime"] == 0x102
    assert I.parse_snmp_response(b"junk") is None
    assert I.parse_snmp_response(I.ber_tlv(0x30, b"")) is None


def test_classify():
    svc = FakeSvc()
    inf = I.Infra(svc)
    assert inf.classify("1.2.3.4", {"sysDescr": "Cisco Catalyst 2960"}) == "switch"
    assert inf.classify("1.2.3.4", {"sysDescr": "MikroTik RouterOS"}) == "router"
    assert inf.classify("1.2.3.4", {"sysDescr": "Linux box"}) == "infra"
    assert inf.classify("1.2.3.4", winrm_ok=True) == "pc"
    assert inf.classify("1.2.3.4") is None


def test_set_dtype_validation():
    inf = I.Infra(FakeSvc())
    assert inf.set_dtype(1, "router") == {"ok": True}
    bad = inf.set_dtype(1, "toaster")
    assert bad["ok"] is False and "тип" in bad["error"]


def test_snap_diff():
    svc = FakeSvc()
    svc.db.execute("INSERT INTO hosts (id, name, ip) VALUES (1,'h','1.1.1.1')")
    inf = I.Infra(svc)
    assert inf.snap_diff(1) == {"diff": [], "note": "нужно минимум 2 снэпшота"}
    inf.save_snapshot(1)
    svc.db.execute("UPDATE hosts SET sys_name='R1' WHERE id=1")
    inf.save_snapshot(1)
    d = inf.snap_diff(1)
    assert {"field": "sys_name", "old": None, "new": "R1"} in d["diff"]


def test_whitelist_match():
    assert I.Infra.match_rules([{"path": "C:\\Tools"}], path="c:\\tools\\app.exe") is True
    assert I.Infra.match_rules([{"path": "C:\\Tools"}], path="D:\\other") is False
    assert I.Infra.match_rules([], path="x") is False


def test_value_convert_variants():
    assert I.value_convert(0x04, "привет".encode()) == "привет"
    assert I.value_convert(0x05, b"") == ""
    assert I.value_convert(0xFF, b"\xab") == "ab"

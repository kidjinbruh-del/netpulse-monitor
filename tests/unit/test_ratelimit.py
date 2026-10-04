"""Unit: BruteForceProtection + IP allowlist."""
from netpulse.server.middleware.auth import AuthMiddleware
from netpulse.server.middleware.rate_limit import BruteForceProtection


def test_brute_force_blocks_after_max():
    bf = BruteForceProtection(max_fails=3, block_sec=600)
    assert bf.is_blocked("1.2.3.4") == 0
    assert bf.register_fail("1.2.3.4") is False
    assert bf.register_fail("1.2.3.4") is False
    assert bf.register_fail("1.2.3.4") is True  # 3rd → blocked
    assert bf.is_blocked("1.2.3.4") > 0


def test_brute_force_reset():
    bf = BruteForceProtection(max_fails=1, block_sec=600)
    bf.register_fail("5.6.7.8")
    assert bf.is_blocked("5.6.7.8") > 0
    bf.reset("5.6.7.8")
    assert bf.is_blocked("5.6.7.8") == 0


def test_brute_force_window_resets_counter():
    import time
    bf = BruteForceProtection(max_fails=5, block_sec=0)
    bf.register_fail("9.9.9.9")
    time.sleep(0.02)
    # окно истекло → счётчик с нуля, блока нет
    assert bf.is_blocked("9.9.9.9") == 0


def test_ip_in_network():
    assert AuthMiddleware._ip_in_network("192.168.1.50", "192.168.1.0/24") is True
    assert AuthMiddleware._ip_in_network("10.0.0.1", "192.168.1.0/24") is False
    assert AuthMiddleware._ip_in_network("127.0.0.1", "127.0.0.1") is True
    assert AuthMiddleware._ip_in_network("bad", "192.168.1.0/24") is False

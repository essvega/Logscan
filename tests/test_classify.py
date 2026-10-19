import ipaddress

import pytest

from logscan.classify import SCOPES, classify, is_public


@pytest.mark.parametrize(
    "ip, scope",
    [
        ("8.8.8.8", "public"),
        ("132.163.97.2", "public"),
        ("10.1.2.3", "private"),
        ("172.20.14.227", "private"),
        ("172.32.0.1", "public"),
        ("192.168.1.1", "private"),
        ("100.64.0.1", "shared"),
        ("127.0.0.1", "loopback"),
        ("169.254.1.1", "link-local"),
        ("224.0.0.251", "multicast"),
        ("192.0.2.1", "documentation"),
        ("198.18.0.1", "benchmark"),
        ("0.0.0.0", "unspecified"),
        ("255.255.255.255", "broadcast"),
        ("240.0.0.1", "reserved"),
        ("0.1.2.3", "reserved"),
        ("2001:4860:4860::8888", "public"),
        ("2001:db8::1", "documentation"),
        ("fd00::1", "private"),
        ("fe80::1", "link-local"),
        ("ff02::1", "multicast"),
        ("::1", "loopback"),
        ("::", "unspecified"),
        ("::ffff:8.8.8.8", "public"),
        ("::ffff:10.0.0.1", "private"),
        ("2002::1", "reserved"),
        ("4000::1", "reserved"),
    ],
)
def test_classify(ip, scope):
    assert classify(ipaddress.ip_address(ip)) == scope
    assert scope in SCOPES


def test_is_public():
    assert is_public(ipaddress.ip_address("1.1.1.1"))
    assert not is_public(ipaddress.ip_address("10.0.0.1"))

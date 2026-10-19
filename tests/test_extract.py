import ipaddress

import pytest

from logscan.extract import extract


def ips(text, **kw):
    return [m.ip for m in extract(text, **kw)]


@pytest.mark.parametrize(
    "text, expected",
    [
        ("connect to 8.8.8.8 failed", ["8.8.8.8"]),
        ("a=1.1.1.1,b=9.9.9.9;", ["1.1.1.1", "9.9.9.9"]),
        ("(203.0.113.7)", ["203.0.113.7"]),
        ("end of sentence 4.4.4.4.", ["4.4.4.4"]),
        ("255.255.255.255 0.0.0.0", ["255.255.255.255", "0.0.0.0"]),
        ("version 1.2.3.4.5", []),
        ("zero padded 01.2.3.4", []),
        ("out of range 256.1.1.1 1.2.3.999", []),
        ("timestamp 00:00:01. 567 §", []),
        ("uuid e9755e02-e895-4178-ad14-4ea170032fe4", []),
    ],
)
def test_ipv4(text, expected):
    assert ips(text) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        ("dns 2001:4860:4860::8888 ok", ["2001:4860:4860::8888"]),
        ("full 2001:0db8:0000:0000:0000:0000:0000:0001", ["2001:db8::1"]),
        ("loop ::1 here", ["::1"]),
        ("link fe80::1%eth0 up", ["fe80::1"]),
        ("mapped ::ffff:192.0.2.1", ["::ffff:192.0.2.1"]),
        ("[2606:4700::1111]:443", ["2606:4700::1111"]),
        ("end 2001:db8::2.", ["2001:db8::2"]),
        ("mac aa:bb:cc:dd:ee:ff", []),
        ("time 12:30:45 and 1:2:3", []),
        ("c++ std::string and a :: b", []),
    ],
)
def test_ipv6(text, expected):
    # Compare parsed addresses: str() of IPv4-mapped addresses differs across Python versions.
    assert [m.address for m in extract(text)] == [ipaddress.ip_address(e) for e in expected]


def test_ports():
    found = extract("tcp 1.2.3.4:8080 -> [2001:db8::5]:53 and 5.6.7.8:99999")
    assert [(m.ip, m.port) for m in found] == [("1.2.3.4", 8080), ("2001:db8::5", 53), ("5.6.7.8", None)]


def test_order_and_version_filters():
    line = "2001:db8::1 then 10.0.0.1"
    assert ips(line) == ["2001:db8::1", "10.0.0.1"]
    assert ips(line, ipv6=False) == ["10.0.0.1"]
    assert ips(line, ipv4=False) == ["2001:db8::1"]


def test_match_properties():
    (m,) = extract("x 9.9.9.9:53")
    assert m.version == 4 and m.port == 53 and "x 9.9.9.9:53"[m.start : m.end] == "9.9.9.9:53"

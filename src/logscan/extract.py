"""Find IPv4 and IPv6 addresses (with optional ports) inside free-form text."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterator, Optional, Union

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"

# A dotted quad that is not part of a longer dotted/numeric run, so version
# strings such as "1.2.3.4.5" and zero-padded values such as "01.2.3.4" are
# rejected. An optional ":port" suffix is captured.
IPV4_RE = re.compile(rf"(?<![\w.])(?P<ip>(?:{_OCTET}\.){{3}}{_OCTET})(?!\.?\d)(?::(?P<port>\d{{1,5}})(?!\d))?")

# IPv6 is too irregular for a precise regex, so this matches generous
# candidates (optionally bracketed, with a zone id and a port) and every
# candidate is then validated by the ipaddress module.
IPV6_RE = re.compile(
    r"(?<![\w:.])"
    r"(?:\[(?P<bip>[0-9A-Fa-f:.]+)(?:%[\w.-]+)?\](?::(?P<port>\d{1,5}))?"
    r"|(?P<ip>(?:[0-9A-Fa-f]{0,4}:){2,7}(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f]{1,4})?)(?:%[\w.-]+)?)"
    r"(?![\w:]|\.\d)"
)


_HEX = re.compile(r"[0-9A-Fa-f]")
# Cheap gate run before the expensive IPv6 regex: every IPv6 literal either
# contains "::" or six consecutive "group:" runs.
_V6_GATE = re.compile(r"::|(?:[0-9A-Fa-f]{1,4}:){6}")


@dataclass(frozen=True)
class Match:
    """A single address found in a line of text."""

    address: IPAddress
    port: Optional[int]
    start: int
    end: int

    @property
    def ip(self) -> str:
        return str(self.address)

    @property
    def version(self) -> int:
        return self.address.version


_v4 = lru_cache(maxsize=65536)(ipaddress.IPv4Address)
_v6 = lru_cache(maxsize=65536)(ipaddress.IPv6Address)


def _plausible_v6(raw: str) -> bool:
    # A valid IPv6 literal either compresses zeros ("::") or spells out all
    # groups; this cheaply rejects timestamps ("12:30:45") and MAC addresses.
    if not _HEX.search(raw):
        return False  # a bare "::" in prose or C++ code is noise
    if "::" in raw:
        return True
    colons = raw.count(":")
    return colons == 7 or (colons == 6 and "." in raw)


def _port(raw: Optional[str]) -> Optional[int]:
    if raw is None:
        return None
    value = int(raw)
    return value if 0 < value <= 65535 else None


def _iter_ipv4(line: str) -> Iterator[Match]:
    for m in IPV4_RE.finditer(line):
        yield Match(_v4(m.group("ip")), _port(m.group("port")), m.start(), m.end())


def _iter_ipv6(line: str) -> Iterator[Match]:
    for m in IPV6_RE.finditer(line):
        raw = m.group("bip") or m.group("ip")
        if not raw or not _plausible_v6(raw):
            continue
        try:
            addr = _v6(raw)
        except ValueError:
            continue
        yield Match(addr, _port(m.group("port")), m.start(), m.end())


def extract(line: str, *, ipv4: bool = True, ipv6: bool = True) -> list[Match]:
    """Return every address in ``line`` in the order it appears.

    >>> [m.ip for m in extract("connect to 8.8.8.8:53 and [2001:db8::1]:443")]
    ['8.8.8.8', '2001:db8::1']
    """
    v4 = list(_iter_ipv4(line)) if ipv4 and "." in line else []
    v6 = list(_iter_ipv6(line)) if ipv6 and ":" in line and _V6_GATE.search(line) else []
    if not v6:
        return v4
    if v4:
        # Drop dotted quads that are the tail of an IPv6 address such as ::ffff:1.2.3.4.
        v4 = [a for a in v4 if not any(b.start <= a.start < b.end for b in v6)]
    return sorted(v4 + v6, key=lambda m: m.start)

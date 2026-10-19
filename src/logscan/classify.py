"""Classify addresses into scopes (public, private, loopback, bogon, ...).

The tables below are explicit so results do not drift between Python
versions, whose ``is_private``/``is_global`` definitions have changed over time.
Sources: IANA IPv4/IPv6 Special-Purpose Address Registries (RFC 6890 and updates).
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

from .extract import IPAddress

PUBLIC = "public"

SCOPES = (
    "public",
    "private",
    "shared",
    "loopback",
    "link-local",
    "multicast",
    "documentation",
    "benchmark",
    "unspecified",
    "broadcast",
    "reserved",
)

_V4_TABLE = [
    ("0.0.0.0/32", "unspecified"),
    ("255.255.255.255/32", "broadcast"),
    ("0.0.0.0/8", "reserved"),
    ("10.0.0.0/8", "private"),
    ("100.64.0.0/10", "shared"),
    ("127.0.0.0/8", "loopback"),
    ("169.254.0.0/16", "link-local"),
    ("172.16.0.0/12", "private"),
    ("192.0.0.0/24", "reserved"),
    ("192.0.2.0/24", "documentation"),
    ("192.88.99.0/24", "reserved"),
    ("192.168.0.0/16", "private"),
    ("198.18.0.0/15", "benchmark"),
    ("198.51.100.0/24", "documentation"),
    ("203.0.113.0/24", "documentation"),
    ("224.0.0.0/4", "multicast"),
    ("240.0.0.0/4", "reserved"),
]

_V6_TABLE = [
    ("::/128", "unspecified"),
    ("::1/128", "loopback"),
    ("64:ff9b:1::/48", "reserved"),
    ("100::/64", "reserved"),
    ("2001::/23", "reserved"),
    ("2001:db8::/32", "documentation"),
    ("2002::/16", "reserved"),
    ("3fff::/20", "documentation"),
    ("fc00::/7", "private"),
    ("fe80::/10", "link-local"),
    ("fec0::/10", "reserved"),
    ("ff00::/8", "multicast"),
]

_V4_NETS = [(ipaddress.IPv4Network(n), s) for n, s in _V4_TABLE]
_V6_NETS = [(ipaddress.IPv6Network(n), s) for n, s in _V6_TABLE]
_V6_GLOBAL_UNICAST = ipaddress.IPv6Network("2000::/3")


@lru_cache(maxsize=65536)
def classify(address: IPAddress) -> str:
    """Return the scope name of ``address`` (one of :data:`SCOPES`)."""
    if isinstance(address, ipaddress.IPv6Address):
        mapped = address.ipv4_mapped
        if mapped is not None:
            return classify(mapped)
        for net, scope in _V6_NETS:
            if address in net:
                return scope
        return PUBLIC if address in _V6_GLOBAL_UNICAST else "reserved"
    for net4, scope in _V4_NETS:
        if address in net4:
            return scope
    return PUBLIC


def is_public(address: IPAddress) -> bool:
    return classify(address) == PUBLIC

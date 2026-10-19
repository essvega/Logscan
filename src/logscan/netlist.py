"""CIDR lists used for ``--ignore`` and ``--watch``."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Iterable, Union

from .extract import IPAddress

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class NetList:
    """A set of networks with fast membership tests.

    Entries may be single addresses or CIDR blocks. An entry starting with
    ``@`` names a file holding one entry per line; ``#`` starts a comment.
    """

    def __init__(self, entries: Iterable[str] = ()) -> None:
        self.networks: list[Network] = []
        for entry in entries:
            self.add(entry)

    def add(self, entry: str) -> None:
        entry = entry.strip()
        if not entry:
            return
        if entry.startswith("@"):
            self.load(Path(entry[1:]))
            return
        try:
            self.networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            raise ValueError(f"invalid address or CIDR: {entry!r}") from exc

    def load(self, path: Path) -> None:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                self.add(line)

    def match(self, address: IPAddress) -> Network | None:
        """Return the first network containing ``address``, or ``None``."""
        for net in self.networks:
            if net.version == address.version and address in net:
                return net
        return None

    def __contains__(self, address: object) -> bool:
        return isinstance(address, (ipaddress.IPv4Address, ipaddress.IPv6Address)) and (self.match(address) is not None)

    def __bool__(self) -> bool:
        return bool(self.networks)

    def __len__(self) -> int:
        return len(self.networks)

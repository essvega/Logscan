"""Walk inputs, extract addresses and aggregate them into a :class:`ScanResult`."""

from __future__ import annotations

import bz2
import fnmatch
import gzip
import io
import lzma
import os
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO, Any, Callable, Iterable, Iterator, Optional, Sequence

from .classify import PUBLIC, SCOPES, classify
from .extract import IPAddress, extract
from .netlist import NetList

STDIN = "-"
SAMPLE_LENGTH = 240
_BINARY_PROBE = 8192
_OPENERS: dict[str, Callable[..., Any]] = {
    ".gz": gzip.open,
    ".bz2": bz2.open,
    ".xz": lzma.open,
    ".lzma": lzma.open,
}
_SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", "node_modules", ".venv", "venv", ".tox"}


@dataclass
class Location:
    source: str
    line: int


@dataclass
class Hit:
    """Everything known about one address across all scanned inputs."""

    address: IPAddress
    scope: str
    count: int = 0
    ports: Counter = field(default_factory=Counter)
    sources: Counter = field(default_factory=Counter)
    first_seen: Optional[Location] = None
    last_seen: Optional[Location] = None
    sample: str = ""
    watch: Optional[str] = None
    info: dict = field(default_factory=dict)

    @property
    def ip(self) -> str:
        return str(self.address)

    @property
    def version(self) -> int:
        return self.address.version

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "version": self.version,
            "scope": self.scope,
            "count": self.count,
            "ports": dict(sorted(self.ports.items())),
            "sources": dict(self.sources.most_common()),
            "first_seen": vars(self.first_seen) if self.first_seen else None,
            "last_seen": vars(self.last_seen) if self.last_seen else None,
            "sample": self.sample,
            "watch": self.watch,
            "info": self.info,
        }


@dataclass
class SourceStats:
    name: str
    lines: int = 0
    bytes: int = 0
    addresses: int = 0
    error: Optional[str] = None


@dataclass
class ScanOptions:
    scopes: frozenset = frozenset({PUBLIC})
    ipv4: bool = True
    ipv6: bool = True
    ignore: NetList = field(default_factory=NetList)
    watch: NetList = field(default_factory=NetList)
    include: Sequence[str] = ()
    exclude: Sequence[str] = ()
    recursive: bool = True
    include_binary: bool = False
    follow_symlinks: bool = False

    def __post_init__(self) -> None:
        unknown = set(self.scopes) - set(SCOPES)
        if unknown:
            raise ValueError(f"unknown scope(s): {', '.join(sorted(unknown))}")


@dataclass
class ScanResult:
    hits: dict[str, Hit] = field(default_factory=dict)
    sources: list[SourceStats] = field(default_factory=list)
    total_matches: int = 0
    filtered: Counter = field(default_factory=Counter)
    elapsed: float = 0.0

    @property
    def watch_hits(self) -> list[Hit]:
        return [h for h in self.hits.values() if h.watch]

    def summary(self) -> dict:
        scopes = Counter(h.scope for h in self.hits.values())
        countries = Counter(h.info.get("country_code") or h.info.get("country") for h in self.hits.values())
        countries.pop(None, None)
        return {
            "sources": len(self.sources),
            "sources_failed": sum(1 for s in self.sources if s.error),
            "lines": sum(s.lines for s in self.sources),
            "bytes": sum(s.bytes for s in self.sources),
            "matches": self.total_matches,
            "unique": len(self.hits),
            "ipv4": sum(1 for h in self.hits.values() if h.version == 4),
            "ipv6": sum(1 for h in self.hits.values() if h.version == 6),
            "scopes": dict(scopes.most_common()),
            "countries": dict(countries.most_common()),
            "filtered": dict(self.filtered.most_common()),
            "watch_hits": len(self.watch_hits),
            "elapsed_seconds": round(self.elapsed, 3),
        }


def _matches_any(name: str, patterns: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(name, p) for p in patterns)


def _is_binary(path: Path) -> bool:
    if path.suffix.lower() in _OPENERS:
        return False
    try:
        with path.open("rb") as fh:
            return b"\0" in fh.read(_BINARY_PROBE)
    except OSError:
        return False


def iter_files(paths: Sequence[str], options: ScanOptions) -> Iterator[str]:
    """Expand ``paths`` (files, directories or ``-``) into the files to scan."""
    seen: set[str] = set()
    for raw in paths:
        if raw == STDIN:
            yield STDIN
            continue
        path = Path(raw)
        candidates = _walk(path, options) if path.is_dir() else iter([path])
        for candidate in candidates:
            key = os.path.realpath(candidate)
            if key in seen:
                continue
            seen.add(key)
            yield str(candidate)


def _walk(root: Path, options: ScanOptions) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root, followlinks=options.follow_symlinks):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS and not d.startswith("."))
        if not options.recursive:
            dirnames[:] = []
        for name in sorted(filenames):
            if options.include and not _matches_any(name, options.include):
                continue
            if options.exclude and _matches_any(name, options.exclude):
                continue
            path = Path(dirpath, name)
            if not options.include_binary and _is_binary(path):
                continue
            yield path


def open_text(source: str) -> IO[str]:
    """Open a file (transparently decompressing it) or stdin as text."""
    if source == STDIN:
        return io.TextIOWrapper(sys.stdin.buffer, encoding="utf-8", errors="replace")
    opener = _OPENERS.get(Path(source).suffix.lower(), open)
    return io.TextIOWrapper(opener(source, "rb"), encoding="utf-8-sig", errors="replace")


class Scanner:
    """Incrementally scan sources; call :meth:`result` when done."""

    def __init__(self, options: Optional[ScanOptions] = None) -> None:
        self.options = options or ScanOptions()
        self._result = ScanResult()
        self._rejected: dict[str, str] = {}
        self._started = time.perf_counter()

    def scan_lines(self, lines: Iterable[str], source: str = "<text>") -> SourceStats:
        opts = self.options
        stats = SourceStats(source)
        hits = self._result.hits
        filtered = self._result.filtered
        rejected = self._rejected
        for number, line in enumerate(lines, 1):
            stats.lines = number
            stats.bytes += len(line)
            for m in extract(line, ipv4=opts.ipv4, ipv6=opts.ipv6):
                stats.addresses += 1
                key = m.ip
                hit = hits.get(key)
                if hit is None:
                    reason = rejected.get(key)
                    if reason is None:
                        scope = classify(m.address)
                        if scope not in opts.scopes:
                            reason = scope
                        elif opts.ignore and m.address in opts.ignore:
                            reason = "ignored"
                    if reason is not None:
                        rejected[key] = reason
                        filtered[reason] += 1
                        continue
                    hit = Hit(m.address, scope)
                    net = opts.watch.match(m.address) if opts.watch else None
                    hit.watch = str(net) if net else None
                    hit.first_seen = Location(source, number)
                    hit.sample = line.strip()[:SAMPLE_LENGTH]
                    hits[key] = hit
                hit.count += 1
                hit.sources[source] += 1
                hit.last_seen = Location(source, number)
                if m.port is not None:
                    hit.ports[m.port] += 1
        self._result.total_matches += stats.addresses
        self._result.sources.append(stats)
        return stats

    def scan_source(self, source: str) -> SourceStats:
        try:
            with open_text(source) as fh:
                return self.scan_lines(fh, source)
        except (OSError, EOFError, lzma.LZMAError) as exc:
            stats = SourceStats(source, error=f"{type(exc).__name__}: {exc}")
            self._result.sources.append(stats)
            return stats

    def result(self) -> ScanResult:
        self._result.elapsed = time.perf_counter() - self._started
        return self._result


def scan(
    paths: Sequence[str] = (".",),
    options: Optional[ScanOptions] = None,
    on_source: Optional[Callable[[SourceStats], None]] = None,
) -> ScanResult:
    """Scan files, directories and/or ``-`` (stdin) and return the aggregated result."""
    scanner = Scanner(options)
    for source in iter_files(paths, scanner.options):
        stats = scanner.scan_source(source)
        if on_source:
            on_source(stats)
    return scanner.result()


def scan_text(text: str, options: Optional[ScanOptions] = None) -> ScanResult:
    """Convenience helper to scan an in-memory string."""
    scanner = Scanner(options)
    scanner.scan_lines(text.splitlines(), "<text>")
    return scanner.result()

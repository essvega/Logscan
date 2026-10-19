"""Command-line interface: ``logscan [OPTIONS] [PATH ...]``."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional, Sequence

from . import __version__
from .classify import PUBLIC, SCOPES
from .enrich import DEFAULT_TTL, PROVIDERS, AuthError, Cache, EnrichError, default_cache_path, enrich, make_provider
from .netlist import NetList
from .report import FORMATS, render, use_color
from .scanner import Hit, ScanOptions, ScanResult, SourceStats, scan

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_WATCH = 3

SORT_KEYS = {
    "hits": lambda h: (-h.count, h.version, h.address),
    "ip": lambda h: (h.version, h.address),
    "first-seen": lambda h: (h.first_seen.source, h.first_seen.line) if h.first_seen else ("", 0),
    "files": lambda h: (-len(h.sources), -h.count),
}

EPILOG = """\
examples:
  logscan device.log                       public addresses in one file
  logscan ./logs --glob '*.log' --glob '*.gz'
  journalctl -o cat | logscan -            read from stdin
  logscan logs/ --scope all -f json -o report.json
  logscan logs/ --enrich ipinfo -f html -o report.html
  logscan logs/ --watch @blocklist.txt --fail-on-watch

exit status: 0 success, 1 error, 2 usage error, 3 watch-list hit with --fail-on-watch
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="logscan",
        description="Find, classify and enrich the IP addresses hidden in log files.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "paths",
        nargs="*",
        default=["."],
        metavar="PATH",
        help="files or directories to scan, '-' for stdin (default: current directory)",
    )
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")

    g = p.add_argument_group("input")
    g.add_argument(
        "-g",
        "--glob",
        action="append",
        default=[],
        metavar="PATTERN",
        help="when walking directories, only scan files whose name matches (repeatable), e.g. '*.log'",
    )
    g.add_argument(
        "-x",
        "--exclude",
        action="append",
        default=[],
        metavar="PATTERN",
        help="skip files whose name matches (repeatable)",
    )
    g.add_argument("--no-recursive", dest="recursive", action="store_false", help="do not descend into subdirectories")
    g.add_argument("--follow-symlinks", action="store_true", help="follow symbolic links when walking directories")
    g.add_argument("--binary", action="store_true", help="also scan files that look binary")

    g = p.add_argument_group("filtering")
    g.add_argument(
        "-s",
        "--scope",
        action="append",
        choices=(*SCOPES, "all"),
        metavar="SCOPE",
        help=f"address scopes to report (repeatable; default: public). One of: {', '.join(SCOPES)}, all",
    )
    v = g.add_mutually_exclusive_group()
    v.add_argument("-4", "--ipv4-only", action="store_true", help="only look for IPv4 addresses")
    v.add_argument("-6", "--ipv6-only", action="store_true", help="only look for IPv6 addresses")
    g.add_argument(
        "-i",
        "--ignore",
        action="append",
        default=[],
        metavar="CIDR|@FILE",
        help="never report these addresses/networks (repeatable)",
    )
    g.add_argument(
        "-w",
        "--watch",
        action="append",
        default=[],
        metavar="CIDR|@FILE",
        help="flag addresses inside these networks (repeatable)",
    )
    g.add_argument("--min-hits", type=int, default=1, metavar="N", help="only report addresses seen at least N times")
    g.add_argument("--top", type=int, metavar="N", help="only report the first N addresses after sorting")
    g.add_argument("--sort", choices=tuple(SORT_KEYS), default="hits", help="sort order (default: hits)")

    g = p.add_argument_group("enrichment")
    g.add_argument(
        "-e",
        "--enrich",
        choices=tuple(PROVIDERS),
        metavar="PROVIDER",
        help=f"look up public addresses with a provider: {', '.join(PROVIDERS)}",
    )
    g.add_argument("--token", help="API token for the provider (default: $IPINFO_TOKEN)")
    g.add_argument("--workers", type=int, default=8, help="parallel lookups (default: 8)")
    g.add_argument(
        "--cache", type=Path, default=None, metavar="FILE", help=f"lookup cache file (default: {default_cache_path()})"
    )
    g.add_argument(
        "--cache-ttl",
        type=float,
        default=DEFAULT_TTL / 3600,
        metavar="HOURS",
        help="how long cached lookups stay valid (default: 168)",
    )
    g.add_argument("--no-cache", action="store_true", help="do not read or write the lookup cache")

    g = p.add_argument_group("output")
    g.add_argument(
        "-f",
        "--format",
        choices=FORMATS,
        default=None,
        help="output format (default: table, or inferred from --output's extension)",
    )
    g.add_argument("-o", "--output", type=Path, metavar="FILE", help="write the report to FILE instead of stdout")
    g.add_argument("--color", choices=("auto", "always", "never"), default="auto", help="colorize the table output")
    g.add_argument("-q", "--quiet", action="store_true", help="no progress or warnings on stderr")
    g.add_argument("--fail-on-watch", action="store_true", help="exit with status 3 if any watch-list address is found")
    return p


_EXTENSIONS = {
    ".json": "json",
    ".ndjson": "ndjson",
    ".jsonl": "ndjson",
    ".csv": "csv",
    ".md": "markdown",
    ".markdown": "markdown",
    ".html": "html",
    ".htm": "html",
    ".txt": "table",
}


def _select(result: ScanResult, args: argparse.Namespace) -> list[Hit]:
    hits = [h for h in result.hits.values() if h.count >= args.min_hits]
    hits.sort(key=SORT_KEYS[args.sort])
    return hits[: args.top] if args.top is not None and args.top >= 0 else hits


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    err = sys.stderr

    def warn(msg: str) -> None:
        if not args.quiet:
            print(f"logscan: {msg}", file=err)

    if not args.scope:
        scopes = frozenset({PUBLIC})
    elif "all" in args.scope:
        scopes = frozenset(SCOPES)
    else:
        scopes = frozenset(args.scope)
    try:
        options = ScanOptions(
            scopes=scopes,
            ipv4=not args.ipv6_only,
            ipv6=not args.ipv4_only,
            ignore=NetList(args.ignore),
            watch=NetList(args.watch),
            include=args.glob,
            exclude=args.exclude,
            recursive=args.recursive,
            include_binary=args.binary,
            follow_symlinks=args.follow_symlinks,
        )
    except (ValueError, OSError) as exc:
        parser.error(str(exc))

    for path in args.paths:
        if path != "-" and not os.path.exists(path):
            parser.error(f"no such file or directory: {path}")

    progress = not args.quiet and err.isatty()

    def on_source(stats: SourceStats) -> None:
        if stats.error:
            warn(f"{stats.name}: {stats.error}")
        elif progress:
            print(f"\r\033[Kscanned {stats.name} ({stats.lines:,} lines)", end="", file=err, flush=True)

    try:
        result = scan(args.paths, options, on_source=on_source)
    except KeyboardInterrupt:
        print(file=err)
        return 130
    if progress:
        print("\r\033[K", end="", file=err, flush=True)
    if result.sources and all(s.error for s in result.sources):
        warn("no input could be read")
        return EXIT_ERROR

    hits = _select(result, args)

    if args.enrich:
        public = [h for h in hits if h.scope == PUBLIC]
        cache = None if args.no_cache else Cache(args.cache or default_cache_path(), ttl=args.cache_ttl * 3600)
        try:
            provider = make_provider(args.enrich, token=args.token, workers=args.workers)
            if args.enrich == "ip-api":
                warn("ip-api.com's free tier uses unencrypted HTTP; use --enrich ipinfo for HTTPS")
            enrich(public, provider, cache)
        except AuthError as exc:
            warn(str(exc))
            return EXIT_ERROR
        except EnrichError as exc:
            warn(f"enrichment failed: {exc}")

    fmt = args.format or (_EXTENSIONS.get(args.output.suffix.lower(), "table") if args.output else "table")
    color = {"always": True, "never": False}.get(args.color, use_color() and not args.output)
    text = render(result, hits, fmt, color=color)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
        warn(f"wrote {fmt} report with {len(hits)} address(es) to {args.output}")
    else:
        try:
            sys.stdout.write(text)
            sys.stdout.flush()
        except BrokenPipeError:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())

    if args.fail_on_watch and any(h.watch for h in hits):
        return EXIT_WATCH
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

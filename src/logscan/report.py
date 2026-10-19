"""Render a :class:`~logscan.scanner.ScanResult` as table, JSON, CSV, Markdown or HTML."""

from __future__ import annotations

import csv
import io
import json
import os
import sys
from datetime import datetime, timezone
from typing import Callable, Sequence

from . import __version__
from .scanner import Hit, ScanResult

FORMATS = ("table", "json", "ndjson", "csv", "markdown", "html")

_SCOPE_COLORS = {"public": "36", "private": "32", "loopback": "90", "multicast": "35", "reserved": "33"}


def _ports(hit: Hit, limit: int = 5) -> str:
    ports = [str(p) for p, _ in hit.ports.most_common(limit)]
    if len(hit.ports) > limit:
        ports.append("…")
    return ",".join(ports)


def _location(hit: Hit) -> str:
    info = hit.info
    parts = [info.get("city"), info.get("region"), info.get("country_code") or info.get("country")]
    return ", ".join(p for p in parts if p)


def _org(hit: Hit) -> str:
    info = hit.info
    if "error" in info:
        return f"(lookup failed: {info['error']})"
    return " ".join(p for p in (info.get("asn"), info.get("org")) if p)


def _first(hit: Hit) -> str:
    loc = hit.first_seen
    return f"{os.path.basename(loc.source)}:{loc.line}" if loc else ""


def _rows(hits: Sequence[Hit], enriched: bool) -> tuple[list[str], list[list[str]]]:
    header = ["IP", "SCOPE", "HITS", "FILES", "PORTS", "FIRST SEEN"]
    if enriched:
        header += ["LOCATION", "ORGANISATION"]
    header.append("WATCH")
    rows = []
    for h in hits:
        row = [h.ip, h.scope, str(h.count), str(len(h.sources)), _ports(h), _first(h)]
        if enriched:
            row += [_location(h), _org(h)]
        row.append(h.watch or "")
        rows.append(row)
    return header, rows


def _is_enriched(hits: Sequence[Hit]) -> bool:
    return any(h.info for h in hits)


def use_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def render_table(result: ScanResult, hits: Sequence[Hit], color: bool = False) -> str:
    out = io.StringIO()
    s = result.summary()

    def paint(text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if color else text

    if hits:
        header, rows = _rows(hits, _is_enriched(hits))
        widths = [max(len(header[i]), *(len(r[i]) for r in rows)) for i in range(len(header))]
        widths = [min(w, 60) for w in widths]

        def fmt(cells: list[str], styled: bool) -> str:
            parts = []
            for i, cell in enumerate(cells):
                text = cell if len(cell) <= widths[i] else cell[: widths[i] - 1] + "…"
                text = text.rjust(widths[i]) if header[i] in ("HITS", "FILES") else text.ljust(widths[i])
                if styled and header[i] == "SCOPE":
                    text = paint(text, _SCOPE_COLORS.get(cell, "0"))
                elif styled and header[i] == "WATCH" and cell:
                    text = paint(text, "1;31")
                parts.append(text)
            return "  ".join(parts).rstrip()

        out.write(paint(fmt(header, False), "1") + "\n")
        out.write("  ".join("─" * w for w in widths) + "\n")
        for row in rows:
            out.write(fmt(row, True) + "\n")
        out.write("\n")
    else:
        out.write("No matching addresses found.\n\n")

    line = (
        f"{s['unique']} unique address(es) [{s['ipv4']} IPv4 / {s['ipv6']} IPv6] from "
        f"{s['matches']} match(es) in {s['sources']} source(s), {s['lines']} line(s), {s['elapsed_seconds']}s"
    )
    out.write(paint(line, "2") + "\n")
    if s["filtered"]:
        filtered = ", ".join(f"{k}={v}" for k, v in s["filtered"].items())
        out.write(paint(f"Filtered occurrences: {filtered}  (use --scope all to include)", "2") + "\n")
    if s["watch_hits"]:
        out.write(paint(f"⚠ {s['watch_hits']} address(es) matched the watch list", "1;31") + "\n")
    for src in result.sources:
        if src.error:
            out.write(paint(f"! {src.name}: {src.error}", "33") + "\n")
    return out.getvalue()


def _document(result: ScanResult, hits: Sequence[Hit]) -> dict:
    return {
        "tool": "logscan",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": result.summary(),
        "sources": [vars(s) for s in result.sources],
        "addresses": [h.to_dict() for h in hits],
    }


def render_json(result: ScanResult, hits: Sequence[Hit]) -> str:
    return json.dumps(_document(result, hits), indent=2, ensure_ascii=False) + "\n"


def render_ndjson(result: ScanResult, hits: Sequence[Hit]) -> str:
    return "".join(json.dumps(h.to_dict(), ensure_ascii=False) + "\n" for h in hits)


def _csv_safe(value: str) -> str:
    # Neutralise spreadsheet formula injection from untrusted log content.
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def render_csv(result: ScanResult, hits: Sequence[Hit]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(
        [
            "ip",
            "version",
            "scope",
            "count",
            "sources",
            "ports",
            "first_seen",
            "last_seen",
            "country_code",
            "region",
            "city",
            "asn",
            "org",
            "hostname",
            "watch",
            "sample",
        ]
    )
    for h in hits:
        i = h.info
        writer.writerow(
            [
                h.ip,
                h.version,
                h.scope,
                h.count,
                ";".join(h.sources),
                ";".join(map(str, sorted(h.ports))),
                f"{h.first_seen.source}:{h.first_seen.line}" if h.first_seen else "",
                f"{h.last_seen.source}:{h.last_seen.line}" if h.last_seen else "",
                i.get("country_code", ""),
                i.get("region", ""),
                i.get("city", ""),
                i.get("asn", ""),
                _csv_safe(str(i.get("org", ""))),
                i.get("hostname", ""),
                h.watch or "",
                _csv_safe(h.sample),
            ]
        )
    return out.getvalue()


def render_markdown(result: ScanResult, hits: Sequence[Hit]) -> str:
    def cell(text: str) -> str:
        return text.replace("|", "\\|").replace("\n", " ") or " "

    s = result.summary()
    lines = [
        "# Logscan report",
        "",
        f"- **Unique addresses:** {s['unique']} ({s['ipv4']} IPv4, {s['ipv6']} IPv6)",
        f"- **Matches:** {s['matches']} across {s['sources']} source(s) / {s['lines']} line(s)",
        f"- **Watch-list hits:** {s['watch_hits']}",
        "",
    ]
    if hits:
        header, rows = _rows(hits, _is_enriched(hits))
        lines.append("| " + " | ".join(header) + " |")
        lines.append("|" + "|".join("---:" if h in ("HITS", "FILES") else "---" for h in header) + "|")
        lines.extend("| " + " | ".join(cell(c) for c in row) + " |" for row in rows)
    else:
        lines.append("_No matching addresses found._")
    return "\n".join(lines) + "\n"


def render_html(result: ScanResult, hits: Sequence[Hit]) -> str:
    from .html_report import build

    return build(_document(result, hits))


RENDERERS: dict[str, Callable[[ScanResult, Sequence[Hit]], str]] = {
    "json": render_json,
    "ndjson": render_ndjson,
    "csv": render_csv,
    "markdown": render_markdown,
    "html": render_html,
}


def render(result: ScanResult, hits: Sequence[Hit], fmt: str = "table", color: bool = False) -> str:
    if fmt == "table":
        return render_table(result, hits, color=color)
    try:
        return RENDERERS[fmt](result, hits)
    except KeyError:
        raise ValueError(f"unknown format {fmt!r}; choose from {', '.join(FORMATS)}") from None


__all__ = ["FORMATS", "render", "use_color"]

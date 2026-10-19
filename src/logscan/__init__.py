"""Logscan — find, classify and enrich the IP addresses hidden in log files."""

__version__ = "2.0.0"

from .classify import SCOPES, classify, is_public
from .extract import Match, extract
from .netlist import NetList
from .scanner import Hit, Scanner, ScanOptions, ScanResult, scan, scan_text

__all__ = [
    "SCOPES",
    "Hit",
    "Match",
    "NetList",
    "ScanOptions",
    "ScanResult",
    "Scanner",
    "__version__",
    "classify",
    "extract",
    "is_public",
    "scan",
    "scan_text",
]

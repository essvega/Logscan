# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [2.0.0] - 2026-10-19

Complete rewrite of the original `read.py` script as an installable, tested package and command-line tool.

### Added
- `logscan` command (`python -m logscan`) that accepts files, directories, glob filters and stdin.
- Transparent decompression of `.gz`, `.bz2`, `.xz` and `.lzma` logs; binary files and VCS folders are skipped.
- Real IPv6 extraction (compressed, bracketed, zone IDs, IPv4-mapped) and port capture from `ip:port`.
- Eleven address scopes based on the IANA special-purpose registries, selectable with `--scope`.
- Per-address aggregation: hit count, files, ports, first/last occurrence and a sample line.
- `--watch` / `--ignore` network lists (inline or `@file`) and `--fail-on-watch` exit status for CI.
- Optional enrichment through ipinfo.io (HTTPS) or ip-api.com, with parallel lookups, retries and a disk cache.
- Output as terminal table, JSON, NDJSON, CSV, Markdown and a self-contained interactive HTML report.
- Python API (`logscan.scan`, `scan_text`, `Scanner`, `extract`, `classify`, …) with type hints.
- Test suite, GitHub Actions CI (Linux/macOS/Windows × Python 3.9–3.13), Dockerfile, and a release workflow
  that publishes standalone executables for Windows, macOS and Linux.

### Changed
- Enrichment is optional; the API token comes from `IPINFO_TOKEN` or `--token` instead of an interactive prompt.
- The sample log moved to `examples/embedded-device.log`.

### Fixed
- The IPv4 pattern matched invalid addresses (e.g. `299.1.1.1`) and fragments of longer numbers.
- IPv6 support was advertised but addresses were never extracted.
- Only `.txt` files located next to the script could be scanned.
- Crash when a lookup returned no country or region.
- Every address of every file was re-processed and re-queried for each additional file (quadratic work).

### Removed
- `read.py` and `requirements.txt`; the tool now has no runtime dependencies (the old list pinned outdated
  `requests`/`urllib3` releases with known vulnerabilities and several unused packages).

## [1.0.0] - 2020

- Initial script: scan `.txt` files for IPv4 addresses, drop private ranges, geolocate with ipinfo.

[2.0.0]: https://github.com/essvega/Logscan/compare/e4a4199...v2.0.0

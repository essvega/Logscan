# Security policy

Please report vulnerabilities privately through
[GitHub security advisories](https://github.com/essvega/Logscan/security/advisories/new) rather than public issues.

Logscan treats every log line as untrusted input:

- HTML reports embed data as escaped JSON and build the page with DOM text nodes, so log content cannot run script.
- CSV cells that a spreadsheet would interpret as a formula are prefixed with `'`.
- API tokens are sent only in the `Authorization` header and are never written to reports or the cache.

Note that the free ip-api.com tier only supports plain HTTP; use `--enrich ipinfo` when the addresses you look up
are sensitive.

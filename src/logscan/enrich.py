"""Optional enrichment of public addresses with geolocation / ownership data.

Only the Python standard library is used. Results are cached on disk so the
same address is not looked up twice within the cache TTL.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable, Iterable, Optional

from . import __version__

USER_AGENT = f"logscan/{__version__} (+https://github.com/essvega/Logscan)"
DEFAULT_TTL = 7 * 24 * 3600

# Normalised keys every provider fills in when it can.
FIELDS = ("country", "country_code", "region", "city", "org", "asn", "hostname", "latitude", "longitude")


class EnrichError(RuntimeError):
    pass


class AuthError(EnrichError):
    pass


def default_cache_path() -> Path:
    base = os.environ.get("XDG_CACHE_HOME") or (os.environ.get("LOCALAPPDATA") if sys.platform == "win32" else None)
    root = Path(base) if base else Path.home() / ".cache"
    return root / "logscan" / "enrich.json"


class Cache:
    """A small thread-safe JSON cache keyed by ``provider:ip``."""

    def __init__(self, path: Optional[Path], ttl: float = DEFAULT_TTL) -> None:
        self.path = path
        self.ttl = ttl
        self._lock = threading.Lock()
        self._data: dict[str, dict] = {}
        self._dirty = False
        if path and path.is_file():
            try:
                self._data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self._data = {}

    def get(self, key: str) -> Optional[dict]:
        with self._lock:
            entry = self._data.get(key)
        if entry and time.time() - entry.get("t", 0) < self.ttl:
            return entry["v"]
        return None

    def set(self, key: str, value: dict) -> None:
        with self._lock:
            self._data[key] = {"t": time.time(), "v": value}
            self._dirty = True

    def save(self) -> None:
        if not self.path or not self._dirty:
            return
        now = time.time()
        with self._lock:
            fresh = {k: v for k, v in self._data.items() if now - v.get("t", 0) < self.ttl}
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(fresh, separators=(",", ":")), encoding="utf-8")
            os.replace(tmp, self.path)
            self._dirty = False
        except OSError:
            pass  # a cache that cannot be written is not fatal


def _http(
    url: str,
    *,
    data: Optional[bytes] = None,
    headers: Optional[dict] = None,
    timeout: float = 10.0,
    retries: int = 3,
) -> object:
    hdrs = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    hdrs.update(headers or {})
    if data is not None:
        hdrs.setdefault("Content-Type", "application/json")
    delay = 1.0
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=data, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise AuthError(f"authentication failed ({exc.code}); check your token") from exc
            if exc.code not in (429, 500, 502, 503, 504) or attempt == retries:
                raise EnrichError(f"HTTP {exc.code} from {urllib.parse.urlsplit(url).netloc}") from exc
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
            time.sleep(float(retry_after) if retry_after and retry_after.isdigit() else delay)
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            if attempt == retries:
                raise EnrichError(f"network error: {exc}") from exc
            time.sleep(delay)
        except ValueError as exc:
            raise EnrichError("invalid JSON response") from exc
        delay *= 2
    raise EnrichError("unreachable")  # pragma: no cover


class Provider:
    name = "base"

    def lookup_many(self, ips: list[str]) -> dict[str, dict]:
        raise NotImplementedError


class IPInfoProvider(Provider):
    """https://ipinfo.io — HTTPS; works without a token at a low rate limit."""

    name = "ipinfo"

    def __init__(self, token: Optional[str] = None, workers: int = 8, base_url: str = "https://ipinfo.io") -> None:
        self.token = token
        self.workers = max(1, workers)
        self.base_url = base_url.rstrip("/")

    def _one(self, ip: str) -> dict:
        headers = {"Authorization": f"Bearer {self.token}"} if self.token else {}
        raw = _http(f"{self.base_url}/{urllib.parse.quote(ip)}/json", headers=headers)
        return self.normalise(raw if isinstance(raw, dict) else {})

    @staticmethod
    def normalise(raw: dict) -> dict:
        out: dict = {"country_code": raw.get("country"), "region": raw.get("region"), "city": raw.get("city")}
        out["hostname"] = raw.get("hostname")
        org = raw.get("org") or ""
        if org.startswith("AS") and " " in org:
            asn, name = org.split(" ", 1)
            out["asn"], out["org"] = asn, name
        else:
            out["asn"], out["org"] = None, org or None
        loc = raw.get("loc")
        if isinstance(loc, str) and "," in loc:
            lat, lon = loc.split(",", 1)
            with contextlib.suppress(ValueError):
                out["latitude"], out["longitude"] = float(lat), float(lon)
        if raw.get("bogon"):
            out["bogon"] = True
        return {k: v for k, v in out.items() if v not in (None, "")}

    def _safe(self, ip: str) -> dict:
        try:
            return self._one(ip)
        except AuthError:
            raise
        except EnrichError as exc:
            return {"error": str(exc)}

    def lookup_many(self, ips: list[str]) -> dict[str, dict]:
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            return dict(zip(ips, pool.map(self._safe, ips)))


class IPApiProvider(Provider):
    """http://ip-api.com batch API — free and keyless, but plain HTTP only."""

    name = "ip-api"
    BATCH = 100
    _FIELDS = "status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,reverse,query"

    def __init__(self, base_url: str = "http://ip-api.com") -> None:
        self.base_url = base_url.rstrip("/")

    @staticmethod
    def normalise(raw: dict) -> dict:
        if raw.get("status") != "success":
            return {"error": raw.get("message", "lookup failed")}
        asn = (raw.get("as") or "").split(" ", 1)[0] or None
        out = {
            "country": raw.get("country"),
            "country_code": raw.get("countryCode"),
            "region": raw.get("regionName"),
            "city": raw.get("city"),
            "org": raw.get("org") or raw.get("isp"),
            "asn": asn,
            "hostname": raw.get("reverse"),
            "latitude": raw.get("lat"),
            "longitude": raw.get("lon"),
        }
        return {k: v for k, v in out.items() if v not in (None, "")}

    def lookup_many(self, ips: list[str]) -> dict[str, dict]:
        out: dict[str, dict] = {}
        for i in range(0, len(ips), self.BATCH):
            chunk = ips[i : i + self.BATCH]
            body = json.dumps([{"query": ip} for ip in chunk]).encode()
            raw = _http(f"{self.base_url}/batch?fields={self._FIELDS}", data=body)
            for item in raw if isinstance(raw, list) else []:
                if isinstance(item, dict) and item.get("query") in chunk:
                    out[item["query"]] = self.normalise(item)
        return out


PROVIDERS: dict[str, Callable[..., Provider]] = {
    "ipinfo": IPInfoProvider,
    "ip-api": IPApiProvider,
}


def make_provider(name: str, *, token: Optional[str] = None, workers: int = 8) -> Provider:
    if name == "ipinfo":
        return IPInfoProvider(token=token or os.environ.get("IPINFO_TOKEN"), workers=workers)
    if name == "ip-api":
        return IPApiProvider()
    raise ValueError(f"unknown provider {name!r}; choose from {', '.join(PROVIDERS)}")


def enrich(
    hits: Iterable,
    provider: Provider,
    cache: Optional[Cache] = None,
) -> int:
    """Fill ``hit.info`` for each hit; returns the number of network lookups made."""
    pending = []
    for hit in hits:
        cached = cache.get(f"{provider.name}:{hit.ip}") if cache else None
        if cached is not None:
            hit.info = dict(cached)
        else:
            pending.append(hit)
    if not pending:
        return 0
    results = provider.lookup_many([h.ip for h in pending])
    for hit in pending:
        info = results.get(hit.ip)
        if info is None:
            continue
        hit.info = dict(info)
        if cache and "error" not in info:
            cache.set(f"{provider.name}:{hit.ip}", info)
    if cache:
        cache.save()
    return len(pending)

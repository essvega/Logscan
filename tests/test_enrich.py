import io
import json
import urllib.error

import pytest

from logscan import enrich as E
from logscan import scan_text


class FakeProvider(E.Provider):
    name = "fake"

    def __init__(self):
        self.calls = []

    def lookup_many(self, ips):
        self.calls.append(list(ips))
        return {ip: {"country_code": "XX", "org": f"org-{ip}"} for ip in ips}


def test_enrich_uses_cache(tmp_path):
    hits = list(scan_text("1.1.1.1 8.8.8.8").hits.values())
    cache = E.Cache(tmp_path / "c.json")
    provider = FakeProvider()
    assert E.enrich(hits, provider, cache) == 2
    assert hits[0].info["country_code"] == "XX"
    again = list(scan_text("1.1.1.1 8.8.8.8").hits.values())
    assert E.enrich(again, provider, E.Cache(tmp_path / "c.json")) == 0
    assert again[1].info["org"] == "org-8.8.8.8"
    assert len(provider.calls) == 1


def test_cache_ttl(tmp_path):
    cache = E.Cache(tmp_path / "c.json", ttl=0)
    cache.set("k", {"a": 1})
    assert cache.get("k") is None


def test_ipinfo_normalise():
    out = E.IPInfoProvider.normalise(
        {
            "ip": "8.8.8.8",
            "hostname": "dns.google",
            "city": "Mountain View",
            "region": "California",
            "country": "US",
            "loc": "37.4056,-122.0775",
            "org": "AS15169 Google LLC",
        }
    )
    assert out == {
        "country_code": "US",
        "region": "California",
        "city": "Mountain View",
        "hostname": "dns.google",
        "asn": "AS15169",
        "org": "Google LLC",
        "latitude": 37.4056,
        "longitude": -122.0775,
    }


def test_ipapi_normalise():
    ok = E.IPApiProvider.normalise(
        {
            "status": "success",
            "country": "United States",
            "countryCode": "US",
            "as": "AS15169 Google LLC",
            "isp": "Google LLC",
            "query": "8.8.8.8",
        }
    )
    assert ok["asn"] == "AS15169" and ok["org"] == "Google LLC" and ok["country"] == "United States"
    assert E.IPApiProvider.normalise({"status": "fail", "message": "reserved range"}) == {"error": "reserved range"}


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_ipinfo_lookup(monkeypatch):
    seen = []

    def urlopen(req, timeout):
        seen.append((req.full_url, req.get_header("Authorization")))
        return FakeResponse(json.dumps({"country": "US", "org": "AS1 Test"}).encode())

    monkeypatch.setattr(E.urllib.request, "urlopen", urlopen)
    out = E.IPInfoProvider(token="t0k", workers=2).lookup_many(["1.1.1.1", "8.8.8.8"])
    assert out["8.8.8.8"] == {"country_code": "US", "asn": "AS1", "org": "Test"}
    assert sorted(seen) == [
        ("https://ipinfo.io/1.1.1.1/json", "Bearer t0k"),
        ("https://ipinfo.io/8.8.8.8/json", "Bearer t0k"),
    ]


def test_ipapi_batches(monkeypatch):
    bodies = []

    def urlopen(req, timeout):
        batch = json.loads(req.data)
        bodies.append(len(batch))
        return FakeResponse(
            json.dumps([{"status": "success", "query": q["query"], "countryCode": "DE"} for q in batch]).encode()
        )

    monkeypatch.setattr(E.urllib.request, "urlopen", urlopen)
    ips = [f"1.1.{i // 250}.{i % 250}" for i in range(150)]
    out = E.IPApiProvider().lookup_many(ips)
    assert bodies == [100, 50] and len(out) == 150 and out[ips[0]]["country_code"] == "DE"


def _http_error(code):
    return urllib.error.HTTPError("https://x", code, "err", {}, io.BytesIO(b""))


def test_auth_error_aborts(monkeypatch):
    def urlopen(req, timeout):
        raise _http_error(403)

    monkeypatch.setattr(E.urllib.request, "urlopen", urlopen)
    with pytest.raises(E.AuthError):
        E.IPInfoProvider(token="bad").lookup_many(["1.1.1.1"])


def test_retry_then_per_ip_error(monkeypatch):
    calls = []

    def urlopen(req, timeout):
        calls.append(1)
        raise _http_error(503)

    monkeypatch.setattr(E.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(E.time, "sleep", lambda s: None)
    out = E.IPInfoProvider(workers=1).lookup_many(["1.1.1.1"])
    assert "error" in out["1.1.1.1"] and len(calls) == 4


def test_make_provider(monkeypatch):
    monkeypatch.setenv("IPINFO_TOKEN", "envtok")
    assert E.make_provider("ipinfo").token == "envtok"
    assert isinstance(E.make_provider("ip-api"), E.IPApiProvider)
    with pytest.raises(ValueError):
        E.make_provider("nope")

import csv
import io
import json

import pytest

from logscan import scan_text
from logscan.report import FORMATS, render

LOG = 'hit 8.8.8.8:53\nevil "=cmd|calc" 1.1.1.1 </script><b>x</b>\n'


@pytest.fixture
def data():
    result = scan_text(LOG)
    hits = sorted(result.hits.values(), key=lambda h: h.ip)
    hits[1].info = {"country_code": "US", "city": "Mountain View", "asn": "AS15169", "org": "Google LLC"}
    return result, hits


def test_every_format_renders(data):
    for fmt in FORMATS:
        assert render(*data, fmt)
    with pytest.raises(ValueError):
        render(*data, "pdf")


def test_table(data):
    out = render(*data, "table")
    assert "8.8.8.8" in out and "Mountain View, US" in out and "AS15169 Google LLC" in out
    assert "\033[" not in out
    assert "\033[" in render(*data, "table", color=True)


def test_empty_table():
    result = scan_text("nothing here")
    assert "No matching addresses" in render(result, [], "table")


def test_json(data):
    doc = json.loads(render(*data, "json"))
    assert doc["tool"] == "logscan"
    assert [a["ip"] for a in doc["addresses"]] == ["1.1.1.1", "8.8.8.8"]
    assert doc["addresses"][1]["ports"] == {"53": 1}
    assert doc["summary"]["unique"] == 2
    lines = render(*data, "ndjson").splitlines()
    assert [json.loads(x)["ip"] for x in lines] == ["1.1.1.1", "8.8.8.8"]


def test_csv_neutralises_formulas(data):
    rows = list(csv.DictReader(io.StringIO(render(*data, "csv"))))
    assert rows[0]["ip"] == "1.1.1.1"
    assert rows[1]["org"] == "Google LLC"
    assert rows[0]["sample"].startswith("evil")
    result = scan_text("=HYPERLINK(1.1.1.1)")
    row = next(csv.DictReader(io.StringIO(render(result, list(result.hits.values()), "csv"))))
    assert row["sample"].startswith("'=")


def test_markdown(data):
    out = render(*data, "markdown")
    assert out.startswith("# Logscan report") and "| 8.8.8.8 |" in out


def test_html_is_self_contained_and_escaped(data):
    out = render(*data, "html")
    assert out.startswith("<!doctype html>")
    assert "</script><b>" not in out
    assert "\\u003c/script\\u003e" in out
    assert "http://" not in out.split("<footer>")[0]  # no external resources

import bz2
import gzip
import lzma
from pathlib import Path

import pytest

from logscan import NetList, ScanOptions, scan, scan_text
from logscan.classify import SCOPES

LOG = """\
boot ok
connect to 8.8.8.8:53 ok
connect to 10.0.0.1:80 failed
ntp reply from 132.163.97.2
retry 8.8.8.8:853
dns 2001:4860:4860::8888
"""


def test_scan_text_defaults_to_public():
    result = scan_text(LOG)
    assert sorted(result.hits) == ["132.163.97.2", "2001:4860:4860::8888", "8.8.8.8"]
    hit = result.hits["8.8.8.8"]
    assert hit.count == 2
    assert dict(hit.ports) == {53: 1, 853: 1}
    assert (hit.first_seen.line, hit.last_seen.line) == (2, 5)
    assert hit.sample == "connect to 8.8.8.8:53 ok"
    assert result.filtered["private"] == 1
    s = result.summary()
    assert s["unique"] == 3 and s["ipv4"] == 2 and s["ipv6"] == 1 and s["matches"] == 5 and s["lines"] == 6


def test_scopes_ignore_watch_and_versions():
    opts = ScanOptions(
        scopes=frozenset(SCOPES),
        ignore=NetList(["132.163.0.0/16"]),
        watch=NetList(["8.8.8.0/24"]),
        ipv6=False,
    )
    result = scan_text(LOG, opts)
    assert sorted(result.hits) == ["10.0.0.1", "8.8.8.8"]
    assert result.hits["8.8.8.8"].watch == "8.8.8.0/24"
    assert result.hits["10.0.0.1"].watch is None
    assert result.filtered["ignored"] == 1
    assert [h.ip for h in result.watch_hits] == ["8.8.8.8"]


def test_unknown_scope_rejected():
    with pytest.raises(ValueError):
        ScanOptions(scopes=frozenset({"galaxy"}))


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    (tmp_path / "a.log").write_text("from 1.1.1.1\n")
    (tmp_path / "b.txt").write_text("\ufefffrom 9.9.9.9\n")
    sub = tmp_path / "sub"
    sub.mkdir()
    with gzip.open(sub / "c.log.gz", "wt") as fh:
        fh.write("from 4.4.4.4\n")
    with bz2.open(sub / "d.log.bz2", "wt") as fh:
        fh.write("from 5.5.5.5\n")
    with lzma.open(sub / "e.log.xz", "wt") as fh:
        fh.write("from 6.6.6.6\n")
    (sub / "blob.bin").write_bytes(b"\x00\x01 7.7.7.7")
    hidden = tmp_path / ".git"
    hidden.mkdir()
    (hidden / "x.log").write_text("from 3.3.3.3\n")
    return tmp_path


def test_directory_walk(tree):
    result = scan([str(tree)])
    assert sorted(result.hits) == ["1.1.1.1", "4.4.4.4", "5.5.5.5", "6.6.6.6", "9.9.9.9"]


def test_walk_options(tree):
    assert sorted(scan([str(tree)], ScanOptions(recursive=False)).hits) == ["1.1.1.1", "9.9.9.9"]
    assert sorted(scan([str(tree)], ScanOptions(include=["*.log*"])).hits) == [
        "1.1.1.1",
        "4.4.4.4",
        "5.5.5.5",
        "6.6.6.6",
    ]
    assert "9.9.9.9" not in scan([str(tree)], ScanOptions(exclude=["*.txt"])).hits
    assert "7.7.7.7" in scan([str(tree)], ScanOptions(include_binary=True)).hits


def test_duplicate_paths_scanned_once(tree):
    result = scan([str(tree / "a.log"), str(tree), str(tree / "a.log")])
    assert result.hits["1.1.1.1"].count == 1


def test_unreadable_source_is_reported(tmp_path):
    bad = tmp_path / "broken.gz"
    bad.write_bytes(b"not gzip at all")
    result = scan([str(bad)])
    assert result.sources[0].error and not result.hits
    assert result.summary()["sources_failed"] == 1


def test_stdin(monkeypatch):
    import io
    import sys

    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"x 1.0.0.1\n")))
    assert list(scan(["-"]).hits) == ["1.0.0.1"]


def test_sample_device_log():
    sample = Path(__file__).resolve().parent.parent / "examples" / "embedded-device.log"
    result = scan([str(sample)])
    assert list(result.hits) == ["132.163.97.2"]
    assert result.hits["132.163.97.2"].count == 6
    assert result.filtered["private"] == 42168

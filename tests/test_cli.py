import json

import pytest

from logscan import enrich as E
from logscan.cli import EXIT_WATCH, main


@pytest.fixture
def logs(tmp_path):
    (tmp_path / "a.log").write_text("x 8.8.8.8:53\ny 8.8.8.8\nz 10.0.0.1\nw 1.1.1.1\n")
    return tmp_path


def test_table_default(logs, capsys):
    assert main([str(logs), "--color", "never"]) == 0
    out = capsys.readouterr().out
    assert "8.8.8.8" in out and "10.0.0.1" not in out and "private=1" in out


def test_scope_all_json(logs, capsys):
    assert main([str(logs), "-s", "all", "-f", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert [a["ip"] for a in doc["addresses"]] == ["8.8.8.8", "1.1.1.1", "10.0.0.1"]


def test_sort_top_min_hits(logs, capsys):
    main([str(logs), "-f", "ndjson", "--sort", "ip"])
    assert [json.loads(x)["ip"] for x in capsys.readouterr().out.splitlines()] == ["1.1.1.1", "8.8.8.8"]
    main([str(logs), "-f", "ndjson", "--top", "1"])
    assert len(capsys.readouterr().out.splitlines()) == 1
    main([str(logs), "-f", "ndjson", "--min-hits", "2"])
    assert [json.loads(x)["ip"] for x in capsys.readouterr().out.splitlines()] == ["8.8.8.8"]


def test_output_file_format_inferred(logs, tmp_path):
    out = tmp_path / "r" / "report.html"
    assert main([str(logs), "-o", str(out), "-q"]) == 0
    assert out.read_text().startswith("<!doctype html>")


def test_watch_exit_code(logs, capsys):
    assert main([str(logs), "-w", "8.8.8.0/24", "--fail-on-watch", "--color", "never"]) == EXIT_WATCH
    assert "watch list" in capsys.readouterr().out
    assert main([str(logs), "-w", "9.9.9.9", "--fail-on-watch"]) == 0


def test_usage_errors(logs):
    with pytest.raises(SystemExit) as exc:
        main([str(logs / "missing.log")])
    assert exc.value.code == 2
    with pytest.raises(SystemExit):
        main([str(logs), "--ignore", "bogus"])


def test_all_inputs_failed(tmp_path, capsys):
    bad = tmp_path / "x.gz"
    bad.write_bytes(b"nope")
    assert main([str(bad)]) == 1


def test_enrich_flow(logs, tmp_path, monkeypatch, capsys):
    class Fake(E.Provider):
        name = "ipinfo"

        def lookup_many(self, ips):
            return {ip: {"country_code": "US", "asn": "AS15169", "org": "Google LLC"} for ip in ips}

    monkeypatch.setattr("logscan.cli.make_provider", lambda *a, **k: Fake())
    assert main([str(logs), "-e", "ipinfo", "--cache", str(tmp_path / "c.json"), "-f", "json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["addresses"][0]["info"]["org"] == "Google LLC"
    assert doc["summary"]["countries"] == {"US": 2}


def test_enrich_auth_failure(logs, monkeypatch, capsys):
    class Fake(E.Provider):
        def lookup_many(self, ips):
            raise E.AuthError("authentication failed (403)")

    monkeypatch.setattr("logscan.cli.make_provider", lambda *a, **k: Fake())
    assert main([str(logs), "-e", "ipinfo", "--no-cache"]) == 1
    assert "authentication failed" in capsys.readouterr().err


def test_module_entry_point():
    import os
    import subprocess
    import sys
    from pathlib import Path

    src = str(Path(__file__).resolve().parent.parent / "src")
    env = {**os.environ, "PYTHONPATH": src + os.pathsep + os.environ.get("PYTHONPATH", "")}
    proc = subprocess.run([sys.executable, "-m", "logscan", "--version"], capture_output=True, text=True, env=env)
    assert proc.returncode == 0 and proc.stdout.startswith("logscan ")

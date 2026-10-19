import ipaddress

import pytest

from logscan.netlist import NetList


def test_entries_and_files(tmp_path):
    f = tmp_path / "list.txt"
    f.write_text("# comment\n8.8.8.0/24  # google\n\n2001:db8::/32\n")
    nl = NetList(["1.1.1.1", f"@{f}"])
    assert len(nl) == 3 and nl
    assert ipaddress.ip_address("8.8.8.8") in nl
    assert ipaddress.ip_address("1.1.1.1") in nl
    assert ipaddress.ip_address("2001:db8::9") in nl
    assert ipaddress.ip_address("9.9.9.9") not in nl
    assert str(nl.match(ipaddress.ip_address("8.8.8.4"))) == "8.8.8.0/24"
    assert "8.8.8.8" not in nl  # strings are not addresses


def test_non_strict_cidr_and_errors():
    assert ipaddress.ip_address("10.0.0.9") in NetList(["10.0.0.5/24"])
    assert not NetList()
    with pytest.raises(ValueError, match="invalid"):
        NetList(["not-an-ip"])

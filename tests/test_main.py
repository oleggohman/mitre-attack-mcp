"""In-process tests of `main()` (startup flow); stdout is the MCP stream and must stay empty."""

import pytest

from mitre_mcp_server import server

pytestmark = pytest.mark.unit


@pytest.fixture
def calls(monkeypatch):
    log = []
    monkeypatch.setattr(server.mcp, "run", lambda transport: log.append(("run", transport)))
    monkeypatch.setattr(
        server, "load_all_domains", lambda: log.append(("load",)) or list(server.DOMAINS)
    )
    return log


def test_main_with_existing_data_does_not_download(monkeypatch, calls, capsys):
    monkeypatch.setattr(server, "check_existing_data", lambda: list(server.DOMAINS))
    monkeypatch.setattr(
        server, "download_all_domains", lambda force=False: pytest.fail("must not download")
    )
    server.main()
    out, err = capsys.readouterr()
    assert out == ""
    assert "Using existing data" in err
    assert "Downloading" not in err
    assert f"Loaded {len(server.DOMAINS)} domains" in err
    assert "Server ready!" in err
    assert calls == [("load",), ("run", "stdio")]


def test_main_with_missing_domain_downloads_first(monkeypatch, calls, capsys):
    monkeypatch.setattr(server, "check_existing_data", lambda: ["enterprise", "mobile", "ics"])

    def fake_download(force=False):
        calls.append(("download", force))
        return list(server.DOMAINS)

    monkeypatch.setattr(server, "download_all_domains", fake_download)
    server.main()
    out, err = capsys.readouterr()
    assert out == ""
    assert "Downloading MITRE ATT&CK data" in err
    assert "Downloaded 4/4 domains" in err
    assert "Using existing data" not in err
    assert calls == [("download", False), ("load",), ("run", "stdio")]

"""Tests for the shared conftest helpers (markers, require_domain, isolation guard)."""

import pytest
from conftest import check_state_unchanged, require_domain, snapshot_state

from mitre_mcp_server import server

pytestmark = pytest.mark.unit


def test_require_domain_fails_when_required(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "get_stix_path", lambda d: tmp_path / "missing.json")
    monkeypatch.setenv("MITRE_MCP_REQUIRE_DATA", "1")
    with pytest.raises(pytest.fail.Exception, match="not available"):
        require_domain("enterprise")


def test_require_domain_skips_otherwise(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "get_stix_path", lambda d: tmp_path / "missing.json")
    monkeypatch.delenv("MITRE_MCP_REQUIRE_DATA", raising=False)
    with pytest.raises(pytest.skip.Exception, match="not available"):
        require_domain("enterprise")


def test_require_domain_returns_data_when_present(monkeypatch, tmp_path):
    bundle = tmp_path / "bundle.json"
    bundle.write_text("{}")
    sentinel = object()
    monkeypatch.setattr(server, "get_stix_path", lambda d: bundle)
    monkeypatch.setattr(server, "get_attack_data", lambda d="enterprise": sentinel)
    assert require_domain("ics") is sentinel


def test_isolation_guard_detects_replaced_entry(monkeypatch):
    monkeypatch.setitem(server.attack_data, "ics-attack", object())  # ensure key exists
    before = snapshot_state()
    monkeypatch.setitem(server.attack_data, "ics-attack", object())
    problems = check_state_unchanged(before, snapshot_state())
    assert problems == ["attack_data['ics-attack'] was replaced"]


def test_isolation_guard_detects_removed_domain_and_entry(monkeypatch):
    monkeypatch.setitem(server.attack_data, "ics-attack", object())
    monkeypatch.setattr(server, "_loaded_domains", ["ics"])
    before = snapshot_state()
    monkeypatch.delitem(server.attack_data, "ics-attack")
    monkeypatch.setattr(server, "_loaded_domains", [])
    problems = check_state_unchanged(before, snapshot_state())
    assert "attack_data['ics-attack'] was removed" in problems
    assert "domain 'ics' was removed from _loaded_domains" in problems


def test_isolation_guard_allows_additions(monkeypatch):
    before = snapshot_state()
    monkeypatch.setitem(server.attack_data, "zzz-attack", object())
    assert check_state_unchanged(before, snapshot_state()) == []

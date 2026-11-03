"""Tests for the ATLAS download and path helpers (no network access)."""

import hashlib
import io

import pytest

from mitre_mcp_server import server


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "DATA_DIR", tmp_path)
    return tmp_path


def _patch_urlopen(monkeypatch, content, calls):
    def fake(url, timeout=None):
        calls.append(url)
        return _FakeResponse(content)

    monkeypatch.setattr(server.urllib.request, "urlopen", fake)


def test_atlas_in_domains():
    assert "atlas" in server.DOMAINS


def test_hash_mismatch_raises_and_leaves_no_file(data_dir, monkeypatch):
    calls = []
    _patch_urlopen(monkeypatch, b"not the bundle", calls)
    with pytest.raises(RuntimeError, match="hash mismatch"):
        server.download_domain_data("atlas")
    assert not server.get_stix_path("atlas").exists()
    assert not list(data_dir.rglob("*.tmp"))


def test_hash_match_writes_file(data_dir, monkeypatch):
    content = b'{"objects": []}'
    monkeypatch.setattr(server, "ATLAS_SHA256", hashlib.sha256(content).hexdigest())
    calls = []
    _patch_urlopen(monkeypatch, content, calls)
    domain, path = server.download_domain_data("atlas")
    assert domain == "atlas"
    assert path == server.get_stix_path("atlas")
    assert path.read_bytes() == content
    assert len(calls) == 1


def test_existing_file_not_redownloaded_unless_forced(data_dir, monkeypatch):
    content = b'{"objects": []}'
    monkeypatch.setattr(server, "ATLAS_SHA256", hashlib.sha256(content).hexdigest())
    calls = []
    _patch_urlopen(monkeypatch, content, calls)
    server.download_domain_data("atlas")
    server.download_domain_data("atlas")
    assert len(calls) == 1
    server.download_domain_data("atlas", force=True)
    assert len(calls) == 2


def test_stats_report_atlas_version(data_dir):
    path = server.get_stix_path("atlas")
    path.parent.mkdir(parents=True)
    path.write_text("{}")
    stats = server._compute_data_stats()
    assert stats["atlas"]["exists"] is True
    assert stats["atlas"]["version"] == server.ATLAS_VERSION

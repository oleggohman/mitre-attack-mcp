"""Download / load / startup helpers without network or the real cache (testing plan Task 8b)."""

import io
import json

import pytest

from mitre_mcp_server import server

pytestmark = pytest.mark.unit


@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "DATA_DIR", tmp_path)
    monkeypatch.setattr(server, "attack_data", {})
    monkeypatch.setattr(server, "_loaded_domains", [])
    return tmp_path


def write_bundle(path, objects=()):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "type": "bundle",
                "id": "bundle--00000000-0000-4000-8000-000000000000",
                "objects": list(objects),
            }
        )
    )


def test_check_existing_data_lists_domains_with_files(data_dir):
    assert server.check_existing_data() == []
    write_bundle(server.get_stix_path("ics"))
    write_bundle(server.get_stix_path("atlas"))
    assert server.check_existing_data() == ["ics", "atlas"]


def test_download_domain_data_rejects_unknown_domain(data_dir):
    with pytest.raises(ValueError, match="Invalid domain 'nope'"):
        server.download_domain_data("nope")


def test_download_domain_data_returns_existing_file_without_downloading(data_dir, monkeypatch):
    path = server.get_stix_path("mobile")
    write_bundle(path)
    monkeypatch.setattr(
        server.download_stix, "download_stix", lambda **k: pytest.fail("no download")
    )
    assert server.download_domain_data("mobile") == ("mobile", path)


def test_attack_download_passes_release_and_hash(data_dir, monkeypatch):
    calls = []

    def fake_download(**kwargs):
        calls.append(kwargs)
        write_bundle(server.get_stix_path("ics"))

    monkeypatch.setattr(server.download_stix, "download_stix", fake_download)
    assert server.download_domain_data("ics") == ("ics", server.get_stix_path("ics"))
    (call,) = calls
    assert call["domain"] == "ics" and call["stix_version"] == "2.1"
    assert call["release"] == server.release_info.LATEST_VERSION
    assert (
        call["known_hash"] == server.release_info.STIX21["ics"][server.release_info.LATEST_VERSION]
    )
    assert call["download_dir"] == str(data_dir)


def test_attack_download_that_leaves_no_file_is_an_error(data_dir, monkeypatch):
    monkeypatch.setattr(server.download_stix, "download_stix", lambda **k: None)
    with pytest.raises(RuntimeError, match="file not found"):
        server.download_domain_data("enterprise")


def test_atlas_download_that_leaves_no_file_is_an_error(data_dir, monkeypatch):
    monkeypatch.setattr(server, "_download_atlas", lambda path: None)
    with pytest.raises(RuntimeError, match="file not found"):
        server.download_domain_data("atlas")


def test_atlas_download_write_failure_removes_temp_file(data_dir, monkeypatch):
    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    content = b"bundle"
    monkeypatch.setattr(server, "ATLAS_SHA256", server.hashlib.sha256(content).hexdigest())
    monkeypatch.setattr(
        server.urllib.request, "urlopen", lambda url, timeout=None: Response(content)
    )

    def failing_replace(src, dst):
        raise OSError("disk full")

    monkeypatch.setattr(server.os, "replace", failing_replace)
    target = server.get_stix_path("atlas")
    with pytest.raises(OSError, match="disk full"):
        server._download_atlas(target)
    assert list(target.parent.iterdir()) == []  # temp file cleaned up, no bundle written


def test_atlas_temp_file_removal_failure_does_not_mask_the_error(data_dir, monkeypatch):
    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    content = b"bundle"
    monkeypatch.setattr(server, "ATLAS_SHA256", server.hashlib.sha256(content).hexdigest())
    monkeypatch.setattr(
        server.urllib.request, "urlopen", lambda url, timeout=None: Response(content)
    )
    monkeypatch.setattr(server.os, "replace", lambda s, d: (_ for _ in ()).throw(OSError("first")))

    def failing_unlink(path):
        raise OSError("second")

    monkeypatch.setattr(server.os, "unlink", failing_unlink)
    with pytest.raises(OSError, match="first"):
        server._download_atlas(server.get_stix_path("atlas"))


def test_download_all_domains_warns_and_continues(data_dir, monkeypatch, capsys):
    def fake(domain, force=False):
        if domain == "mobile":
            raise RuntimeError("offline")
        return domain, server.get_stix_path(domain)

    monkeypatch.setattr(server, "download_domain_data", fake)
    result = server.download_all_domains(force=True)
    assert [d for d, _ in result] == ["enterprise", "ics", "atlas"]
    assert "Warning: Could not download mobile domain: offline" in capsys.readouterr().err
    assert data_dir.is_dir()


def test_load_domain_validation_and_missing_file(data_dir):
    with pytest.raises(ValueError, match="Invalid domain"):
        server.load_domain("nope")
    with pytest.raises(FileNotFoundError, match="STIX data file not found"):
        server.load_domain("ics")


def test_load_domain_wraps_loader_failures(data_dir):
    path = server.get_stix_path("ics")
    path.parent.mkdir(parents=True)
    path.write_text("not json")
    with pytest.raises(RuntimeError, match="Failed to load ics domain data"):
        server.load_domain("ics")
    assert "ics-attack" not in server.attack_data


def test_load_domain_loads_once_and_registers(data_dir):
    write_bundle(server.get_stix_path("ics"))
    assert server.load_domain("ics") is True
    first = server.attack_data["ics-attack"]
    assert server.get_loaded_domains() == ["ics"]
    assert server.load_domain("ics") is True  # already loaded: same object, no duplicate
    assert server.attack_data["ics-attack"] is first
    assert server.get_loaded_domains() == ["ics"]
    server.get_loaded_domains().append("x")  # a copy is returned
    assert server.get_loaded_domains() == ["ics"]


def test_load_all_domains_reports_loaded_and_warns(data_dir, capsys):
    write_bundle(server.get_stix_path("ics"))
    assert server.load_all_domains() == ["ics"]
    err = capsys.readouterr().err
    for missing in ("enterprise", "mobile", "atlas"):
        assert f"Warning: Could not load {missing} domain" in err


def test_load_domain_does_not_duplicate_registered_domain(data_dir):
    write_bundle(server.get_stix_path("ics"))
    server._loaded_domains.append("ics")  # registered, but its data object is not cached
    server.load_domain("ics")
    assert server.get_loaded_domains() == ["ics"]

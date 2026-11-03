"""Shared fixtures."""

import hashlib
import os
from pathlib import Path

import pytest

from mitre_mcp_server import server

needs_atlas = pytest.mark.usefixtures("atlas_loaded")


def _atlas_bundle_path():
    primary = server.get_stix_path("atlas")
    if primary.exists():
        return primary
    tmp = os.environ.get("TMPDIR")
    if tmp:
        fallback = Path(tmp) / "atlas" / "v1160.json"
        if fallback.exists():
            if hashlib.sha256(fallback.read_bytes()).hexdigest() == server.ATLAS_SHA256:
                return fallback
    return None


@pytest.fixture(scope="module")
def atlas_loaded():
    path = _atlas_bundle_path()
    if path is None:
        msg = "ATLAS bundle not available (no cached file and no verified $TMPDIR copy)"
        if os.environ.get("MITRE_MCP_REQUIRE_ATLAS") == "1":
            pytest.fail(msg)
        pytest.skip(msg)
    old = server.attack_data.get("atlas-attack")
    was_loaded = "atlas" in server._loaded_domains
    server.attack_data["atlas-attack"] = server._MitreData(str(path))
    if not was_loaded:
        server._loaded_domains.append("atlas")
    yield server.attack_data["atlas-attack"]
    if old is None:
        server.attack_data.pop("atlas-attack", None)
    else:
        server.attack_data["atlas-attack"] = old
    if not was_loaded and "atlas" in server._loaded_domains:
        server._loaded_domains.remove("atlas")

"""Shared fixtures."""

import functools
import hashlib
import json
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
        fallback = Path(tmp) / "atlas" / f"v{server.ATLAS_VERSION.replace('.', '')}.json"
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


# ---------------------------------------------------------------------------
# Markers, data requirement, state isolation, shared helpers (testing plan D10)
# ---------------------------------------------------------------------------


def pytest_collection_modifyitems(config, items):
    """Tag every test that is neither `unit` nor `protocol` with `data`."""
    for item in items:
        if item.get_closest_marker("unit") or item.get_closest_marker("protocol"):
            continue
        item.add_marker(pytest.mark.data)


def require_domain(domain):
    """Return the loaded data of `domain`; fail (REQUIRE_DATA=1) or skip if the cache is missing."""
    path = server.get_stix_path(domain)
    if not path.exists():
        msg = f"STIX bundle for {domain} not available at {path}"
        if os.environ.get("MITRE_MCP_REQUIRE_DATA") == "1":
            pytest.fail(msg)
        pytest.skip(msg)
    return server.get_attack_data(domain)


@functools.cache
def raw_bundle(domain):
    """Parsed raw STIX bundle of `domain` (cached; treat as read-only)."""
    return json.loads(server.get_stix_path(domain).read_text(encoding="utf-8"))


async def call_tool(name, args):
    """Call a tool in-process (argument validation + serialisation as on the wire).

    Returns (result_dict, wire_bytes). Raises like `server.mcp.call_tool` on tool errors.
    """
    res = await server.mcp.call_tool(name, args)
    assert res.is_error is False
    wire = len(res.model_dump_json(by_alias=True))
    return res.structured_content["result"], wire


def snapshot_state():
    """Snapshot of the module state that tests must not leak into."""
    return (
        {k: id(v) for k, v in server.attack_data.items()},
        list(server._loaded_domains),
    )


def check_state_unchanged(before, after):
    """Return a list of problems: replaced/removed entries and removed loaded domains.

    Additions (legitimate lazy loading) are allowed.
    """
    problems = []
    for key, ident in before[0].items():
        if key not in after[0]:
            problems.append(f"attack_data[{key!r}] was removed")
        elif after[0][key] != ident:
            problems.append(f"attack_data[{key!r}] was replaced")
    for dom in before[1]:
        if dom not in after[1]:
            problems.append(f"domain {dom!r} was removed from _loaded_domains")
    return problems


@pytest.fixture(autouse=True)
def _state_isolation_guard():
    """Fail any test that replaces or removes module state (additions are allowed)."""
    before = snapshot_state()
    yield
    problems = check_state_unchanged(before, snapshot_state())
    assert not problems, "test leaked module state: " + "; ".join(problems)

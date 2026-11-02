"""Regression tests: list/search tools must exclude revoked and deprecated objects by default.

Requires the enterprise STIX bundle to be present in the data directory
(downloaded on first server start).
"""

import functools
import json

import pytest

from mitre_mcp_server import server


@functools.cache
def _stale_set() -> frozenset:
    path = server.get_stix_path("enterprise")
    objs = json.loads(path.read_text())["objects"]
    return frozenset(
        o["id"] for o in objs if o.get("revoked", False) or o.get("x_mitre_deprecated", False)
    )


def _is_revoked_or_deprecated(stix_id: str) -> bool:
    return stix_id in _stale_set()


def _stale_ids(items, key="stix_id"):
    return [i[key] for i in items if _is_revoked_or_deprecated(i[key])]


async def test_techniques_by_platform_excludes_revoked_by_default():
    res = await server.get_techniques_by_platform("IaaS", include_description=False)
    assert res["count"] > 0
    assert _stale_ids(res["techniques"]) == []


async def test_techniques_by_platform_can_include_revoked():
    res = await server.get_techniques_by_platform(
        "IaaS", include_description=False, remove_revoked_deprecated=False
    )
    assert _stale_ids(res["techniques"]) != []


async def test_objects_by_name_excludes_revoked_by_default():
    # T1522 (revoked) and T1552.005 share this name.
    res = await server.get_objects_by_name("Cloud Instance Metadata API", "attack-pattern")
    assert res["count"] == 1
    assert res["objects"][0]["attack_id"] == "T1552.005"


async def test_objects_by_name_can_include_revoked():
    res = await server.get_objects_by_name(
        "Cloud Instance Metadata API", "attack-pattern", remove_revoked_deprecated=False
    )
    assert res["count"] == 2


async def test_objects_by_content_excludes_revoked_by_default():
    res = await server.get_objects_by_content("cloud", "attack-pattern", include_description=False)
    assert res["count"] > 0
    assert _stale_ids(res["objects"]) == []


def _object_ids(res):
    # created/modified_after tools may use different list keys; collect any STIX IDs present.
    for key in ("objects", "results", "items"):
        if key in res:
            return [o.get("stix_id") or o.get("id") for o in res[key]]
    raise AssertionError(f"no object list in result keys: {list(res)}")


@pytest.mark.parametrize("tool", ["get_objects_created_after", "get_objects_modified_after"])
async def test_objects_after_timestamp_excludes_revoked_by_default(tool):
    res = await getattr(server, tool)("2018-01-01T00:00:00Z", include_description=False)
    ids = _object_ids(res)
    assert ids
    assert all(ids), "every returned object must carry its STIX ID"
    assert [i for i in ids if _is_revoked_or_deprecated(i)] == []


@pytest.mark.parametrize("tool", ["get_objects_created_after", "get_objects_modified_after"])
async def test_objects_after_timestamp_can_include_revoked(tool):
    res = await getattr(server, tool)(
        "2018-01-01T00:00:00Z", include_description=False, remove_revoked_deprecated=False
    )
    assert [i for i in _object_ids(res) if _is_revoked_or_deprecated(i)] != []

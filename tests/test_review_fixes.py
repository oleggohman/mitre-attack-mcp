"""Regression tests for review findings (detection index, ID resolution, pagination, score)."""

import math

import pytest
from conftest import needs_atlas

from mitre_mcp_server import server

META_KEYS = {"total", "returned", "offset", "limit", "has_more"}


async def _stix(attack_id, typ):
    res = await server.get_object_by_attack_id(attack_id, typ)
    return res["object"]["stix_id"]


# --- A1: failed detection index builds are not cached -------------------------------------


def test_detection_index_failure_not_cached(monkeypatch, capsys):
    data = server.get_attack_data("enterprise")
    if hasattr(data, "_mcp_detection_index"):
        monkeypatch.delattr(data, "_mcp_detection_index")
    real = data.get_analytics
    calls = {"n": 0}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return real(*args, **kwargs)

    monkeypatch.setattr(data, "get_analytics", flaky)
    first = data._detection_index()
    assert first["analytics_by_id"] == {}
    assert "boom" in capsys.readouterr().err
    second = data._detection_index()
    assert second["analytics_by_id"]  # retried and now populated
    assert data._detection_index() is second  # successful build is cached
    monkeypatch.delattr(data, "_mcp_detection_index")


# --- A2: ATT&CK IDs for group tools ---------------------------------------------------------


@pytest.mark.parametrize("gid", ["G1015", "g1015"])
async def test_techniques_used_by_group_accepts_attack_id(gid):
    res = await server.get_techniques_used_by_group(gid)
    assert res["count"] > 0
    assert res["group"]["attack_id"] == "G1015"
    assert res["group"]["stix_id"].startswith("intrusion-set--")


@pytest.mark.parametrize("gid", ["G1015", "g1015"])
async def test_group_software_accepts_attack_id(gid):
    res = await server.get_techniques_used_by_group_software(gid)
    assert res["count"] > 0
    assert res["group"]["attack_id"] == "G1015"


async def test_group_software_include_description():
    off = await server.get_techniques_used_by_group_software("G1015")
    on = await server.get_techniques_used_by_group_software("G1015", include_description=True)
    assert all(not t.get("description") for t in off["techniques"])
    assert any(t.get("description") for t in on["techniques"])


# --- A4: canonical technique id ---------------------------------------------------------------


async def test_technique_by_id_canonical_id():
    res = await server.get_technique_by_id("t1059")
    assert res["found"] is True
    assert res["technique"]["id"] == "T1059"


# --- A5: non-technique STIX IDs ---------------------------------------------------------------


async def test_detection_strategies_rejects_non_technique():
    gid = await _stix("G1015", "intrusion-set")
    res = await server.get_detection_strategies_for_technique(gid)
    assert res["technique"] is None
    assert res["count"] == 0
    assert "not found" in res["message"]


# --- A6: technique ID passed to the data-component tool ------------------------------------------


async def test_techniques_detected_by_datacomponent_with_technique_id():
    res = await server.get_techniques_detected_by_datacomponent("T1059")
    assert res["count"] == 0
    assert res["message"]


# --- B1: empty-result responses carry pagination meta -------------------------------------------


def _assert_empty_meta(res):
    assert META_KEYS <= set(res)
    assert res["total"] == 0
    assert res["returned"] == 0
    assert res["has_more"] is False


async def test_empty_modified_after_has_meta():
    _assert_empty_meta(await server.get_objects_modified_after("2099-01-01T00:00:00Z"))


async def test_empty_created_after_has_meta():
    _assert_empty_meta(await server.get_objects_created_after("2099-01-01T00:00:00Z"))


async def test_empty_platform_has_meta():
    _assert_empty_meta(await server.get_techniques_by_platform("Nonexistent"))


@needs_atlas
async def test_empty_atlas_groups_and_software_have_meta():
    _assert_empty_meta(await server.get_all_groups(domain="atlas"))
    _assert_empty_meta(await server.get_all_software(domain="atlas"))


# --- B2: limit semantics ------------------------------------------------------------------------


@pytest.mark.parametrize("limit", [0, -5])
def test_paginate_nonpositive_limit_returns_nothing(limit):
    page, meta = server._paginate([1, 2, 3], limit, 0)
    assert page == []
    assert meta == {"total": 3, "returned": 0, "offset": 0, "limit": 0, "has_more": True}


def test_paginate_none_is_unlimited():
    page, meta = server._paginate([1, 2, 3], None, 1)
    assert page == [2, 3] and meta["limit"] is None and meta["has_more"] is False


async def test_tool_limit_zero_is_count_probe():
    res = await server.get_all_groups(limit=0)
    assert res["groups"] == []
    assert res["total"] > 0 and res["returned"] == 0 and res["has_more"] is True


# --- B4: generate_layer score validation --------------------------------------------------------


@pytest.mark.parametrize("score", [math.nan, math.inf, True])
async def test_generate_layer_rejects_bad_score(score):
    res = await server.generate_layer("G1015", score=score)
    assert res["success"] is False
    assert "score" in res["message"]
    assert res["layer"] is None

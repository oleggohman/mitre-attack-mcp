"""Regression tests for tools that consume library RelationshipEntry wrappers."""

import re

import pytest
from conftest import needs_atlas
from mitre_mcp_server import server


async def _stix(attack_id, domain="enterprise", typ="attack-pattern"):
    res = await server.get_object_by_attack_id(attack_id, typ, domain=domain)
    assert res["found"] is True
    return res["object"]["stix_id"]


# --- Task 1: sub-technique / parent tools ---------------------------------


async def test_subtechniques_of_technique_enterprise():
    res = await server.get_subtechniques_of_technique(await _stix("T1059"))
    assert res["count"] > 0
    for s in res["subtechniques"]:
        assert s["attack_id"].startswith("T1059.")
        assert s["name"] and s["stix_id"]
    assert res["subtechniques"][0]["name"] in res["formatted"]


@needs_atlas
async def test_subtechniques_of_technique_atlas():
    res = await server.get_subtechniques_of_technique(
        await _stix("AML.T0051", "atlas"), domain="atlas"
    )
    ids = {s["attack_id"] for s in res["subtechniques"]}
    assert {"AML.T0051.000", "AML.T0051.001", "AML.T0051.002"} <= ids


async def test_parent_of_subtechnique_enterprise():
    res = await server.get_parent_technique_of_subtechnique(await _stix("T1059.001"))
    assert res["parent"]["attack_id"] == "T1059"
    assert res["parent"]["name"] and res["parent"]["stix_id"]


@needs_atlas
async def test_parent_of_subtechnique_atlas():
    res = await server.get_parent_technique_of_subtechnique(
        await _stix("AML.T0051.000", "atlas"), domain="atlas"
    )
    assert res["parent"]["attack_id"] == "AML.T0051"


async def test_parent_of_parent_technique_is_not_subtechnique():
    res = await server.get_parent_technique_of_subtechnique(await _stix("T1059"))
    assert res["parent"] is None
    assert "not a subtechnique" in res["message"]


def _assert_parents(res):
    assert res["count"] > 0
    for s in res["subtechniques"]:
        assert s["parent_attack_id"] and s["parent_name"] and s["parent_stix_id"]


async def test_all_subtechniques_have_parent_enterprise():
    _assert_parents(await server.get_all_subtechniques(domain="enterprise"))


@needs_atlas
async def test_all_subtechniques_have_parent_atlas():
    _assert_parents(await server.get_all_subtechniques(domain="atlas"))


# --- Task 2: group -> campaigns --------------------------------------------


async def test_campaigns_attributed_to_group():
    data = server.get_attack_data("enterprise")
    for g in data.get_groups(remove_revoked_deprecated=True):
        if data.get_campaigns_attributed_to_group(g["id"]):
            gid = g["id"]
            break
    else:
        raise AssertionError("no group with campaigns found")
    res = await server.get_campaigns_attributed_to_group(gid)
    assert res["count"] > 0
    for c in res["campaigns"]:
        assert c["name"] and c["stix_id"] and c["attack_id"]
    assert res["campaigns"][0]["name"] in res["formatted"]


# --- Task 3: mitigation -> techniques --------------------------------------


async def test_techniques_mitigated_enterprise():
    mid = await _stix("M1036", typ="course-of-action")
    res = await server.get_techniques_mitigated_by_mitigation(mid)
    assert res["count"] > 0
    for t in res["techniques"]:
        assert t["attack_id"] and t["name"] and t["stix_id"]


@needs_atlas
async def test_techniques_mitigated_atlas(atlas_loaded):
    for m in atlas_loaded.get_objects_by_type("course-of-action"):
        if atlas_loaded.get_techniques_mitigated_by_mitigation(m["id"]):
            mid = m["id"]
            break
    else:
        raise AssertionError("no atlas mitigation with techniques")
    res = await server.get_techniques_mitigated_by_mitigation(mid, domain="atlas")
    assert res["count"] > 0
    assert all(t["attack_id"].startswith("AML.T") for t in res["techniques"])


# --- Task 4: ICS asset pair -------------------------------------------------


def _need_ics():
    if not server.get_stix_path("ics").exists():
        pytest.skip("ICS data not cached")


async def test_ics_asset_tools():
    _need_ics()
    res = await server.get_assets_targeted_by_technique(
        await _stix("T0800", "ics"), domain="ics"
    )
    assert res["count"] > 0
    for a in res["assets"]:
        assert a["name"] and a["stix_id"]
    res2 = await server.get_techniques_targeting_asset(
        res["assets"][0]["stix_id"], domain="ics"
    )
    assert res2["count"] > 0
    for t in res2["techniques"]:
        assert t["id"] and t["name"] and t["stix_id"]


# --- Task 5: data component -------------------------------------------------


async def test_techniques_detected_by_datacomponent_unwraps(monkeypatch):
    data = server.get_attack_data("enterprise")
    dc = data.get_objects_by_type("x-mitre-data-component")[0]
    tech = data.get_techniques(include_subtechniques=False)[0]
    entry = {"object": tech, "relationships": []}
    monkeypatch.setattr(
        data, "get_techniques_detected_by_datacomponent", lambda _id: [entry]
    )
    res = await server.get_techniques_detected_by_datacomponent(dc["id"])
    assert res["count"] == 1
    t = res["techniques"][0]
    assert t["attack_id"] and t["name"] and t["stix_id"] == tech["id"]
    assert t["name"] in res["formatted"]


# --- Task 6: parent techniques ----------------------------------------------


async def test_all_parent_techniques_enterprise():
    data = server.get_attack_data("enterprise")
    expected = data.get_techniques(include_subtechniques=False, remove_revoked_deprecated=True)
    res = await server.get_all_parent_techniques(domain="enterprise")
    assert res["count"] == len(expected)


@needs_atlas
async def test_all_parent_techniques_atlas():
    res = await server.get_all_parent_techniques(domain="atlas")
    assert res["count"] == 101
    assert not any(re.search(r"\.\d{3}$", t["attack_id"]) for t in res["parent_techniques"])

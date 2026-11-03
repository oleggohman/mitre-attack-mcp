"""Library-level ATLAS tests (subclass behaviour)."""

import pytest

from mitre_mcp_server import server

needs_atlas = pytest.mark.usefixtures("atlas_loaded")


def _t0051(atlas):
    return atlas.get_object_by_attack_id("AML.T0051", "attack-pattern")


def test_get_tactics_and_matrices(atlas_loaded):
    assert len(atlas_loaded.get_tactics()) == 16
    assert len(atlas_loaded.get_matrices()) == 1


def test_get_attack_id(atlas_loaded):
    tech = _t0051(atlas_loaded)
    assert atlas_loaded.get_attack_id(tech["id"]) == "AML.T0051"
    tactic = atlas_loaded.get_tactics()[0]
    assert atlas_loaded.get_attack_id(tactic["id"]).startswith("AML.TA")
    mit = atlas_loaded.get_objects_by_type("course-of-action")[0]
    assert atlas_loaded.get_attack_id(mit["id"]).startswith("AML.M")


def test_tactics_by_technique(atlas_loaded):
    tech = _t0051(atlas_loaded)
    assert atlas_loaded.get_tactics_by_technique(tech["id"])


def test_techniques_by_tactic(atlas_loaded):
    res = atlas_loaded.get_techniques_by_tactic("ai-attack-staging", "atlas-attack")
    assert len(res) > 0


# --- Tool-level behaviour -------------------------------------------------


async def _t0051_stix_id():
    res = await server.get_object_by_attack_id("AML.T0051", "attack-pattern", domain="atlas")
    return res["object"]["stix_id"]


@needs_atlas
async def test_get_all_tactics_atlas():
    res = await server.get_all_tactics(domain="atlas")
    assert res["count"] == 16
    for t in res["tactics"]:
        assert t["name"] and t["stix_id"]
        assert t["attack_id"].startswith("AML.TA")
    staging = [t for t in res["tactics"] if t["name"] == "AI Attack Staging"]
    assert len(staging) == 1
    assert staging[0]["shortname"] == "ai-attack-staging"


@needs_atlas
async def test_get_all_techniques_atlas():
    res = await server.get_all_techniques(domain="atlas")
    assert res["count"] > 0
    assert all(t["attack_id"].startswith("AML.T") for t in res["techniques"])


@needs_atlas
async def test_get_object_by_attack_id_atlas():
    res = await server.get_object_by_attack_id("AML.T0051", "attack-pattern", domain="atlas")
    assert res["found"] is True
    assert res["object"]["name"] == "LLM Prompt Injection"
    assert res["object"]["id"] == "AML.T0051"
    assert "ID: AML.T0051" in res["formatted"]


@needs_atlas
async def test_mitigations_for_technique_atlas():
    stix_id = await _t0051_stix_id()
    res = await server.get_mitigations_mitigating_technique(stix_id, domain="atlas")
    assert res["count"] >= 1
    assert any((m.get("attack_id") or "").startswith("AML.M") for m in res["mitigations"])


@needs_atlas
async def test_techniques_by_tactic_name_and_shortname_atlas():
    a = await server.get_techniques_by_tactic("AI Attack Staging", "atlas")
    b = await server.get_techniques_by_tactic("ai-attack-staging", "atlas")
    assert a["count"] > 0
    assert a["count"] == b["count"]


async def test_techniques_by_tactic_display_name_enterprise():
    res = await server.get_techniques_by_tactic("Initial Access", "enterprise")
    assert res["count"] > 0


@needs_atlas
async def test_tactics_by_technique_atlas():
    stix_id = await _t0051_stix_id()
    res = await server.get_tactics_by_technique(stix_id, domain="atlas")
    assert res["count"] > 0
    assert all(t["name"] and t["stix_id"] for t in res["tactics"])


@needs_atlas
async def test_matrices_and_tactics_by_matrix_atlas():
    res = await server.get_all_matrices(domain="atlas")
    assert [m["name"] for m in res["matrices"]] == ["ATLAS Matrix"]
    tac = await server.get_tactics_by_matrix(res["matrices"][0]["stix_id"], domain="atlas")
    assert tac["count"] == 16
    assert all(t["name"] and t["stix_id"] for t in tac["tactics"])


@needs_atlas
async def test_get_all_groups_atlas_empty():
    res = await server.get_all_groups(domain="atlas")
    assert res["count"] == 0


async def test_generate_layer_atlas_guard():
    res = await server.generate_layer("AML.M0000", domain="atlas")
    assert "ATLAS layers not supported" in str(res)
    assert "Invalid ATT&CK ID format" not in str(res)


async def test_get_layer_metadata_atlas_rejected():
    res = await server.get_layer_metadata("atlas")
    assert res["success"] is False
    assert "ATLAS layers not supported" in res["message"]
    assert "Must be one of" not in res["message"]

"""Regression tests for bugs found by the smoke suite (testing plan D13)."""

import pytest
from conftest import call_tool, raw_bundle, require_domain

from mitre_mcp_server import server

GHOST = "00000000-0000-4000-8000-000000000000"


async def test_revoked_mobile_techniques_have_attack_ids():
    result, _ = await call_tool("get_revoked_techniques", {"domain": "mobile"})
    assert result["count"] > 0
    assert all(t["id"] for t in result["techniques"])
    assert any(t["id"] == "T1425" for t in result["techniques"])


def test_get_attack_id_accepts_legacy_source_names():
    data = server.get_attack_data("mobile")
    assert data.get_attack_id("attack-pattern--11bd699b-f2c2-4e48-bf46-fb3f8acd9799") == "T1425"


@pytest.mark.parametrize("domain", ["enterprise", "atlas"])
async def test_subtechniques_of_unknown_technique_is_not_found(domain):
    result, _ = await call_tool(
        "get_subtechniques_of_technique",
        {"technique_stix_id": f"attack-pattern--{GHOST}", "domain": domain},
    )
    assert result["count"] == 0 and result["subtechniques"] == []
    assert result["parent"]["attack_id"] is None
    assert "not found" in result["message"]


@pytest.mark.parametrize("domain", ["enterprise", "atlas"])
async def test_techniques_mitigated_by_unknown_mitigation_is_not_found(domain):
    result, _ = await call_tool(
        "get_techniques_mitigated_by_mitigation",
        {"mitigation_stix_id": f"course-of-action--{GHOST}", "domain": domain},
    )
    assert result["found"] is False and result["count"] == 0
    assert "not found" in result["message"]


async def test_three_tools_publish_output_schema():
    tools = {t.name: t for t in await server.mcp.list_tools()}
    for name in (
        "get_datacomponents_detecting_technique",
        "get_tactics_by_matrix",
        "get_tactics_by_technique",
    ):
        assert tools[name].output_schema is not None, name


@pytest.mark.parametrize(
    "query,attack_id", [("APT1", "G0006"), ("apt3", "G0022"), ("APT29", "G0016")]
)
async def test_group_lookup_prefers_exact_name_over_partial(query, attack_id):
    by_name, _ = await call_tool("get_group_by_name", {"group_name": query})
    assert by_name["group"]["attack_id"] == attack_id
    techniques, _ = await call_tool("get_group_techniques", {"group_name": query})
    assert techniques["group"]["attack_id"] == attack_id


async def test_group_lookup_falls_back_to_alias_then_partial():
    alias, _ = await call_tool("get_group_by_name", {"group_name": "Cozy Bear"})
    assert alias["group"]["attack_id"] == "G0016"
    partial, _ = await call_tool("get_group_by_name", {"group_name": "Cozy"})
    assert partial["found"] is True
    missing, _ = await call_tool("get_group_by_name", {"group_name": "Nonexistent-xyz"})
    assert missing["found"] is False


async def test_get_stats_success_flag_and_counts():
    result, _ = await call_tool("get_stats", {"domain": "enterprise"})
    assert result["success"] is True
    assert result["stats"]["techniques"] > 0
    assert all(isinstance(v, int) for v in result["stats"].values())
    assert "statistics" in result["message"]


async def test_get_stats_reports_failure_when_one_accessor_raises(monkeypatch):
    data = server.get_attack_data("ics")

    def boom(**kwargs):
        raise RuntimeError("groups lookup exploded")

    monkeypatch.setattr(data, "get_groups", boom)
    res = await server.mcp.call_tool("get_stats", {"domain": "ics"})
    result = res.structured_content["result"]
    assert result["success"] is False
    assert result["stats"]["groups"] is None
    assert result["stats"]["techniques"] > 0
    assert "groups lookup exploded" in result["message"]
    assert "ATT&CK object statistics" not in result["message"]


@pytest.mark.unit
def test_readme_tool_counts_match_registry():
    import asyncio
    import re
    from pathlib import Path

    readme = (Path(__file__).parent.parent / "README.md").read_text(encoding="utf-8")
    counts = [int(m) for m in re.findall(r"\b(\d+) tools\b", readme)]
    assert counts, "README no longer states the tool count"
    registered = len(asyncio.run(server.mcp.list_tools()))
    assert counts == [registered] * len(counts)


async def test_empty_group_search_lists_every_group():
    require_domain("ics")
    everything, _ = await call_tool("search_groups", {"query": "", "domain": "ics"})
    all_groups, _ = await call_tool("get_all_groups", {"domain": "ics"})
    assert everything["count"] == all_groups["count"] > 0


@pytest.mark.parametrize("query", ["", "   "])
async def test_empty_group_query_matches_nothing(query):
    by_name, _ = await call_tool("get_group_by_name", {"group_name": query})
    assert by_name["found"] is False and by_name["group"] is None
    assert "ambiguous_matches" not in by_name
    techniques, _ = await call_tool("get_group_techniques", {"group_name": query})
    assert techniques["found"] is False and techniques["count"] == 0


def _raw_groups_matching(text):
    """ATT&CK IDs of active enterprise groups whose name or alias contains `text` (raw data)."""
    ids = []
    for o in raw_bundle("enterprise")["objects"]:
        if o["type"] != "intrusion-set" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        names = [o["name"], *o.get("aliases", [])]
        if any(text in n.lower() for n in names):
            ids.append(
                next(
                    r["external_id"]
                    for r in o["external_references"]
                    if r["source_name"] == "mitre-attack"
                )
            )
    return sorted(ids)


@pytest.mark.parametrize("tool", ["get_group_by_name", "get_group_techniques"])
async def test_ambiguous_partial_group_query_lists_candidates(tool):
    candidates = _raw_groups_matching("apt")
    assert len(candidates) > 10  # raw check: the query is genuinely ambiguous and exceeds the cap
    res, _ = await call_tool(tool, {"group_name": "apt"})
    assert res["found"] is True
    assert res["group"]["attack_id"] == candidates[0]
    assert res["ambiguous_matches"] == candidates[:10]
    assert "matched several groups" in res["message"] and candidates[0] in res["message"]


async def test_unambiguous_group_queries_have_no_candidate_list():
    for query in ("APT29", "Cozy"):  # exact name, single partial match
        assert len(_raw_groups_matching(query.lower())) >= 1
        res, _ = await call_tool("get_group_by_name", {"group_name": query})
        assert res["found"] is True and "ambiguous_matches" not in res

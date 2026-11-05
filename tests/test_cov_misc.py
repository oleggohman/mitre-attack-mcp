"""Remaining small branches: helpers, empty queries, failing library calls (plan Task 8h)."""

from types import SimpleNamespace

import pytest
from stubs import boom, entry, install, obj, sid

from mitre_mcp_server import server

pytestmark = pytest.mark.unit


def test_safe_attack_id_handles_missing_ids_and_lookup_errors():
    data = SimpleNamespace(get_attack_id=lambda i: "T1")
    assert server._safe_attack_id(data, None) is None
    assert server._safe_attack_id(data, "") is None
    assert server._safe_attack_id(data, "x") == "T1"
    assert server._safe_attack_id(SimpleNamespace(get_attack_id=boom), "x") is None


def test_format_objects_unwraps_relationship_entries(monkeypatch):
    tech = obj("attack-pattern", 1, "Wrapped")
    install(monkeypatch, [tech], {tech["id"]: "T1"})
    wrapped = server.format_objects([entry(tech)], include_description=False, domain="enterprise")
    bare = server.format_objects([tech], include_description=False, domain="enterprise")
    assert wrapped == bare and "Name: Wrapped" in wrapped and "T1" in wrapped


async def test_mitigations_tool_accepts_wrapped_and_bare_entries(monkeypatch):
    tech = obj("attack-pattern", 1, "Technique")
    mit_a = obj("course-of-action", 1, "Wrapped mitigation")
    mit_b = SimpleNamespace(id=sid("course-of-action", 2), name="Bare mitigation")
    mit_c = SimpleNamespace(object=obj("course-of-action", 3, "Attribute mitigation"))
    install(
        monkeypatch,
        [tech, mit_a],
        {mit_a["id"]: "M1", mit_b.id: "M2"},
        get_mitigations_mitigating_technique=lambda i: [entry(mit_a), mit_b, mit_c],
    )
    res = await server.mcp.call_tool(
        "get_mitigations_mitigating_technique", {"technique_stix_id": tech["id"]}
    )
    names = [m["name"] for m in res.structured_content["result"]["mitigations"]]
    assert names == ["Wrapped mitigation", "Bare mitigation", "Attribute mitigation"]


async def test_group_techniques_survive_a_failing_relationship_query(monkeypatch):
    group = obj("intrusion-set", 1, "Group", aliases=["Group"])
    install(
        monkeypatch,
        [group],
        {group["id"]: "G1"},
        get_groups=lambda remove_revoked_deprecated: [group],
        get_techniques_used_by_group=boom,
    )
    res = await server.mcp.call_tool("get_group_techniques", {"group_name": "group"})
    result = res.structured_content["result"]
    assert result["found"] is True and result["count"] == 0 and result["techniques"] == []


async def test_group_software_techniques_filter_revoked_without_library_helper(monkeypatch):
    group = obj("intrusion-set", 1, "Group")
    live, dead = obj("attack-pattern", 1, "Live"), obj("attack-pattern", 2, "Dead", revoked=True)
    install(
        monkeypatch,
        [group, live, dead],
        {live["id"]: "T1"},
        get_techniques_used_by_group_software=lambda g: [live, dead],
        remove_revoked_deprecated=boom,
    )
    res = await server.mcp.call_tool(
        "get_techniques_used_by_group_software",
        {"group_stix_id": group["id"], "include_campaigns": False},
    )
    assert [t["attack_id"] for t in res.structured_content["result"]["techniques"]] == ["T1"]


async def test_software_tools_skip_entries_without_objects(monkeypatch):
    group = obj("intrusion-set", 1, "Group")
    install(monkeypatch, [group], {}, get_software_used_by_group=lambda g: [entry(None)])
    res = await server.mcp.call_tool("get_software_used_by_group", {"group_stix_id": group["id"]})
    result = res.structured_content["result"]
    # An entry whose object is missing is skipped: nothing is counted, listed or formatted.
    assert result["count"] == 0 and result["software"] == [] and result["formatted"] == ""


def test_load_all_domains_ignores_domains_that_report_not_loaded(monkeypatch):
    monkeypatch.setattr(server, "load_domain", lambda d: d != "mobile")
    assert server.load_all_domains() == ["enterprise", "ics", "atlas"]


async def test_procedure_examples_by_tactic_formatting_with_library_relationships(monkeypatch):
    """F6: real data hits a missing library method, so the formatting code runs on a stub."""
    tactic = obj("x-mitre-tactic", 1, "Execution", x_mitre_shortname="execution")
    group = SimpleNamespace(**obj("intrusion-set", 1, "Group"))  # library returns stix2 objects
    tech = SimpleNamespace(**obj("attack-pattern", 1, "Technique"))
    ids = {tactic["id"]: "TA1", group.id: "G1", tech.id: "T1"}

    def relationship(n, source, target, description):
        return SimpleNamespace(
            id=sid("relationship", n),
            relationship_type="uses",
            description=description,
            source_ref=source,
            target_ref=target,
        )

    examples = [
        relationship(1, group.id, tech.id, "ran things"),
        relationship(2, sid("intrusion-set", 99), sid("attack-pattern", 99), "unknown ends"),
        relationship(3, None, None, None),
    ]
    fake = install(
        monkeypatch,
        [tactic, group, tech],
        ids,
        get_tactics=lambda remove_revoked_deprecated: [tactic],
        get_procedure_examples_by_tactic=lambda name: examples,
    )
    res = await server.mcp.call_tool(
        "get_procedure_examples_by_tactic", {"tactic": "execution", "include_description": True}
    )
    result = res.structured_content["result"]
    assert result["tactic"] == {"name": "Execution", "attack_id": "TA1", "stix_id": tactic["id"]}
    first, second, third = result["examples"]
    assert first["description"] == "ran things"
    assert first["group"] == {"attack_id": "G1", "name": "Group", "stix_id": group.id}
    assert first["technique"] == {"attack_id": "T1", "name": "Technique", "stix_id": tech.id}
    assert second["group"]["name"] is None and second["technique"]["stix_id"] == sid(
        "attack-pattern", 99
    )
    assert third["group"]["stix_id"] is None and third["technique"]["stix_id"] is None
    assert result["count"] == 3 and "3 procedure example(s)" in result["message"]

    # lookups of the ends failing degrade to unresolved ids
    fake.get_attack_id = boom
    res = await server.mcp.call_tool(
        "get_procedure_examples_by_tactic", {"tactic": "Execution", "include_description": False}
    )
    result = res.structured_content["result"]
    assert result["tactic"]["attack_id"] is None
    assert result["examples"][0]["group"]["attack_id"] is None
    assert result["examples"][0]["technique"]["attack_id"] is None
    assert result["examples"][0]["description"] is None

    # tactics lookup and relationship query failing
    fake.get_tactics = boom
    fake.get_procedure_examples_by_tactic = boom
    res = await server.mcp.call_tool("get_procedure_examples_by_tactic", {"tactic": "Execution"})
    result = res.structured_content["result"]
    assert result["count"] == 0 and result["tactic"]["stix_id"] is None
    assert "No procedure examples found for tactic 'Execution'" in result["message"]


async def test_subtechnique_listing_skips_unusable_techniques(monkeypatch):
    anon = {"type": "attack-pattern", "name": "No id"}
    parent = obj("attack-pattern", 1, "Parent")
    sub = obj("attack-pattern", 2, "Sub")
    broken = obj("attack-pattern", 3, "Broken lookup")

    def parent_of(stix_id):
        if stix_id == broken["id"]:
            raise RuntimeError("lookup failed")
        return [entry(parent)] if stix_id == sub["id"] else []

    install(
        monkeypatch,
        [parent, sub, broken],
        {sub["id"]: "T1.001"},
        get_techniques=lambda **kwargs: [anon, parent, broken, sub],
        get_parent_technique_of_subtechnique=parent_of,
    )
    res = await server.mcp.call_tool("get_all_subtechniques", {"domain": "enterprise"})
    result = res.structured_content["result"]
    assert [s["name"] for s in result["subtechniques"]] == ["Sub"]
    assert result["count"] == 1


async def test_parent_technique_listing_skips_unusable_techniques(monkeypatch):
    anon = {"type": "attack-pattern", "name": "No id"}
    parent = obj(
        "attack-pattern", 1, "Parent", kill_chain_phases=[{"phase_name": "initial-access"}]
    )
    unresolved = obj("attack-pattern", 2, "Unresolved id")
    raising = obj("attack-pattern", 3, "Raising id lookup")
    sub = obj("attack-pattern", 4, "Sub", x_mitre_is_subtechnique=True)
    ids = {parent["id"]: "T1", raising["id"]: "T3", sub["id"]: "T1.001"}

    def attack_id(stix_id):
        if stix_id == raising["id"]:
            raise RuntimeError("lookup failed")
        return ids.get(stix_id)

    install(
        monkeypatch,
        [parent, unresolved, raising, sub],
        {},
        get_attack_id=attack_id,
        get_techniques=lambda **kwargs: [anon, parent, unresolved, raising, sub],
    )
    res = await server.mcp.call_tool("get_all_parent_techniques", {"domain": "enterprise"})
    result = res.structured_content["result"]
    assert [(t["attack_id"], t["tactics"]) for t in result["parent_techniques"]] == [
        ("T1", ["Initial Access"])
    ]


async def test_procedure_examples_for_technique_with_unknown_group(monkeypatch):
    tech = obj("attack-pattern", 1, "Technique")
    rel = SimpleNamespace(
        id=sid("relationship", 1), description="d", source_ref=sid("intrusion-set", 5)
    )
    fake = install(
        monkeypatch,
        [tech],
        {tech["id"]: "T1"},
        get_procedure_examples_by_technique=lambda i: [rel],
    )
    fake.get_object_by_stix_id = lambda i: tech if i == tech["id"] else None
    res = await server.mcp.call_tool(
        "get_procedure_examples_by_technique", {"technique_stix_id": tech["id"]}
    )
    (example,) = res.structured_content["result"]["examples"]
    assert example["source_group_name"] is None and example["source_group_attack_id"] is None
    assert example["relationship_id"] == rel.id


async def test_alias_lookup_formats_matching_software(monkeypatch):
    sw = SimpleNamespace(**obj("malware", 1, "Soft", aliases=["Alias"], description="d"))
    install(
        monkeypatch,
        [],
        {sw.id: "S1"},
        get_software_by_alias=lambda alias: [sw],
        remove_revoked_deprecated=lambda objs: objs,
    )
    res = await server.mcp.call_tool("get_software_by_alias", {"alias": "Alias"})
    result = res.structured_content["result"]
    assert result["count"] == 1 and result["software"][0]["attack_id"] == "S1"
    assert "Name: Soft" in result["formatted"]


async def test_group_software_techniques_skip_a_failing_software(monkeypatch):
    group = obj("intrusion-set", 1, "Group")
    good, bad = obj("malware", 1, "Good"), obj("malware", 2, "Bad")
    tech = obj("attack-pattern", 1, "Technique")

    def techniques_of(sw_id):
        if sw_id == bad["id"]:
            raise RuntimeError("injected")
        return [tech]

    install(
        monkeypatch,
        [group, good, bad, tech],
        {tech["id"]: "T1"},
        # the nameless entry has no id and is ignored
        get_software_used_by_group=lambda g: [entry(good), entry(bad), entry({"type": "malware"})],
        get_techniques_used_by_software=techniques_of,
    )
    args = {"group_stix_id": group["id"], "include_campaigns": True}
    res = await server.mcp.call_tool("get_techniques_used_by_group_software", args)
    result = res.structured_content["result"]
    assert [t["attack_id"] for t in result["techniques"]] == ["T1"] and result["count"] == 1
    assert len(result["warnings"]) == 1
    assert bad["id"] in result["warnings"][0] and "RuntimeError" in result["warnings"][0]

    # every software failing: empty result, one warning each, no exception
    server.get_attack_data("enterprise").get_techniques_used_by_software = boom
    res = await server.mcp.call_tool("get_techniques_used_by_group_software", args)
    result = res.structured_content["result"]
    assert result["count"] == 0 and result["techniques"] == []
    assert len(result["warnings"]) == 2 and "No techniques found" in result["message"]


async def test_find_group_orders_ambiguous_matches_by_attack_id(monkeypatch):
    late = obj("intrusion-set", 1, "Team Late", aliases=["Team Late"])
    early = obj("intrusion-set", 2, "Team Early", aliases=["Team Early"])
    nameless = obj("intrusion-set", 3, "Team No Id", aliases=["Team No Id"])
    fake = install(
        monkeypatch, [late, early, nameless], {late["id"]: "G0020", early["id"]: "G0002"}
    )
    group, ambiguous = server._find_group(fake, [late, early, nameless], "team")
    assert group is early and ambiguous == ["G0002", "G0020"]
    # exact and single partial matches are not ambiguous
    assert server._find_group(fake, [late, early], "team early") == (early, [])
    assert server._find_group(fake, [late, early], "late") == (late, [])
    assert server._find_group(fake, [late, early], "other") == (None, [])
    # ids are capped
    many = [obj("intrusion-set", 10 + n, f"Many {n}") for n in range(15)]
    ids = {g["id"]: f"G{n:04d}" for n, g in enumerate(many)}
    install(monkeypatch, many, ids)
    group, ambiguous = server._find_group(server.get_attack_data(), many, "many")
    assert group is many[0] and ambiguous == [f"G{n:04d}" for n in range(10)]

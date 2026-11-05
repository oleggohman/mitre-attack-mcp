"""Cross-tool invariants on real data (testing plan D4).

Two tools that describe the same relation must agree. Scope: every object in mobile/ics/atlas;
enterprise is sampled (first ENTERPRISE_SAMPLE objects per role by ATT&CK ID plus the anchor IDs
G1015, M1036, S0154) to keep the module fast.
"""

import pytest
from conftest import call_tool, require_domain
from tool_args import DOMAINS, active_entities

ENTERPRISE_SAMPLE = 25
ANCHORS = {"G1015", "M1036", "S0154"}
SOFTWARE = ("malware", "tool")


def scope(domain, *types):
    ents = [e for e in active_entities(domain, *types) if e.attack_id]
    if domain != "enterprise":
        return ents
    head = ents[:ENTERPRISE_SAMPLE]
    return head + [e for e in ents[ENTERPRISE_SAMPLE:] if e.attack_id in ANCHORS]


def items(result, key):
    return result.get(key) or []


def sids(result, key):
    return {i["stix_id"] for i in items(result, key)}


def aids(result, key):
    return {i["attack_id"] for i in items(result, key)}


def layer_ids(result):
    """Technique IDs in a generated layer without the parents the layer builder added."""
    assert result["success"] is True, result["message"]
    added = set(result.get("auto_added_parents") or [])
    return {t["techniqueID"] for t in result["layer"]["techniques"]} - added


def fail_if(problems):
    assert not problems, f"{len(problems)} mismatches, first: {problems[:5]}"


async def check_inverse(domain, sources, fwd_tool, fwd_arg, fwd_key, bwd_tool, bwd_arg, bwd_key):
    """forward(source) lists targets; backward(target) must list that source, and nothing else."""
    forward, problems = {}, []
    for src in sources:
        res, _ = await call_tool(fwd_tool, {fwd_arg: src.stix_id, "domain": domain})
        forward[src.stix_id] = sids(res, fwd_key)
    targets = set().union(*forward.values()) if forward else set()
    backward = {}
    for tgt in sorted(targets):
        res, _ = await call_tool(bwd_tool, {bwd_arg: tgt, "domain": domain})
        backward[tgt] = sids(res, bwd_key)
    for src, tgts in forward.items():
        for tgt in tgts:
            if src not in backward[tgt]:
                problems.append(f"{fwd_tool}({src}) lists {tgt} but {bwd_tool}({tgt}) lacks it")
    sampled = set(forward)
    for tgt, srcs in backward.items():
        for src in srcs & sampled:
            if tgt not in forward[src]:
                problems.append(f"{bwd_tool}({tgt}) lists {src} but {fwd_tool}({src}) lacks it")
    return problems


@pytest.fixture(params=DOMAINS)
def domain(request):
    require_domain(request.param)
    return request.param


async def test_group_tools_match_group_layer(domain):
    problems = []
    for g in scope(domain, "intrusion-set"):
        for inc in (True, False):
            by_name, _ = await call_tool(
                "get_group_techniques",
                {"group_name": g.name, "domain": domain, "include_campaigns": inc},
            )
            by_id, _ = await call_tool(
                "get_techniques_used_by_group",
                {"group_stix_id": g.stix_id, "domain": domain, "include_campaigns": inc},
            )
            a, b = aids(by_name, "techniques"), aids(by_id, "techniques")
            if a != b:
                problems.append(
                    f"{g.attack_id} include_campaigns={inc}: by name {len(a)} vs by id {len(b)}"
                )
            if not a:
                continue
            layer, _ = await call_tool(
                "generate_layer",
                {"attack_id": g.attack_id, "domain": domain, "include_campaigns": inc},
            )
            c = layer_ids(layer)
            if a != c:
                problems.append(
                    f"{g.attack_id} include_campaigns={inc}: tools {len(a)} vs layer {len(c)}"
                )
    fail_if(problems)


async def test_group_software_techniques_are_union_of_software_techniques(domain):
    problems = []
    for g in scope(domain, "intrusion-set"):
        res, _ = await call_tool(
            "get_techniques_used_by_group_software",
            {"group_stix_id": g.stix_id, "domain": domain, "limit": None},
        )
        software, _ = await call_tool(
            "get_software_used_by_group", {"group_stix_id": g.stix_id, "domain": domain}
        )
        union = set()
        for s in items(software, "software"):
            used, _ = await call_tool(
                "get_techniques_used_by_software",
                {"software_stix_id": s["stix_id"], "domain": domain},
            )
            union |= aids(used, "techniques")
        if aids(res, "techniques") != union:
            problems.append(f"{g.attack_id}: {len(aids(res, 'techniques'))} vs union {len(union)}")
    fail_if(problems)


async def test_software_and_mitigation_layers_match_tools(domain):
    if domain == "atlas":
        # Not applicable: generate_layer is documented as unsupported for ATLAS.
        mitigation = scope(domain, "course-of-action")[0]
        layer, _ = await call_tool(
            "generate_layer", {"attack_id": mitigation.attack_id, "domain": domain}
        )
        assert layer["success"] is False and layer["count"] == 0
        assert 'generate_technique_layer(domain="atlas")' in layer["message"]
        return
    problems = []
    for s in scope(domain, *SOFTWARE):
        used, _ = await call_tool(
            "get_techniques_used_by_software", {"software_stix_id": s.stix_id, "domain": domain}
        )
        if not items(used, "techniques"):
            continue
        layer, _ = await call_tool("generate_layer", {"attack_id": s.attack_id, "domain": domain})
        if aids(used, "techniques") != layer_ids(layer):
            problems.append(
                f"{s.attack_id}: tool {len(aids(used, 'techniques'))} "
                f"vs layer {len(layer_ids(layer))}"
            )
    for m in scope(domain, "course-of-action"):
        mitigated, _ = await call_tool(
            "get_techniques_mitigated_by_mitigation",
            {"mitigation_stix_id": m.stix_id, "domain": domain},
        )
        if not items(mitigated, "techniques"):
            continue
        layer, _ = await call_tool("generate_layer", {"attack_id": m.attack_id, "domain": domain})
        if aids(mitigated, "techniques") != layer_ids(layer):
            problems.append(
                f"{m.attack_id}: tool {len(aids(mitigated, 'techniques'))} "
                f"vs layer {len(layer_ids(layer))}"
            )
    fail_if(problems)


async def test_subtechnique_parent_relations(domain):
    subs, _ = await call_tool("get_all_subtechniques", {"domain": domain})
    entries = items(subs, "subtechniques")
    assert entries
    if domain == "enterprise":
        entries = entries[: ENTERPRISE_SAMPLE * 4]
    problems = []
    for sub in entries:
        parent, _ = await call_tool(
            "get_parent_technique_of_subtechnique",
            {"technique_stix_id": sub["stix_id"], "domain": domain},
        )
        p = parent["parent"]
        if p["attack_id"] != sub["parent_attack_id"]:
            problems.append(
                f"{sub['attack_id']}: list says parent {sub['parent_attack_id']}, "
                f"tool {p['attack_id']}"
            )
            continue
        children, _ = await call_tool(
            "get_subtechniques_of_technique", {"technique_stix_id": p["stix_id"], "domain": domain}
        )
        if sub["stix_id"] not in sids(children, "subtechniques"):
            problems.append(f"{sub['attack_id']} missing from subtechniques of {p['attack_id']}")
    fail_if(problems)


async def test_mitigation_technique_both_directions(domain):
    problems = await check_inverse(
        domain,
        scope(domain, "course-of-action"),
        "get_techniques_mitigated_by_mitigation",
        "mitigation_stix_id",
        "techniques",
        "get_mitigations_mitigating_technique",
        "technique_stix_id",
        "mitigations",
    )
    fail_if(problems)


async def test_group_software_both_directions(domain):
    problems = await check_inverse(
        domain,
        scope(domain, "intrusion-set"),
        "get_software_used_by_group",
        "group_stix_id",
        "software",
        "get_groups_using_software",
        "software_stix_id",
        "groups",
    )
    fail_if(problems)


async def test_group_campaign_both_directions(domain):
    problems = await check_inverse(
        domain,
        scope(domain, "intrusion-set"),
        "get_campaigns_attributed_to_group",
        "group_stix_id",
        "campaigns",
        "get_groups_attributing_to_campaign",
        "campaign_stix_id",
        "groups",
    )
    fail_if(problems)


async def test_technique_datacomponent_both_directions(domain):
    problems = await check_inverse(
        domain,
        scope(domain, "x-mitre-data-component"),
        "get_techniques_detected_by_datacomponent",
        "datacomponent_stix_id",
        "techniques",
        "get_datacomponents_detecting_technique",
        "technique_stix_id",
        "datacomponents",
    )
    fail_if(problems)


async def test_group_technique_direct_entries_reverse(domain):
    """Direct group->technique entries must list the group in get_groups_using_technique."""
    problems = []
    for g in scope(domain, "intrusion-set"):
        res, _ = await call_tool(
            "get_techniques_used_by_group", {"group_stix_id": g.stix_id, "domain": domain}
        )
        direct = [t for t in items(res, "techniques") if t.get("direct") is True][:10]
        for t in direct:
            back, _ = await call_tool(
                "get_groups_using_technique", {"technique_stix_id": t["stix_id"], "domain": domain}
            )
            if g.stix_id not in sids(back, "groups"):
                problems.append(
                    f"{g.attack_id} uses {t['attack_id']} but reverse lookup lacks the group"
                )
    fail_if(problems)


ROUND_TRIP_TYPES = (
    "attack-pattern",
    "intrusion-set",
    "malware",
    "tool",
    "course-of-action",
    "campaign",
    "x-mitre-tactic",
    "x-mitre-data-component",
    "x-mitre-asset",
)


async def test_id_round_trip(domain):
    problems = []
    for type_ in ROUND_TRIP_TYPES:
        for e in scope(domain, type_):
            args = {"domain": domain}
            by_aid, _ = await call_tool(
                "get_object_by_attack_id", {**args, "attack_id": e.attack_id, "stix_type": type_}
            )
            by_sid, _ = await call_tool("get_object_by_stix_id", {**args, "stix_id": e.stix_id})
            aid, _ = await call_tool("get_attack_id", {**args, "stix_id": e.stix_id})
            name, _ = await call_tool("get_name", {**args, "stix_id": e.stix_id})
            kind, _ = await call_tool("get_stix_type", {**args, "stix_id": e.stix_id})
            got = (
                by_aid["object"]["stix_id"] if by_aid.get("found") else None,
                by_sid["object"]["name"] if by_sid.get("found") else None,
                aid.get("attack_id"),
                name.get("name"),
                kind.get("stix_type"),
            )
            want = (e.stix_id, e.name, e.attack_id, e.name, type_)
            if got != want:
                problems.append(f"{type_} {e.attack_id}: got {got}, want {want}")
    fail_if(problems)


STATS_TOOLS = {
    "techniques": ("get_all_techniques", "count"),
    "groups": ("get_all_groups", "count"),
    "software": ("get_all_software", "count"),
    "tactics": ("get_all_tactics", "count"),
    "mitigations": ("get_all_mitigations", "count"),
}


async def test_stats_match_catalogues(domain):
    stats, _ = await call_tool("get_stats", {"domain": domain})
    problems = []
    for key, value in stats["stats"].items():
        assert key in STATS_TOOLS, f"unknown stats key {key!r}: extend STATS_TOOLS"
        tool, count_key = STATS_TOOLS[key]
        res, _ = await call_tool(tool, {"domain": domain})
        if res[count_key] != value:
            problems.append(f"stats.{key}={value} but {tool}.{count_key}={res[count_key]}")
    fail_if(problems)

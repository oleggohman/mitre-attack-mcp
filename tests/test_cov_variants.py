"""Registry-driven parameter variants: every optional flag of every tool on real data.

Coverage batch for flags the default smoke call does not exercise (testing plan Task 8).
Assertions check observable output, not just that the call returns.
"""

import asyncio

import pytest
from conftest import call_tool, raw_bundle, require_domain
from tool_args import ARGS, _active, _attack_id, cell_args, nonempty, tool_domains

from mitre_mcp_server import server

_TOOLS = {t.name: t.input_schema for t in asyncio.run(server.mcp.list_tools())}


def _cells(param, with_empty=False):
    """Cells of tools that take `param` and have data (expected-empty cells are checked by the
    smoke suite against the raw bundle; `with_empty` keeps them)."""
    out = []
    for tool, schema in sorted(_TOOLS.items()):
        if param in schema.get("properties", {}):
            spec = ARGS[tool]
            for d in tool_domains(schema):
                if d in spec.known_bug or d in spec.expect_failure or d in spec.na:
                    continue
                if d in spec.expect_empty and not with_empty:
                    continue
                out.append(pytest.param(tool, d, id=f"{tool}-{d}"))
    return out


async def _call(tool, domain, **extra):
    if domain:
        require_domain(domain)
    args = cell_args(tool, domain, "default", _TOOLS[tool])
    args.update(extra)
    return await call_tool(tool, args)


def _strings_under_description(node):
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            if "description" in key and isinstance(value, str) and value.strip():
                found.append(value)
            found.extend(_strings_under_description(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_strings_under_description(value))
    return found


@pytest.mark.parametrize("tool,domain", _cells("include_description"))
async def test_include_description_true_returns_descriptions(tool, domain):
    result, _ = await _call(tool, domain, include_description=True)
    assert nonempty(result), "cell has data, so the call must return some"
    assert _strings_under_description(result), "include_description=True returned no description"
    without, _ = await _call(tool, domain, include_description=False)
    assert nonempty(without)
    assert _strings_under_description(without) == [], "include_description=False leaked text"


@pytest.mark.parametrize("tool,domain", _cells("include_relationships"))
async def test_include_relationships_returns_relationship_records(tool, domain):
    result, _ = await _call(tool, domain, include_relationships=True)
    assert nonempty(result), "cell has data, so the call must return some"

    def rels(node):
        if isinstance(node, dict):
            if isinstance(node.get("relationships"), list):
                yield from node["relationships"]
            for v in node.values():
                yield from rels(v)
        elif isinstance(node, list):
            for v in node:
                yield from rels(v)

    records = list(rels(result))
    assert records, "include_relationships=True returned no relationship records"
    assert all(r.get("relationship_type") or r.get("stix_id") for r in records)
    default, _ = await _call(tool, domain)
    assert not list(rels(default)), "relationships must be omitted by default"


# --- include_campaigns: expected sizes computed from the raw bundle --------------------------


def _raw_group_id(domain, args):
    groups = [o for o in raw_bundle(domain)["objects"] if o["type"] == "intrusion-set"]
    for key in ("group_stix_id", "group_name", "attack_id"):
        if key in args:
            for g in groups:
                if args[key] in (g["id"], g["name"], _attack_id(g)):
                    return g["id"]
    raise AssertionError(f"no raw group for {args}")


def _raw_group_sets(domain, group_id, via_software):
    """(direct, campaign_only) STIX IDs of active techniques of a group, from raw relationships.

    Direct: `uses` relationships of the group (via_software=False) or of software the group uses
    directly (True). Campaign-derived: the same through campaigns attributed to the group.
    """
    objs = raw_bundle(domain)["objects"]
    live = {o["id"]: o for o in objs if _active(o)}
    uses = [
        (o["source_ref"], o["target_ref"])
        for o in objs
        if o["type"] == "relationship" and o["relationship_type"] == "uses" and _active(o)
    ]
    campaigns = {
        o["source_ref"]
        for o in objs
        if o["type"] == "relationship"
        and o["relationship_type"] == "attributed-to"
        and o["target_ref"] == group_id
        and _active(o)
    }

    def targets(sources, types):
        return {t for s, t in uses if s in sources and t in live and live[t]["type"] in types}

    if not via_software:
        direct = targets({group_id}, {"attack-pattern"})
        return direct, targets(campaigns, {"attack-pattern"}) - direct
    software = {"malware", "tool"}
    direct_sw = targets({group_id}, software)
    direct = targets(direct_sw, {"attack-pattern"})
    all_sw = direct_sw | targets(campaigns, software)
    return direct, targets(all_sw, {"attack-pattern"}) - direct


def _stix_ids(result):
    return {t["stix_id"] for v in result.values() if isinstance(v, list) for t in v}


@pytest.mark.parametrize("tool,domain", _cells("include_campaigns"))
async def test_include_campaigns_matches_raw_campaign_derived_items(tool, domain):
    via_software = tool == "get_techniques_used_by_group_software"
    args = cell_args(tool, domain, "default", _TOOLS[tool])
    direct, only = _raw_group_sets(domain, _raw_group_id(domain, args), via_software)
    assert direct, "cell has data, so the group has techniques in the raw bundle"

    with_c, _ = await _call(tool, domain, include_campaigns=True)
    without, _ = await _call(tool, domain, include_campaigns=False)
    if tool == "generate_layer":
        # `count` is the number of techniques, parents auto-added for display are separate
        assert (with_c["count"], without["count"]) == (len(direct) + len(only), len(direct))
    else:
        assert with_c["count"] == len(direct) + len(only)
        assert without["count"] == len(direct)
        assert _stix_ids(without) == direct
        assert _stix_ids(with_c) == direct | only
    if "campaign_only_count" in with_c:
        assert with_c["campaign_only_count"] == len(only)
        assert with_c["direct_count"] == len(direct)
        assert without["campaign_only_count"] == 0
    if only:
        assert without["count"] < with_c["count"]


@pytest.mark.parametrize(
    "tool,arg",
    [
        ("get_group_techniques", "group_name"),
        ("get_techniques_used_by_group", "group_stix_id"),
        ("get_techniques_used_by_group_software", "group_stix_id"),
        ("generate_layer", "attack_id"),
    ],
)
async def test_campaign_only_techniques_exist_for_scattered_spider(tool, arg):
    """G1015 has techniques that its campaign adds (raw check), so the flag must change results."""
    require_domain("enterprise")
    group = next(
        o for o in raw_bundle("enterprise")["objects"] if _attack_id(o) == "G1015" and _active(o)
    )
    value = {"group_name": group["name"], "attack_id": "G1015"}.get(arg, group["id"])
    via_software = tool == "get_techniques_used_by_group_software"
    direct, only = _raw_group_sets("enterprise", group["id"], via_software)
    assert only, "raw data: the campaign adds techniques to the group"
    with_c, _ = await call_tool(tool, {arg: value, "include_campaigns": True})
    without, _ = await call_tool(tool, {arg: value, "include_campaigns": False})
    assert with_c["count"] == len(direct) + len(only)
    assert without["count"] == len(direct) < with_c["count"]


@pytest.mark.parametrize("tool,domain", _cells("limit"))
async def test_limit_and_offset_page_the_same_items(tool, domain):
    full, _ = await _call(tool, domain, limit=None, offset=0)
    assert nonempty(full), "cell has data, so the call must return some"
    total = full["count"]
    key = next(k for k, v in full.items() if isinstance(v, list) and v and isinstance(v[0], dict))
    page, _ = await _call(tool, domain, limit=1, offset=0)
    assert page["returned"] == 1 and page["count"] == total
    assert page["has_more"] == (total > 1)
    assert page[key][0]["stix_id"] == full[key][0]["stix_id"]
    count_only, _ = await _call(tool, domain, limit=0)
    assert count_only["returned"] == 0 and count_only["count"] == total
    assert count_only[key] == []
    beyond, _ = await _call(tool, domain, limit=5, offset=total + 10)
    assert beyond["returned"] == 0 and beyond["has_more"] is False
    if total > 1:
        second, _ = await _call(tool, domain, limit=1, offset=1)
        assert second[key][0]["stix_id"] == full[key][1]["stix_id"]


# --- remove_revoked_deprecated ---------------------------------------------------------------

# Listing tools whose result is exactly the objects of a raw type: the default count must equal
# the active objects, the wide count all of them.
_RAW_LISTING = {
    "get_all_techniques": lambda o: o["type"] == "attack-pattern",
    "get_all_subtechniques": lambda o: o["type"] == "attack-pattern"
    and o.get("x_mitre_is_subtechnique"),
    "get_all_parent_techniques": lambda o: o["type"] == "attack-pattern"
    and not o.get("x_mitre_is_subtechnique"),
    "get_all_groups": lambda o: o["type"] == "intrusion-set",
    "get_all_software": lambda o: o["type"] in ("malware", "tool"),
    "get_all_mitigations": lambda o: o["type"] == "course-of-action",
    "get_all_campaigns": lambda o: o["type"] == "campaign",
    "get_all_matrices": lambda o: o["type"] == "x-mitre-matrix",
    "get_all_datacomponents": lambda o: o["type"] == "x-mitre-data-component",
    "get_all_assets": lambda o: o["type"] == "x-mitre-asset",
    "get_all_datasources": lambda o: o["type"] == "x-mitre-data-source",
}


@pytest.mark.parametrize("tool,domain", _cells("remove_revoked_deprecated", with_empty=True))
async def test_keeping_revoked_never_shrinks_results(tool, domain):
    default, _ = await _call(tool, domain)
    wide, _ = await _call(tool, domain, remove_revoked_deprecated=False)
    if domain not in ARGS[tool].expect_empty:
        assert nonempty(default)
    assert wide["count"] >= default["count"]
    if tool in _RAW_LISTING:
        raw = raw_bundle(domain)["objects"]
        objs = [o for o in raw if _RAW_LISTING[tool](o)]
        assert default["count"] == sum(1 for o in objs if _active(o))
        # Subtechniques without a parent (revoked ones) are listed too, with null parent fields.
        assert wide["count"] == len(objs)


@pytest.mark.parametrize("domain", ["enterprise", "mobile", "ics", "atlas"])
async def test_known_revoked_object_appears_only_when_kept(domain):
    require_domain(domain)
    revoked = [
        o
        for o in raw_bundle(domain)["objects"]
        if o["type"] == "attack-pattern" and o.get("revoked") and _attack_id(o)
    ]
    args = {"stix_type": "attack-pattern", "domain": domain}
    if not revoked:
        # raw data: nothing is revoked here, so keeping revoked objects changes nothing
        default, _ = await call_tool("get_objects_by_type", args)
        wide, _ = await call_tool(
            "get_objects_by_type", {**args, "remove_revoked_deprecated": False}
        )
        assert default["count"] == wide["count"] > 0
        return
    target = sorted(revoked, key=_attack_id)[0]
    default, _ = await call_tool("get_objects_by_type", args)
    wide, _ = await call_tool("get_objects_by_type", {**args, "remove_revoked_deprecated": False})
    assert target["id"] not in _stix_ids(default)
    assert target["id"] in _stix_ids(wide)
    by_name, _ = await call_tool(
        "get_objects_by_name",
        {"name": target["name"], "stix_type": "attack-pattern", "domain": domain},
    )
    assert target["id"] not in _stix_ids(by_name)
    by_name_wide, _ = await call_tool(
        "get_objects_by_name",
        {
            "name": target["name"],
            "stix_type": "attack-pattern",
            "domain": domain,
            "remove_revoked_deprecated": False,
        },
    )
    assert target["id"] in _stix_ids(by_name_wide)


@pytest.mark.parametrize("tool,domain", _cells("limit"))
async def test_negative_pagination_is_clamped(tool, domain):
    full, _ = await _call(tool, domain, limit=None, offset=0)
    total = full["count"]
    assert total > 0
    key = next(k for k, v in full.items() if isinstance(v, list) and v and isinstance(v[0], dict))
    # negative limit behaves like 0 (count probe), negative offset like 0
    probe, _ = await _call(tool, domain, limit=-1, offset=-5)
    assert probe["offset"] == 0 and probe["limit"] == 0
    assert probe["returned"] == 0 and probe[key] == []
    assert probe["count"] == total and probe["has_more"] is True
    # negative offset with a positive limit starts at the first item
    page, _ = await _call(tool, domain, limit=2, offset=-5)
    assert page["offset"] == 0 and page["returned"] <= page["count"] == total
    assert [x["stix_id"] for x in page[key]] == [x["stix_id"] for x in full[key][:2]]


async def test_all_subtechniques_keeps_revoked_ones_without_parent_relationship():
    require_domain("enterprise")
    raw = raw_bundle("enterprise")["objects"]
    expected = sum(
        1 for o in raw if o["type"] == "attack-pattern" and o.get("x_mitre_is_subtechnique")
    )
    wide, _ = await call_tool(
        "get_all_subtechniques", {"domain": "enterprise", "remove_revoked_deprecated": False}
    )
    assert wide["count"] == expected
    with_parent = {
        r["source_ref"]
        for r in raw
        if r["type"] == "relationship" and r["relationship_type"] == "subtechnique-of"
    }
    revoked_ids = {
        o["id"]
        for o in raw
        if o["type"] == "attack-pattern"
        and o.get("x_mitre_is_subtechnique")
        and o.get("revoked")
        and o["id"] not in with_parent
    }
    orphans = {x["stix_id"]: x for x in wide["subtechniques"] if x["parent_stix_id"] is None}
    assert len(revoked_ids) == 16
    assert set(orphans) == revoked_ids
    for x in orphans.values():
        assert x["parent_attack_id"] is None and x["parent_name"] is None
        assert x["attack_id"] and x["name"]
    # default call is unchanged: no orphans, every entry has a parent
    default, _ = await call_tool("get_all_subtechniques", {"domain": "enterprise"})
    assert default["count"] == 479
    assert all(x["parent_stix_id"] for x in default["subtechniques"])

"""Tool behaviour under different shapes of library results (testing plan Task 8).

The tools accept STIX objects as stix2 objects, plain dicts or attribute-style entries, and must
degrade (not crash) when a per-item lookup fails. Each test replaces `server.get_attack_data` with
a proxy over the real data that changes only the representation or injects one failure kind, and
compares the tool output with the normal output of the same call.
"""

import asyncio
import json
from types import SimpleNamespace

import pytest
from conftest import require_domain
from mitreattack.stix20 import MitreAttackData
from stix2.base import _STIXBase
from tool_args import ARGS, cell, cell_args, tool_domains

from mitre_mcp_server import server

_TOOLS = {t.name: t.input_schema for t in asyncio.run(server.mcp.list_tools())}
CELLS = [
    (t, d)
    for t in sorted(_TOOLS)
    if t in ARGS and ARGS[t].fault_na is None and not ARGS[t].known_bug
    for d in tool_domains(_TOOLS[t])
]
# Cells with data: representation changes must not change the output.
DATA_CELLS = [(t, d) for t, d in CELLS if d not in ARGS[t].expect_empty]


def xfail_attribute_only(request, tool):
    """Strict xfail: a tool that reads attributes only breaks on plain-dict objects (library
    contract). When it becomes representation-agnostic the cell XPASSes and fails: shrink the
    set."""
    request.applymarker(
        pytest.mark.xfail(strict=True, reason=f"{tool} reads attributes only (library contract)")
    )


def IDS(cells):
    return [f"{t}-{d}" for t, d in cells]


def to_dicts(value):
    """stix2 objects -> plain dicts (recursively through lists and entries)."""
    if isinstance(value, _STIXBase):
        return {k: to_dicts(v) for k, v in value.items()}
    if isinstance(value, dict):
        return {k: to_dicts(v) for k, v in value.items()}
    if isinstance(value, list):
        return [to_dicts(v) for v in value]
    return value


def to_namespaces(value):
    """Relationship entries ({"object", "relationships"}) -> attribute-style entries."""
    if isinstance(value, list):
        return [to_namespaces(v) for v in value]
    if isinstance(value, dict) and "object" in value and "relationships" in value:
        return SimpleNamespace(object=value["object"], relationships=value["relationships"])
    return value


def to_bare(value):
    """Relationship entries -> the bare objects (no wrapper, no relationships)."""
    if isinstance(value, list):
        return [to_bare(v) for v in value]
    if isinstance(value, dict) and "object" in value and "relationships" in value:
        return value["object"]
    return value


def null_objects(nulled):
    """Transform: entries whose object is missing; removed objects' STIX IDs go to `nulled`."""

    def transform(value):
        if isinstance(value, list):
            return [transform(v) for v in value]
        if isinstance(value, dict) and "object" in value and "relationships" in value:
            if value["object"] is not None:
                nulled.add(value["object"]["id"])
            return {"object": None, "relationships": value["relationships"]}
        return value

    return transform


class Proxy:
    """Wraps the real data object; `transform` post-processes results of library calls and
    `raising` lists method names that raise instead."""

    def __init__(self, real, transform=None, raising=(), only_raising=False):
        self._real = real
        self._transform = transform or (lambda v: v)
        self._raising = set(raising)
        self._only_raising = only_raising

    def __getattr__(self, name):
        attr = getattr(self._real, name)
        if not callable(attr):
            return attr

        def call(*args, **kwargs):
            if name in self._raising or (self._only_raising and name in LIBRARY_QUERIES):
                raise RuntimeError(f"injected failure in {name}")
            return self._transform(attr(*args, **kwargs))

        return call


# Library queries that fail in `only_raising` mode: everything the library defines except the
# single-object lookups (and the methods this server overrides).
_KEEP = {
    "get_object_by_stix_id",
    "get_attack_id",
    "get_object_by_attack_id",
    "get_objects_by_name",
    "remove_revoked_deprecated",
    "get_field",
}
LIBRARY_QUERIES = {
    n
    for n, v in vars(MitreAttackData).items()
    if callable(v) and n.startswith("get_") and n not in _KEEP and n not in vars(server._MitreData)
}


async def run(tool, domain, proxy_factory, monkeypatch, unpaged=False):
    require_domain(domain)
    args = cell_args(tool, domain, "default", _TOOLS[tool])
    if unpaged and "limit" in _TOOLS[tool].get("properties", {}):
        args["limit"] = None  # compare whole result sets, not a page whose content depends on order
    real = server.get_attack_data(domain)
    monkeypatch.setattr(server, "get_attack_data", lambda d="enterprise": proxy_factory(real))
    res = await server.mcp.call_tool(tool, args)
    return res.structured_content["result"]


def canon(result):
    return json.loads(json.dumps(result, sort_keys=True, default=str))


# Tools that read attributes only. The library returns stix2 objects (not dicts) and
# RelationshipEntry TypedDicts (not attribute objects), so these tools have no branch for the
# other representation; the sets pin that and shrink when a tool becomes representation-agnostic.
ATTRIBUTE_ONLY_OBJECTS = {
    "get_assets_targeted_by_technique",
    "get_campaigns_by_alias",
    "get_procedure_examples_by_technique",
    "get_revoked_techniques",
    "get_subtechniques_of_technique",
    "get_techniques_mitigated_by_mitigation",
}
DICT_ONLY_ENTRIES = {
    "generate_layer",
    "get_all_subtechniques",
    "get_assets_targeted_by_technique",
    "get_campaigns_attributed_to_group",
    "get_campaigns_using_software",
    "get_campaigns_using_technique",
    "get_groups_attributing_to_campaign",
    "get_groups_using_software",
    "get_groups_using_technique",
    "get_parent_technique_of_subtechnique",
    "get_software_used_by_campaign",
    "get_software_using_technique",
    "get_subtechniques_of_technique",
    "get_techniques_mitigated_by_mitigation",
    "get_techniques_targeting_asset",
    "get_techniques_used_by_campaign",
    "get_techniques_used_by_group_software",
    "get_techniques_used_by_software",
}
BARE_UNSUPPORTED = {
    "get_group_techniques",
    "get_software_used_by_group",
    "get_techniques_used_by_group",
}
MODES = [
    ("dicts", to_dicts, ATTRIBUTE_ONLY_OBJECTS),
    ("namespaces", to_namespaces, DICT_ONLY_ENTRIES),
    ("bare", to_bare, BARE_UNSUPPORTED),
]


@pytest.mark.parametrize("mode,transform,skip", MODES, ids=[m[0] for m in MODES])
@pytest.mark.parametrize("tool,domain", DATA_CELLS, ids=IDS(DATA_CELLS))
async def test_output_does_not_depend_on_object_representation(
    tool, domain, mode, transform, skip, monkeypatch, request
):
    if tool in skip and domain not in ARGS[tool].expect_failure:
        # Strict: when the tool learns to handle this representation the cell XPASSes and fails,
        # which tells us to shrink the set. (Documented failure cells never reach the branch.)
        request.applymarker(
            pytest.mark.xfail(strict=True, reason=f"{tool} has no {mode} branch (library contract)")
        )
    expected = (await cell(tool, domain)).result
    got = await run(tool, domain, lambda real: Proxy(real, transform), monkeypatch)
    # `formatted` is rendered text and may differ in key order only; compare structured data.
    assert canon({k: v for k, v in got.items() if k != "formatted"}) == canon(
        {k: v for k, v in expected.items() if k != "formatted"}
    )


ID_IS_THE_OUTPUT = {"generate_layer", "get_attack_id", "get_all_parent_techniques"}
ID_CELLS = [(t, d) for t, d in DATA_CELLS if t not in ID_IS_THE_OUTPUT]


def item_lists(result):
    """{key: list} of every list of objects (also empty ones) in a result."""
    return {
        k: v
        for k, v in result.items()
        if isinstance(v, list) and all(isinstance(x, dict) for x in v) and k != "warnings"
    }


def assert_no_data(got):
    """The response reports 'nothing found': count 0 (or found False) and every item list empty."""
    assert isinstance(got.get("message") or got.get("formatted"), str)
    if "count" in got:
        assert got["count"] == 0
    elif "found" in got:
        assert got["found"] is False
    elif "stats" in got:
        # failed computation reports null values, an empty library zeros
        assert set(got["stats"].values()) in ({0}, {None})
    else:
        assert got["parent"] is None
    for key, items in item_lists(got).items():
        assert items == [], key


# Tools that read through single-object lookups, `_MitreData` overrides or the object store, not
# through the library relationship/listing queries that the injection breaks. With failing or
# empty library queries they must return exactly their normal output.
UNAFFECTED_BY_FAILING_QUERIES = {
    "generate_technique_layer",
    "get_attack_id",
    "get_datacomponents_detecting_technique",
    "get_detection_strategies_for_technique",
    "get_object_by_attack_id",
    "get_object_by_stix_id",
    "get_objects_by_name",
    "get_objects_by_type",
    "get_technique_by_id",
    "get_technique_tactics",
    "get_techniques_detected_by_datacomponent",
}
# Non-list results (names, types, strings) are not changed by "every list is empty".
UNAFFECTED_BY_EMPTY_RESULTS = {
    "generate_technique_layer",
    "get_attack_id",
    "get_name",
    "get_object_by_attack_id",
    "get_object_by_stix_id",
    "get_stix_type",
    "get_tactics_by_matrix",
    "get_technique_by_id",
    "get_technique_tactics",
}


def ident(item):
    return item.get("stix_id") or item.get("id")


def idents(items):
    return sorted(ident(i) for i in items if ident(i))


@pytest.mark.parametrize("tool,domain", ID_CELLS, ids=IDS(ID_CELLS))
async def test_failing_attack_id_lookup_degrades_to_null_ids(tool, domain, monkeypatch):
    expected = await run(tool, domain, Proxy, monkeypatch, unpaged=True)
    got = await run(
        tool, domain, lambda real: Proxy(real, raising=["get_attack_id"]), monkeypatch, unpaged=True
    )
    assert got.get("count") == expected.get("count")
    assert got.get("found") == expected.get("found")
    assert isinstance(got.get("message") or got.get("formatted"), str)
    for key, items in item_lists(got).items():
        # the same items (their order may change: items are sorted by ATT&CK ID) ...
        assert idents(items) == idents(expected[key]), key
        # ... none of which can show an ATT&CK ID any more
        for item in items:
            if "attack_id" in item:
                assert item["attack_id"] is None, item
    with_ids = [
        i for items in item_lists(expected).values() for i in items if i.get("attack_id")
    ]
    assert with_ids or not any("attack_id" in i for v in item_lists(got).values() for i in v)


# The library never returns an entry without an object. These tools do not skip such an entry:
# they list it with null fields and count it (no crash). Pinned here; a tool that starts skipping
# must be removed from the set (the test then fails for the other branch).
KEEPS_NULL_OBJECT_ENTRIES = {
    "get_assets_targeted_by_technique",
    "get_campaigns_attributed_to_group",
    "get_subtechniques_of_technique",
    "get_techniques_mitigated_by_mitigation",
    "get_techniques_targeting_asset",
}
# Items derived from the removed entries' objects (software): with all of it gone, nothing is left.
DERIVED_FROM_ENTRIES = {"get_techniques_used_by_group_software"}


@pytest.mark.parametrize("tool,domain", DATA_CELLS, ids=IDS(DATA_CELLS))
async def test_entries_without_objects_are_skipped(tool, domain, monkeypatch):
    expected = await run(tool, domain, Proxy, monkeypatch, unpaged=True)
    nulled = set()
    got = await run(
        tool, domain, lambda real: Proxy(real, null_objects(nulled)), monkeypatch, unpaged=True
    )
    assert isinstance(got.get("message") or got.get("formatted"), str)
    lists = item_lists(got)
    for key, items in lists.items():
        kept = [i for i in expected[key] if ident(i) not in nulled]
        if tool in DERIVED_FROM_ENTRIES:
            assert nulled and items == [] and got["count"] == 0
        elif tool in KEEPS_NULL_OBJECT_ENTRIES and len(kept) < len(expected[key]):
            # listed with null fields and counted
            assert len(items) == len(expected[key])
            assert all(i.get("stix_id") is None and i.get("name") is None for i in items)
        else:
            # exactly the normal items minus those whose object was removed
            assert idents(items) == idents(kept), key
            assert len(items) == len(kept), key
            if "count" in got and len(lists) == 1:
                assert got["count"] == len(kept)
    if tool in KEEPS_NULL_OBJECT_ENTRIES:
        assert nulled, "the tool is in KEEPS_NULL_OBJECT_ENTRIES but no entry was removed"


@pytest.mark.parametrize("tool,domain", DATA_CELLS, ids=IDS(DATA_CELLS))
async def test_failing_relationship_queries_give_empty_results(tool, domain, monkeypatch):
    expected = (await cell(tool, domain)).result
    got = await run(
        tool, domain, lambda real: Proxy(real, raising=(), only_raising=True), monkeypatch
    )
    if tool in UNAFFECTED_BY_FAILING_QUERIES or domain in ARGS[tool].expect_failure:
        assert canon(got) == canon(expected)
    else:
        assert_no_data(got)


@pytest.mark.parametrize("tool,domain", DATA_CELLS, ids=IDS(DATA_CELLS))
async def test_empty_library_results_give_empty_responses(tool, domain, monkeypatch):
    def empty(value):
        return [] if isinstance(value, list) else value

    expected = (await cell(tool, domain)).result
    got = await run(tool, domain, lambda real: Proxy(real, empty), monkeypatch)
    if tool in UNAFFECTED_BY_EMPTY_RESULTS or domain in ARGS[tool].expect_failure:
        assert canon(got) == canon(expected)
    else:
        assert_no_data(got)


# Detection tools resolve components through ids stored in analytic references, and the
# created/modified listings index objects by their (mandatory STIX) `id`.
ID_FROM_REFERENCES = {
    "get_datacomponents_detecting_technique",
    "get_techniques_detected_by_datacomponent",
    "get_objects_created_after",
    "get_objects_modified_after",
}


def _walk_objects(value, fn):
    """Apply fn to every plain-dict STIX object (a dict with a "type" and an "id")."""
    if isinstance(value, list):
        return [_walk_objects(v, fn) for v in value]
    if isinstance(value, dict):
        value = {k: _walk_objects(v, fn) for k, v in value.items()}
        if "type" in value and "id" in value and value["type"] != "relationship":
            value = fn(value)
    return value


def without_ids(value):
    return _walk_objects(to_dicts(value), lambda o: {k: v for k, v in o.items() if k != "id"})


def without_phase_names(value):
    def strip(o):
        if "kill_chain_phases" in o:
            o = {
                **o,
                "kill_chain_phases": [
                    {k: v for k, v in p.items() if k != "phase_name"}
                    for p in o["kill_chain_phases"]
                ],
            }
        return o

    return _walk_objects(to_dicts(value), strip)


def _item_lists(result):
    return [v for v in result.values() if isinstance(v, list) and v and isinstance(v[0], dict)]


# Of the attribute-only tools, only this one breaks when the objects are plain dicts with the
# phase names removed (the others handle both; measured, see the strict xfail below).
PHASE_NAMES_ATTRIBUTE_ONLY = {"get_revoked_techniques"}

# Not applicable: the ID is the tool's output, or the objects are found through ids stored in
# references, so stripping `id` from the objects cannot be observed in the same way.
NO_ID_NOT_APPLICABLE = ID_IS_THE_OUTPUT | ID_FROM_REFERENCES
NO_ID_CELLS = [(t, d) for t, d in DATA_CELLS if t not in NO_ID_NOT_APPLICABLE]


@pytest.mark.parametrize("tool,domain", NO_ID_CELLS, ids=IDS(NO_ID_CELLS))
async def test_objects_without_ids_never_get_attack_ids(tool, domain, monkeypatch):
    got = await run(tool, domain, lambda real: Proxy(real, without_ids), monkeypatch)
    assert isinstance(got.get("message") or got.get("formatted"), str)
    for items in _item_lists(got):
        for item in items:
            assert item.get("attack_id") is None and item.get("stix_id") is None, item


@pytest.mark.parametrize("tool,domain", DATA_CELLS, ids=IDS(DATA_CELLS))
async def test_techniques_without_phase_names_have_no_tactics(tool, domain, monkeypatch, request):
    if tool in PHASE_NAMES_ATTRIBUTE_ONLY:
        xfail_attribute_only(request, tool)
    expected = (await cell(tool, domain)).result
    got = await run(tool, domain, lambda real: Proxy(real, without_phase_names), monkeypatch)
    assert got.get("count") == expected.get("count")
    for items in _item_lists(got):
        for item in items:
            if "tactics" in item:
                assert item["tactics"] == []

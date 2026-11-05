"""Registry-driven smoke suite: every tool x every applicable domain (testing plan D1-D3).

Each (tool, domain, variant) cell is called at most once per session (tool_args result cache);
the tests below only read the cache so a failure names the violated property.
"""

import asyncio
import json

import pytest
from conftest import raw_bundle, require_domain
from tool_args import (
    ARGS,
    CALL_COUNTS,
    DEFAULT_WIRE_BUDGET,
    DOMAINS,
    NULLABLE,
    SIZE_OVERRIDES,
    MissingRole,
    cell,
    cell_args,
    nonempty,
    tool_domains,
)

from mitre_mcp_server import server

_TOOLS = {t.name: t.input_schema for t in asyncio.run(server.mcp.list_tools())}
CELLS = [(t, d) for t in sorted(_TOOLS) if t in ARGS for d in tool_domains(_TOOLS[t])]
DOMAIN_TOOLS = [
    t for t in sorted(_TOOLS) if t in ARGS and "domain" in _TOOLS[t].get("properties", {})
]
DESC_CELLS = [(t, d) for t, d in CELLS if "include_description" in _TOOLS[t].get("properties", {})]
NEG_CELLS = [
    (t, d)
    for t, d in CELLS
    if ARGS[t].neg
    and d not in ARGS[t].expect_empty
    and d not in ARGS[t].expect_failure
    and d not in ARGS[t].known_bug
]


def _id(val):
    return val if isinstance(val, str) else str(val)


def cells(param_list):
    return pytest.mark.parametrize(
        "tool,domain", param_list, ids=[f"{t}-{d}" for t, d in param_list]
    )


async def _ready(tool, domain, variant="default"):
    if domain:
        require_domain(domain)
    return await cell(tool, domain, variant)


# ---------------------------------------------------------------------------
# Result helpers
# ---------------------------------------------------------------------------

ENTITY_PREFIXES = (
    "attack-pattern",
    "intrusion-set",
    "malware",
    "tool",
    "course-of-action",
    "campaign",
    "x-mitre-tactic",
    "x-mitre-matrix",
    "x-mitre-data-component",
    "x-mitre-asset",
    "x-mitre-detection-strategy",
    "x-mitre-analytic",
)


def _is_stix_id(value) -> bool:
    return isinstance(value, str) and "--" in value and value.split("--")[0] in ENTITY_PREFIXES


def null_problems(node, path="$"):
    out = []
    if isinstance(node, dict):
        stix = (
            node.get("stix_id")
            if _is_stix_id(node.get("stix_id"))
            else (node.get("id") if _is_stix_id(node.get("id")) else None)
        )
        if stix is not None:
            if node.get("name") is None:
                out.append(f"{path}: entity {stix} has null name")
            if "attack_id" in node:
                if node["attack_id"] is None:
                    out.append(f"{path}: entity {stix} has null attack_id")
            elif "id" in node and not _is_stix_id(node["id"]) and node["id"] is None:
                out.append(f"{path}: entity {stix} has null id")
        for key in ("parent_stix_id", "parent_attack_id", "parent_name"):
            if key in node and node[key] is None and key not in NULLABLE:
                out.append(f"{path}: {key} is null")
        for key, value in node.items():
            out.extend(null_problems(value, f"{path}.{key}"))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            out.extend(null_problems(value, f"{path}[{i}]"))
    return out


def description_problems(node, path="$", in_rel=False):
    out = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "relationships":
                continue
            if "description" in key and isinstance(value, str) and value.strip():
                out.append(f"{path}.{key}")
            out.extend(description_problems(value, f"{path}.{key}"))
    elif isinstance(node, list):
        for i, value in enumerate(node):
            out.extend(description_problems(value, f"{path}[{i}]"))
    return out


def _bug_mark(tool, domain):
    reason = ARGS[tool].known_bug.get(domain)
    return pytest.mark.xfail(strict=True, reason=reason) if reason else ()


def marked(param_list, test_fn_name=None):
    """Parametrisation with xfail(strict) for known_bug cells."""
    return [pytest.param(t, d, id=f"{t}-{d}", marks=_bug_mark(t, d)) for t, d in param_list]


# ---------------------------------------------------------------------------
# Registry and infrastructure guards
# ---------------------------------------------------------------------------


async def test_registry_matches_table():
    registered = {t.name for t in await server.mcp.list_tools()}
    assert registered == set(ARGS), (
        f"missing from ARGS: {sorted(registered - set(ARGS))}; "
        f"stale in ARGS: {sorted(set(ARGS) - registered)}"
    )


async def test_every_tool_has_output_schema():
    missing = [t.name for t in await server.mcp.list_tools() if t.output_schema is None]
    assert missing == []


@pytest.mark.parametrize("domain", DOMAINS)
def test_builders_get_samples_for_applicable_cells(domain):
    """A builder must never receive a missing role: the table says NA / expect_empty instead."""
    require_domain(domain)
    for tool, dom in CELLS:
        if dom != domain:
            continue
        try:
            cell_args(tool, dom, "default", _TOOLS[tool])
        except MissingRole as exc:
            pytest.fail(f"{tool}/{domain}: {exc} (add expect_empty with a RawCheck or NA)")


async def test_cells_are_called_once():
    for tool, domain in CELLS[:6]:
        await _ready(tool, domain)
        await _ready(tool, domain)
    assert CALL_COUNTS and max(CALL_COUNTS.values()) == 1


def test_expect_empty_has_rawcheck_and_reason():
    for tool, spec in ARGS.items():
        for domain, check in spec.expect_empty.items():
            assert callable(check) and check.description, (tool, domain)
        for domain, reason in {**spec.known_bug, **spec.na}.items():
            assert reason, (tool, domain)
        for field in ("fault_raises", "fault_na", "no_message"):
            value = getattr(spec, field)
            assert value is None or value.strip(), (tool, field)


# ---------------------------------------------------------------------------
# D3 assertions
# ---------------------------------------------------------------------------


@cells(CELLS)
async def test_no_exception(tool, domain):  # D3 #1
    c = await _ready(tool, domain)
    assert c.exc is None, repr(c.exc)
    assert c.is_error is False


@cells(CELLS)
async def test_shape(tool, domain):  # D3 #2
    c = await _ready(tool, domain)
    assert c.exc is None, repr(c.exc)
    r = c.result
    assert isinstance(r, dict)
    spec = ARGS[tool]
    if not spec.no_message:
        text = r.get("message") or r.get("formatted")
        assert isinstance(text, str) and text.strip(), "no message / formatted"
    expect_data = (
        domain not in spec.expect_empty
        and domain not in spec.expect_failure
        and domain not in spec.known_bug
    )
    if expect_data:
        for key in ("found", "success"):
            if key in r:
                assert r[key] is True, f"{key} is {r[key]!r}: {r.get('message')}"


@cells(CELLS)
async def test_no_null_key_fields(tool, domain):  # D3 #3
    c = await _ready(tool, domain)
    assert c.exc is None, repr(c.exc)
    if not nonempty(c.result):
        return  # nothing to check; empty/not-found responses may echo an unknown (ghost) object
    problems = null_problems(c.result)
    assert not problems, problems[:5]


@pytest.mark.parametrize("tool,domain", marked(CELLS))
async def test_non_empty_where_data_exists(tool, domain):  # D3 #4
    c = await _ready(tool, domain)
    assert c.exc is None, repr(c.exc)
    spec = ARGS[tool]
    if domain in spec.expect_failure:
        assert c.result.get("success") is False
        assert spec.expect_failure[domain] in c.result["message"]
        return
    if domain in spec.expect_empty:
        check = spec.expect_empty[domain]
        assert not nonempty(c.result), f"expected empty but got data: {c.result.get('message')}"
        assert check(raw_bundle(domain)), f"RawCheck failed: {check.description}"
        return
    assert nonempty(c.result), f"empty result: {c.result.get('message')}"


def _items(r):
    return [
        v for v in r.values() if isinstance(v, list) and v and all(isinstance(x, dict) for x in v)
    ]


@cells(CELLS)
async def test_count_semantics(tool, domain):  # D3 #5
    c = await _ready(tool, domain)
    assert c.exc is None, repr(c.exc)
    r = c.result
    lists = [v for v in r.values() if isinstance(v, list)]
    if "total" in r:
        assert r.get("count") == r["total"], (r.get("count"), r["total"])
        assert any(r["returned"] == len(v) for v in lists), (r["returned"], [len(v) for v in lists])
        offset = r.get("offset", 0)
        assert r["has_more"] == (offset + r["returned"] < r["total"])
    elif isinstance(r.get("count"), int) and not isinstance(r.get("count"), bool):
        # Only entity lists (list of dicts) are items; layer tools count techniques inside `layer`.
        dict_lists = [v for v in lists if v and all(isinstance(x, dict) for x in v)]
        if dict_lists:
            assert any(r["count"] == len(v) for v in dict_lists), (
                r["count"],
                [len(v) for v in dict_lists],
            )
        elif r["count"] == 0:
            assert all(not v for v in lists)


@cells(CELLS)
async def test_wire_size(tool, domain):  # D3 #6
    c = await _ready(tool, domain)
    assert c.exc is None, repr(c.exc)
    budget = SIZE_OVERRIDES[tool][0] if tool in SIZE_OVERRIDES else DEFAULT_WIRE_BUDGET
    assert c.wire_bytes <= budget, f"{c.wire_bytes} bytes > {budget}"
    assert c.wire_bytes <= 1_000_000


@cells(DESC_CELLS)
async def test_description_flag(tool, domain):  # D3 #7
    c = await _ready(tool, domain, "no_description")
    assert c.exc is None, repr(c.exc)
    assert not description_problems(c.result), description_problems(c.result)[:5]
    assert "Description:" not in str(c.result.get("formatted", ""))


@cells(NEG_CELLS)
async def test_negative_input(tool, domain):  # D3 #8
    c = await _ready(tool, domain, "negative")
    assert c.exc is None, repr(c.exc)
    r = c.result
    assert not nonempty(r), f"unknown ID returned data: {r.get('message')}"
    text = r.get("message") or r.get("formatted")
    assert isinstance(text, str) and text.strip()


@pytest.mark.parametrize("tool", DOMAIN_TOOLS)
async def test_invalid_domain_raises_value_error(tool):  # D3 #9
    c = await cell(tool, "enterprise", "bogus_domain")
    if ARGS[tool].bogus_response:
        assert c.exc is None, repr(c.exc)
        assert c.result["success"] is False and "Invalid domain" in c.result["message"]
        return
    assert c.exc is not None, "invalid domain did not raise"
    assert type(c.exc).__name__ == "UnexpectedToolError", repr(c.exc)
    assert isinstance(c.exc.__cause__, ValueError)
    assert "bogus" in str(c.exc.__cause__)


@cells(CELLS)
async def test_structured_matches_text(tool, domain):  # D3 #11
    c = await _ready(tool, domain)
    assert c.exc is None, repr(c.exc)
    assert c.structured is not None
    assert c.structured["result"] == json.loads(c.text)

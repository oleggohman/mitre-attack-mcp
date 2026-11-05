"""Layer tools: validation, failure and file-system branches (testing plan Task 8g)."""

import json
from datetime import datetime, timezone

import pytest
from stubs import boom, entry, install, obj, sid

from mitre_mcp_server import server

pytestmark = pytest.mark.unit


async def tool(name, **args):
    res = await server.mcp.call_tool(name, args)
    return res.structured_content["result"]


@pytest.mark.parametrize(
    "bad,fragment",
    [
        ({"default_score": float("inf")}, "`default_score` must be a finite number"),
        ({"techniques": [{"technique_id": "T1059", "bogus": 1}]}, "unsupported key(s): ['bogus']"),
        (
            {"techniques": [{"technique_id": "T1059", "comment": "x" * 2001}]},
            "`comment` must be text up to 2000",
        ),
        ({"techniques": [{"technique_id": "T1059", "comment": 5}]}, "`comment` must be text"),
        ({"techniques": ["  "]}, "Item 0: missing technique ID"),
        ({"techniques": [{"score": 3}]}, "Item 0: missing technique ID"),
    ],
)
async def test_generate_technique_layer_rejects_bad_items(bad, fragment):
    args = {"techniques": ["T1059"], "domain": "enterprise", **bad}
    result = await tool("generate_technique_layer", **args)
    assert result["success"] is False and result["layer"] is None
    assert fragment in result["message"]


async def test_generate_technique_layer_rejects_non_string_non_object_items():
    # Bypasses the MCP argument validation, which would reject the item earlier.
    result = await server.generate_technique_layer(techniques=[5], domain="enterprise")
    assert (
        result["success"] is False and "Item 0: must be a string or an object" in result["message"]
    )


async def test_generate_technique_layer_reports_unavailable_domain(monkeypatch):
    monkeypatch.setattr(server, "get_attack_data", boom)
    result = await tool("generate_technique_layer", techniques=["T1059"], domain="ics")
    assert result["success"] is False
    assert result["message"].startswith("Domain 'ics' is not available:")


async def test_generate_technique_layer_skips_revoked_and_deprecated(monkeypatch):
    live = obj("attack-pattern", 1)
    revoked = obj("attack-pattern", 2, revoked=True)
    deprecated = obj("attack-pattern", 3, x_mitre_deprecated=True)
    by_attack = {"T1": live, "T2": revoked, "T3": deprecated}
    install(
        monkeypatch,
        [live, revoked, deprecated],
        {live["id"]: "T1"},
        get_object_by_attack_id=lambda tid, t: by_attack.get(tid),
    )
    result = await tool(
        "generate_technique_layer", techniques=["t1", "T2", "T2", "T3", "T9"], domain="mobile"
    )
    assert result["success"] is True
    assert result["technique_ids"] == ["T1"]
    assert result["skipped"] == ["T2", "T3"]  # listed once even when repeated
    assert result["unknown_ids"] == ["T9"]
    assert "Unknown IDs: T9" in result["message"]


async def test_generate_technique_layer_without_valid_items_names_the_reasons(monkeypatch):
    revoked = obj("attack-pattern", 2, revoked=True)
    install(
        monkeypatch,
        [revoked],
        {},
        get_object_by_attack_id=lambda tid, t: revoked if tid == "T2" else boom(),
    )
    result = await tool("generate_technique_layer", techniques=["T2", "T9"], domain="mobile")
    assert result["success"] is False
    assert result["message"] == "No valid techniques to put in the layer."
    assert result["skipped"] == ["T2"] and result["unknown_ids"] == ["T9"]


@pytest.fixture
def layer_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "LAYER_DIR", tmp_path / "layers")
    return tmp_path / "layers"


class FrozenDatetime:
    @staticmethod
    def now(tz=None):
        return datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def test_save_layer_writes_private_file_and_never_overwrites(layer_dir, monkeypatch):
    monkeypatch.setattr(server, "datetime", FrozenDatetime)
    first, err = server._save_layer({"a": 1}, "My layer/../x")
    assert err is None and first.name == "My-layer-..-x-20260102T030405Z.json"
    assert json.loads(first.read_text()) == {"a": 1}
    assert first.stat().st_mode & 0o777 == 0o600
    second, _ = server._save_layer({"a": 2}, "My layer/../x")
    assert second.name == "My-layer-..-x-20260102T030405Z-1.json"
    assert json.loads(first.read_text()) == {"a": 1}


def test_save_layer_refuses_paths_that_resolve_outside_the_directory(layer_dir, monkeypatch):
    monkeypatch.setattr(server, "datetime", FrozenDatetime)
    layer_dir.mkdir(parents=True)
    outside = layer_dir.parent / "outside.json"
    (layer_dir / "layer-20260102T030405Z.json").symlink_to(outside)
    path, err = server._save_layer({"a": 1}, "")
    assert path is None and err == "Refusing to write outside the layer directory."
    assert not outside.exists()


def test_save_layer_gives_up_after_1000_collisions(layer_dir, monkeypatch):
    def always_exists(*args, **kwargs):
        raise FileExistsError

    monkeypatch.setattr(server, "open", always_exists, raising=False)
    path, err = server._save_layer({}, "x")
    assert path is None and err == "Could not find a free layer filename."


def test_save_layer_reports_os_errors(tmp_path, monkeypatch):
    blocker = tmp_path / "file"
    blocker.write_text("")
    monkeypatch.setattr(server, "LAYER_DIR", blocker / "layers")
    path, err = server._save_layer({}, "x")
    assert path is None and err.startswith("Could not write layer file:")


GROUP = obj("intrusion-set", 1, "Group")
SOFT = obj("tool", 1, "Tool")
TECH_A = obj("attack-pattern", 1, "A", description="desc A")
TECH_B = obj("attack-pattern", 2, "B", revoked=True)
TECH_C = obj("attack-pattern", 3, "C", x_mitre_deprecated=True)
TECH_D = obj("attack-pattern", 4, "D")
IDS = {GROUP["id"]: "G0001", SOFT["id"]: "S0001", TECH_A["id"]: "T1", TECH_D["id"]: "T4"}


def layer_data(monkeypatch, **methods):
    lookups = {("G0001", "intrusion-set"): GROUP, ("S0001", "tool"): SOFT}
    methods.setdefault("get_object_by_attack_id", lambda aid, t: lookups.get((aid, t)))
    return install(monkeypatch, [GROUP, SOFT, TECH_A, TECH_B, TECH_C, TECH_D], IDS, **methods)


@pytest.mark.parametrize(
    "attack_id,fragment",
    [
        ("X123", "Invalid ATT&CK ID format: 'X123'"),
        ("g9999", "'G9999' not found in domain 'enterprise'"),
    ],
)
async def test_generate_layer_rejects_bad_ids(monkeypatch, attack_id, fragment):
    layer_data(monkeypatch)
    result = await tool("generate_layer", attack_id=attack_id)
    assert result["success"] is False and fragment in result["message"]


async def test_generate_layer_reports_unavailable_domain(monkeypatch):
    monkeypatch.setattr(server, "get_attack_data", boom)
    result = await tool("generate_layer", attack_id="G0016")
    assert result["message"].startswith("Domain 'enterprise' is not available:")


async def test_generate_layer_software_falls_back_to_tool_and_skips_unusable_entries(monkeypatch):
    layer_data(
        monkeypatch,
        get_object_by_attack_id=lambda aid, t: SOFT if (aid, t) == ("S0001", "tool") else None,
        get_techniques_used_by_software=lambda s: [
            entry(TECH_A),
            entry(TECH_A),
            entry(TECH_B),
            entry(TECH_C),
            entry(None),
            entry(obj("attack-pattern", 9, "Unmapped")),
        ],
    )
    result = await tool("generate_layer", attack_id="s0001", include_comments=True)
    assert result["success"] is True and result["count"] == 1
    (technique,) = result["layer"]["techniques"]
    assert technique["techniqueID"] == "T1" and technique["comment"] == "desc A"


async def test_generate_layer_group_without_campaign_provenance_has_no_comment(monkeypatch):
    unknown_source = {
        "relationship_type": "uses",
        "source_ref": sid("malware", 7),
        "target_ref": TECH_D["id"],
    }
    layer_data(
        monkeypatch,
        get_techniques_used_by_group=lambda g: [entry(TECH_D, unknown_source)],
    )
    result = await tool("generate_layer", attack_id="G0001")
    assert result["count"] == 1
    assert "comment" not in result["layer"]["techniques"][0]
    result = await tool("generate_layer", attack_id="G0001", include_campaigns=False)
    assert result["success"] is False and "No techniques found for 'G0001'" in result["message"]


async def test_generate_layer_data_component_uses_detection_chain(monkeypatch):
    dc = obj("x-mitre-data-component", 1, "DC")
    install(
        monkeypatch,
        [dc, TECH_A, TECH_B],
        {TECH_A["id"]: "T1"},
        get_object_by_attack_id=lambda aid, t: dc,
        techniques_for_datacomponent=lambda s: [(TECH_A, ["d"], ["a"]), (TECH_B, [], [])],
    )
    result = await tool("generate_layer", attack_id="DC0001", score=5)
    assert result["count"] == 1 and result["layer"]["techniques"][0]["score"] == 5


async def test_generate_layer_wraps_unexpected_errors(monkeypatch):
    layer_data(monkeypatch, get_techniques_used_by_group=boom)
    result = await tool("generate_layer", attack_id="G0001")
    assert result["success"] is False and "Failed to generate layer: injected" in result["message"]

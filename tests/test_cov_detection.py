"""Pre-v18 detection paths and data-source resolution, with stub data (testing plan Task 8f).

ATT&CK v18+ data has no `detects` relationships, no data-source references and no
`x_mitre_data_sources`, so these paths are exercised with plain-dict stubs.
"""

import pytest
from stubs import boom, entry, install, obj, sid

from mitre_mcp_server import server

pytestmark = pytest.mark.unit

TECH = obj("attack-pattern", 1, "Process Injection")
DS = obj("x-mitre-data-source", 1, "Process")
DC1 = obj(
    "x-mitre-data-component",
    1,
    "Process Creation",
    x_mitre_data_source_ref=DS["id"],
    description="creates a process",
)
DC2 = obj("x-mitre-data-component", 2, "Process Access")
IDS = {TECH["id"]: "T9001", DS["id"]: "DS9001", DC1["id"]: "DC9001", DC2["id"]: "DC9002"}


async def call(tool, **args):
    res = await server.mcp.call_tool(tool, args)
    return res.structured_content["result"]


def rel(n=1, text="rel text"):
    return {
        "id": sid("relationship", n),
        "relationship_type": "detects",
        "description": text,
        "source_ref": DC1["id"],
        "target_ref": TECH["id"],
    }


async def test_legacy_detects_relationships(monkeypatch):
    install(
        monkeypatch,
        [TECH, DS, DC1, DC2],
        IDS,
        get_datacomponents_detecting_technique=lambda i: [entry(DC1, rel()), "junk", entry(DC2)],
    )
    r = await call(
        "get_datacomponents_detecting_technique",
        technique_stix_id=TECH["id"],
        include_description=True,
    )
    assert r["debug"]["query_mode"] == "relationship_detects"
    assert r["technique"]["attack_id"] == "T9001"
    assert r["count"] == 2
    first, second = r["datacomponents"]
    assert (first["attack_id"], first["name"]) == ("DC9001", "Process Creation")
    assert first["description"] == "creates a process"
    assert (first["data_source_name"], first["data_source_attack_id"]) == ("Process", "DS9001")
    assert first["relationships"] == [
        {
            "stix_id": sid("relationship", 1),
            "relationship_type": "detects",
            "description": "rel text",
            "source_ref": DC1["id"],
            "target_ref": TECH["id"],
        }
    ]
    assert second["data_source_stix_id"] is None and second["relationships"] == []
    assert "Process Creation (Process)" in r["formatted"]


async def test_legacy_relationships_survive_failing_data_source_lookups(monkeypatch):
    fake = install(
        monkeypatch,
        [TECH, DS, DC1],
        IDS,
        get_datacomponents_detecting_technique=lambda i: [entry(DC1)],
    )
    real_lookup = fake.get_object_by_stix_id
    fake.get_object_by_stix_id = lambda i: boom() if i == DS["id"] else real_lookup(i)
    r = await call("get_datacomponents_detecting_technique", technique_stix_id=TECH["id"])
    dc = r["datacomponents"][0]
    assert dc["data_source_stix_id"] == DS["id"] and dc["data_source_name"] is None

    fake.get_object_by_stix_id = real_lookup
    fake.get_attack_id = lambda i: boom() if i == DS["id"] else IDS.get(i)
    r = await call("get_datacomponents_detecting_technique", technique_stix_id=TECH["id"])
    dc = r["datacomponents"][0]
    assert dc["data_source_name"] == "Process" and dc["data_source_attack_id"] is None
    assert dc["description"] is None  # include_description defaults to False


def chain_link(analytics):
    return {"detection_strategy": obj("x-mitre-detection-strategy", 1), "analytics": analytics}


async def test_detection_strategy_chain_merges_and_filters_components(monkeypatch):
    revoked = obj("x-mitre-data-component", 3, "Old", revoked=True)
    det = obj("x-mitre-detection-strategy", 1)
    an1 = obj(
        "x-mitre-analytic",
        1,
        x_mitre_log_source_references=[
            {"x_mitre_data_component_ref": DC1["id"], "name": "Sysmon", "channel": "1"},
            {"x_mitre_data_component_ref": DC1["id"], "name": "Sysmon", "channel": "1"},
            {"name": "no component ref"},
            {"x_mitre_data_component_ref": revoked["id"], "name": "x", "channel": "y"},
            {"x_mitre_data_component_ref": sid("x-mitre-data-component", 99), "name": "gone"},
        ],
    )
    an2 = obj(
        "x-mitre-analytic",
        2,
        x_mitre_log_source_references=[
            {"x_mitre_data_component_ref": DC1["id"], "name": "Auditd", "channel": "2"}
        ],
    )
    ids = {**IDS, det["id"]: "DET9001", an1["id"]: "AN9001", an2["id"]: "AN9002"}
    install(
        monkeypatch,
        [TECH, DS, DC1, revoked],
        ids,
        get_datacomponents_detecting_technique=lambda i: [],
        detection_chain_for_technique=lambda i: [
            {"detection_strategy": det, "analytics": [an1, an2]}
        ],
    )
    r = await call("get_datacomponents_detecting_technique", technique_stix_id=TECH["id"])
    assert r["debug"]["query_mode"] == "detection_strategy_analytics"
    assert r["count"] == 1
    dc = r["datacomponents"][0]
    assert dc["detection_strategies"] == ["DET9001"] and dc["analytics"] == ["AN9001", "AN9002"]
    assert dc["log_sources"] == [
        {"name": "Sysmon", "channel": "1"},
        {"name": "Auditd", "channel": "2"},
    ]
    assert dc["data_source_name"] == "Process" and dc["data_source_attack_id"] == "DS9001"


async def test_chain_data_source_lookup_failure_leaves_name_empty(monkeypatch):
    det = obj("x-mitre-detection-strategy", 1)
    an = obj(
        "x-mitre-analytic",
        1,
        x_mitre_log_source_references=[
            {"x_mitre_data_component_ref": DC1["id"], "name": "n", "channel": "c"}
        ],
    )
    fake = install(
        monkeypatch,
        [TECH, DC1],
        IDS,  # DS is not registered, so its lookup raises
        get_datacomponents_detecting_technique=boom,
        detection_chain_for_technique=lambda i: [{"detection_strategy": det, "analytics": [an]}],
    )
    assert fake.get_object_by_stix_id(DC1["id"])
    r = await call("get_datacomponents_detecting_technique", technique_stix_id=TECH["id"])
    dc = r["datacomponents"][0]
    assert dc["data_source_stix_id"] == DS["id"] and dc["data_source_name"] is None


DS_PROCESS = obj("x-mitre-data-source", 1, "Process")
DS_FILE = obj("x-mitre-data-source", 2, "File")
DC_CREATE = obj(
    "x-mitre-data-component",
    1,
    "Process Creation",
    x_mitre_data_source_ref=DS_PROCESS["id"],
    description="d1",
)
DC_ACCESS = obj(
    "x-mitre-data-component", 2, "Process Access", x_mitre_data_source_ref=DS_PROCESS["id"]
)
DC_ORPHAN = obj("x-mitre-data-component", 3, "Orphan")  # no data source: never indexed
FALLBACK_IDS = {DS_PROCESS["id"]: "DS1", DC_CREATE["id"]: "DC1", DC_ACCESS["id"]: "DC2"}


def fallback_tech(sources):
    return obj("attack-pattern", 5, "Legacy technique", x_mitre_data_sources=sources)


def install_fallback(monkeypatch, tech, **overrides):
    methods = dict(
        get_datacomponents_detecting_technique=lambda i: [],
        detection_chain_for_technique=lambda i: [],
        get_datasources=lambda remove_revoked_deprecated: [DS_PROCESS, DS_FILE],
        get_datacomponents=lambda remove_revoked_deprecated: [DC_CREATE, DC_ACCESS, DC_ORPHAN],
    )
    methods.update(overrides)
    return install(
        monkeypatch, [tech, DS_PROCESS, DS_FILE, DC_CREATE, DC_ACCESS], FALLBACK_IDS, **methods
    )


async def test_fallback_resolves_x_mitre_data_sources(monkeypatch):
    tech = fallback_tech(
        [
            "Process: Process Creation",  # filters to the named component
            "Process: No Such Component",  # nothing matches -> all components of the source
            "Process",  # bare source name -> all components
            "Nonexistent: x",  # unknown data source -> skipped
            "File",  # source without components
            "   ",
            42,  # blank / non-string entries ignored
            "Process:",  # empty component name behaves like a bare name
        ]
    )
    install_fallback(monkeypatch, tech)
    r = await call(
        "get_datacomponents_detecting_technique",
        technique_stix_id=tech["id"],
        include_description=True,
    )
    assert r["debug"]["query_mode"] == "fallback_x_mitre_data_sources"
    assert [d["name"] for d in r["datacomponents"]] == ["Process Creation", "Process Access"]
    first = r["datacomponents"][0]
    assert first["description"] == "d1" and first["attack_id"] == "DC1"
    assert (first["data_source_name"], first["data_source_attack_id"]) == ("Process", "DS1")
    assert first["relationships"] == []


async def test_fallback_filter_only_the_named_component(monkeypatch):
    tech = fallback_tech(["Process: process creation"])
    install_fallback(monkeypatch, tech)
    r = await call("get_datacomponents_detecting_technique", technique_stix_id=tech["id"])
    assert [d["name"] for d in r["datacomponents"]] == ["Process Creation"]


async def test_fallback_tolerates_failing_library_calls(monkeypatch):
    tech = fallback_tech(["Process"])
    fake = install_fallback(monkeypatch, tech, get_datasources=boom, get_datacomponents=boom)
    r = await call("get_datacomponents_detecting_technique", technique_stix_id=tech["id"])
    assert r["count"] == 0 and "No data components found" in r["message"]

    fake.get_datasources = lambda remove_revoked_deprecated: [DS_PROCESS]
    fake.get_datacomponents = lambda remove_revoked_deprecated: [DC_CREATE]
    fake.get_attack_id = lambda i: boom()
    r = await call("get_datacomponents_detecting_technique", technique_stix_id=tech["id"])
    assert r["count"] == 1 and r["datacomponents"][0]["data_source_attack_id"] is None


async def test_fallback_without_sources_or_datasource_names(monkeypatch):
    tech = obj("attack-pattern", 6, "No sources")
    install_fallback(
        monkeypatch,
        tech,
        get_datasources=lambda remove_revoked_deprecated: [{"id": "x"}, DS_PROCESS],
    )
    r = await call("get_datacomponents_detecting_technique", technique_stix_id=tech["id"])
    assert r["count"] == 0 and r["formatted"] == ""


async def test_fallback_deduplicates_components(monkeypatch):
    tech = fallback_tech(["Process", "Process: Process Creation"])
    install_fallback(monkeypatch, tech)
    r = await call("get_datacomponents_detecting_technique", technique_stix_id=tech["id"])
    assert [d["name"] for d in r["datacomponents"]] == ["Process Creation", "Process Access"]


async def test_unknown_technique_has_no_info(monkeypatch):
    install(monkeypatch, [], {}, get_datacomponents_detecting_technique=boom)
    r = await call(
        "get_datacomponents_detecting_technique", technique_stix_id=sid("attack-pattern", 7)
    )
    assert r["technique"] is None and r["count"] == 0


async def test_technique_without_stix_id_gets_no_attack_id(monkeypatch):
    nameless = {"name": "No id", "type": "attack-pattern"}
    fake = install(
        monkeypatch,
        [],
        {},
        get_datacomponents_detecting_technique=lambda i: [],
        detection_chain_for_technique=lambda i: [],
        get_datasources=lambda **k: [],
        get_datacomponents=lambda **k: [],
    )
    fake.get_object_by_stix_id = lambda i: nameless
    r = await call(
        "get_datacomponents_detecting_technique", technique_stix_id=sid("attack-pattern", 8)
    )
    assert r["technique"]["attack_id"] is None and r["technique"]["name"] == "No id"


async def test_get_techniques_detected_by_datacomponent_resolves_parent_data_source(monkeypatch):
    tech = obj("attack-pattern", 1, "T")
    fake = install(
        monkeypatch,
        [tech, DS, DC1],
        IDS,
        get_techniques_detected_by_datacomponent=lambda i: [entry(tech)],
    )
    r = await call("get_techniques_detected_by_datacomponent", datacomponent_stix_id=DC1["id"])
    dc = r["datacomponent"]
    assert (dc["data_source_name"], dc["data_source_attack_id"]) == ("Process", "DS9001")
    assert r["count"] == 1

    # data source lookup fails -> no name; attack-id lookup fails -> no attack id
    real = fake.get_object_by_stix_id
    fake.get_object_by_stix_id = lambda i: boom() if i == DS["id"] else real(i)
    r = await call("get_techniques_detected_by_datacomponent", datacomponent_stix_id=DC1["id"])
    assert r["datacomponent"]["data_source_name"] is None
    fake.get_object_by_stix_id = real
    fake.get_attack_id = lambda i: boom() if i == DS["id"] else IDS.get(i)
    r = await call("get_techniques_detected_by_datacomponent", datacomponent_stix_id=DC1["id"])
    assert r["datacomponent"]["data_source_attack_id"] is None
    assert r["datacomponent"]["data_source_name"] == "Process"


async def test_get_all_datacomponents_resolves_parent_data_sources(monkeypatch):
    dc_hyphen = {
        "id": sid("x-mitre-data-component", 9),
        "type": "x-mitre-data-component",
        "name": "Hyphen",
        "x-mitre-data-source-ref": DS["id"],
    }
    fake = install(
        monkeypatch,
        [DS, DC1, DC2, dc_hyphen],
        IDS,
        get_datacomponents=lambda remove_revoked_deprecated: [DC1, DC2, dc_hyphen],
    )
    r = await call("get_all_datacomponents", domain="enterprise")
    by_name = {d["name"]: d for d in r["datacomponents"]}
    assert by_name["Process Creation"]["data_source_name"] == "Process"
    assert by_name["Process Creation"]["data_source_attack_id"] == "DS9001"
    assert by_name["Hyphen"]["data_source_stix_id"] == DS["id"]
    assert by_name["Process Access"]["data_source_stix_id"] is None

    real = fake.get_object_by_stix_id
    fake.get_object_by_stix_id = lambda i: boom() if i == DS["id"] else real(i)
    r = await call("get_all_datacomponents", domain="enterprise")
    assert all(d["data_source_name"] is None for d in r["datacomponents"])
    fake.get_object_by_stix_id = real
    fake.get_attack_id = boom
    r = await call("get_all_datacomponents", domain="enterprise")
    assert all(d["data_source_attack_id"] is None for d in r["datacomponents"])


async def test_get_all_datasources_accepts_plain_dicts(monkeypatch):
    ds = obj("x-mitre-data-source", 1, "Process", description="d", x_mitre_platforms=["Windows"])
    ds_hyphen = obj("x-mitre-data-source", 2, "Files", **{"x-mitre-platforms": ["Linux"]})
    install(
        monkeypatch,
        [ds, ds_hyphen],
        get_datasources=lambda remove_revoked_deprecated: [ds, ds_hyphen],
    )
    r = await call("get_all_datasources", domain="enterprise", include_description=True)
    assert [(d["name"], d["description"], d["platforms"]) for d in r["datasources"]] == [
        ("Process", "d", ["Windows"]),
        ("Files", None, ["Linux"]),
    ]


async def test_legacy_item_without_object_and_namespace_data_sources(monkeypatch):
    from types import SimpleNamespace

    ds_ns = SimpleNamespace(name="Process", id=DS["id"])
    fake = install(
        monkeypatch,
        [TECH, DS, DC1],
        IDS,
        get_datacomponents_detecting_technique=lambda i: [entry(None), entry(DC1)],
        get_techniques_detected_by_datacomponent=lambda i: [entry(TECH)],
        get_datacomponents=lambda remove_revoked_deprecated: [DC1],
    )
    real = fake.get_object_by_stix_id
    fake.get_object_by_stix_id = lambda i: ds_ns if i == DS["id"] else real(i)
    r = await call("get_datacomponents_detecting_technique", technique_stix_id=TECH["id"])
    assert [d["name"] for d in r["datacomponents"]] == [None, "Process Creation"]
    assert r["datacomponents"][1]["data_source_name"] == "Process"
    r = await call("get_techniques_detected_by_datacomponent", datacomponent_stix_id=DC1["id"])
    assert r["datacomponent"]["data_source_name"] == "Process"
    assert r["datacomponent"]["data_source_attack_id"] == "DS9001"
    r = await call("get_all_datacomponents", domain="enterprise")
    assert r["datacomponents"][0]["data_source_name"] == "Process"


async def test_failing_detection_chain_falls_back_to_data_sources(monkeypatch):
    tech = fallback_tech(["Process"])
    install_fallback(monkeypatch, tech, detection_chain_for_technique=boom)
    r = await call("get_datacomponents_detecting_technique", technique_stix_id=tech["id"])
    assert r["debug"]["query_mode"] == "fallback_x_mitre_data_sources"
    assert r["count"] == 2


async def test_fallback_components_without_ids_are_all_kept(monkeypatch):
    tech = fallback_tech(["Process"])
    anon_a = {
        "type": "x-mitre-data-component",
        "name": "Anon A",
        "x_mitre_data_source_ref": DS_PROCESS["id"],
    }
    anon_b = {**anon_a, "name": "Anon B"}
    ds_no_id = {"type": "x-mitre-data-source", "name": "Process"}
    install_fallback(
        monkeypatch,
        tech,
        get_datasources=lambda remove_revoked_deprecated: [ds_no_id],
        get_datacomponents=lambda remove_revoked_deprecated: [anon_a, anon_b],
    )
    r = await call("get_datacomponents_detecting_technique", technique_stix_id=tech["id"])
    # The data source has no id, so no component can be linked to it.
    assert r["count"] == 0
    install_fallback(
        monkeypatch,
        tech,
        get_datacomponents=lambda remove_revoked_deprecated: [
            {**anon_a, "x_mitre_data_source_ref": None},
            DC_CREATE,
        ],
    )
    r = await call("get_datacomponents_detecting_technique", technique_stix_id=tech["id"])
    assert [d["name"] for d in r["datacomponents"]] == ["Process Creation", "Process Access"][:1]


async def test_detection_strategies_tool_keeps_log_sources_without_component(monkeypatch):
    det = obj("x-mitre-detection-strategy", 1, "DET")
    an = obj(
        "x-mitre-analytic",
        1,
        "AN",
        x_mitre_platforms=["Windows"],
        x_mitre_log_source_references=[
            {"name": "Sysmon", "channel": "1"},
            {"x_mitre_data_component_ref": DC1["id"], "name": "Sysmon", "channel": "2"},
        ],
    )
    install(
        monkeypatch,
        [TECH, DC1, det, an],
        {**IDS, det["id"]: "DET1", an["id"]: "AN1"},
        detection_chain_for_technique=lambda i: [{"detection_strategy": det, "analytics": [an]}],
    )
    r = await call("get_detection_strategies_for_technique", technique_id=TECH["id"])
    sources = r["detection_strategies"][0]["analytics"][0]["log_sources"]
    assert [s["data_component_stix_id"] for s in sources] == [None, DC1["id"]]
    assert (
        sources[0]["data_component_name"] is None and sources[0]["data_component_attack_id"] is None
    )
    assert sources[1]["data_component_name"] == "Process Creation"


async def test_fallback_keeps_components_that_have_no_id(monkeypatch):
    tech = fallback_tech(["Process"])
    anon_a = {
        "type": "x-mitre-data-component",
        "name": "Anon A",
        "x_mitre_data_source_ref": DS_PROCESS["id"],
    }
    anon_b = {**anon_a, "name": "Anon B"}
    install_fallback(
        monkeypatch, tech, get_datacomponents=lambda remove_revoked_deprecated: [anon_a, anon_b]
    )
    r = await call("get_datacomponents_detecting_technique", technique_stix_id=tech["id"])
    assert [d["name"] for d in r["datacomponents"]] == ["Anon A", "Anon B"]
    assert all(d["stix_id"] is None for d in r["datacomponents"])

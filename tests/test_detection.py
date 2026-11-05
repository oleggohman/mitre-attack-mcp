"""Detection strategy chain: technique -> DET -> analytic -> data component."""

import pytest
from conftest import needs_atlas
from mitre_mcp_server import server


async def _stix(attack_id, domain="enterprise", typ="attack-pattern"):
    res = await server.get_object_by_attack_id(attack_id, typ, domain=domain)
    assert res["found"] is True
    return res["object"]["stix_id"]


async def test_strategies_for_technique():
    res = await server.get_detection_strategies_for_technique("T1552.005")
    assert res["count"] == 1
    det = res["detection_strategies"][0]
    assert det["attack_id"] == "DET0001"
    assert len(det["analytics"]) == 1
    an = det["analytics"][0]
    assert an["attack_id"] == "AN0001"
    assert an["platforms"] == ["IaaS"]
    assert {ls["data_component_attack_id"] for ls in an["log_sources"]} == {
        "DC0082",
        "DC0070",
        "DC0085",
    }
    assert "description" not in an and "mutable_elements" not in an
    assert "description" not in res["technique"]


async def test_strategies_with_description():
    res = await server.get_detection_strategies_for_technique(
        "T1552.005", include_description=True
    )
    an = res["detection_strategies"][0]["analytics"][0]
    assert "mutable_elements" in an and "description" in an
    assert res["technique"]["description"]


async def test_strategies_platform_filter():
    res = await server.get_detection_strategies_for_technique("T1552.005", platform="Windows")
    assert sum(len(d["analytics"]) for d in res["detection_strategies"]) == 0
    res = await server.get_detection_strategies_for_technique("T1552.005", platform="iaas")
    assert res["count"] == 1


async def test_strategies_attack_id_equals_stix_id():
    by_attack = await server.get_detection_strategies_for_technique("T1552.005")
    by_stix = await server.get_detection_strategies_for_technique(await _stix("T1552.005"))
    assert by_attack == by_stix
    lower = await server.get_detection_strategies_for_technique("t1552.005")
    assert lower == by_attack


async def test_strategies_unknown_technique():
    res = await server.get_detection_strategies_for_technique("T9999")
    assert res["count"] == 0 and res["technique"] is None


async def test_datacomponents_detecting_technique_chain():
    res = server.get_datacomponents_detecting_technique(await _stix("T1552.005"))
    assert res["count"] == 3
    assert {d["attack_id"] for d in res["datacomponents"]} == {"DC0082", "DC0070", "DC0085"}
    for d in res["datacomponents"]:
        assert d["detection_strategies"] == ["DET0001"]
        assert d["analytics"] == ["AN0001"]
        assert d["log_sources"]
        assert d["description"] is None
    assert res["debug"]["query_mode"] == "detection_strategy_analytics"


def test_datacomponents_detecting_technique_attack_id_input():
    res = server.get_datacomponents_detecting_technique("T1552.005")
    assert res["count"] == 3
    assert res["technique"]["attack_id"] == "T1552.005"


async def test_techniques_detected_by_datacomponent_chain():
    res = await server.get_techniques_detected_by_datacomponent("DC0070")
    assert res["count"] > 0
    entry = next(t for t in res["techniques"] if t["attack_id"] == "T1552.005")
    assert "DET0001" in entry["detection_strategies"]
    assert "AN0001" in entry["analytics"]
    data = server.get_attack_data("enterprise")
    for t in res["techniques"]:
        obj = data.get_object_by_stix_id(t["stix_id"])
        assert not obj.get("revoked") and not obj.get("x_mitre_deprecated")
    by_stix = await server.get_techniques_detected_by_datacomponent(
        res["datacomponent"]["stix_id"]
    )
    assert by_stix["count"] == res["count"]


@pytest.mark.parametrize("domain", ["mobile", "ics"])
async def test_other_domains_have_strategies(domain):
    try:
        data = server.get_attack_data(domain)
    except FileNotFoundError:
        pytest.skip(f"{domain} cache missing")
    dets = data.get_detectionstrategies(remove_revoked_deprecated=True)
    assert dets
    for det in dets:
        entries = data.get_techniques_detected_by_detection_strategy(det["id"])
        if entries:
            tech = entries[0]["object"]
            aid = data.get_attack_id(tech["id"])
            res = await server.get_detection_strategies_for_technique(aid, domain=domain)
            assert res["count"] >= 1
            return
    pytest.skip("no technique with a detection strategy")


@needs_atlas
async def test_atlas_has_no_strategies():
    res = await server.get_detection_strategies_for_technique("AML.T0051", domain="atlas")
    assert res["count"] == 0
    res = await server.get_techniques_detected_by_datacomponent("DC0070", domain="atlas")
    assert res["count"] == 0

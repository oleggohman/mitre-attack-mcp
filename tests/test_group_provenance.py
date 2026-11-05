"""Group technique provenance: direct vs inherited through campaigns."""

import pytest

from mitre_mcp_server import server


@pytest.fixture(scope="module")
def g1015_stix():
    data = server.get_attack_data("enterprise")
    return data.get_object_by_attack_id("G1015", "intrusion-set")["id"]


async def test_default_includes_campaigns(g1015_stix):
    res = await server.get_group_techniques("Scattered Spider")
    assert res["count"] == 78
    assert res["direct_count"] == 64
    assert res["campaign_only_count"] == 14
    techs = res["techniques"]
    only = [t for t in techs if not t["direct"]]
    assert len(only) == 14
    assert all(t["via_campaigns"] == ["C0027"] for t in only)
    both = [t for t in techs if t["direct"] and t["via_campaigns"]]
    assert len(both) == 14
    assert "14 only via campaigns (C0027)" in res["message"]


async def test_exclude_campaigns(g1015_stix):
    res = await server.get_group_techniques("Scattered Spider", include_campaigns=False)
    assert res["count"] == 64
    assert res["direct_count"] == 64 and res["campaign_only_count"] == 0
    assert all(t["direct"] for t in res["techniques"])


@pytest.mark.parametrize("include_campaigns", [True, False])
async def test_both_tools_agree(g1015_stix, include_campaigns):
    by_name = await server.get_group_techniques(
        "Scattered Spider", include_campaigns=include_campaigns
    )
    by_id = await server.get_techniques_used_by_group(
        g1015_stix, include_campaigns=include_campaigns
    )
    assert by_name["count"] == by_id["count"]
    assert {t["attack_id"] for t in by_name["techniques"]} == {
        t["attack_id"] for t in by_id["techniques"]
    }
    assert by_id["direct_count"] == by_name["direct_count"]

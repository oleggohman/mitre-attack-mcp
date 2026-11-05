"""get_techniques_used_by_group_software must unwrap plain technique objects (B6)."""

from mitre_mcp_server import server


async def test_group_software_g1015():
    grp = await server.get_object_by_attack_id("G1015", "intrusion-set")
    gid = grp["object"]["stix_id"]
    data = server.get_attack_data("enterprise")
    raw = data.get_techniques_used_by_group_software(gid)
    expected = {t["id"] for t in data.remove_revoked_deprecated(raw)}
    assert expected

    res = await server.get_techniques_used_by_group_software(gid)
    assert res["count"] == len(expected)
    assert {t["stix_id"] for t in res["techniques"]} == expected
    ids = {t["attack_id"] for t in res["techniques"]}
    assert "T1003.001" in ids
    for t in res["techniques"]:
        assert t["attack_id"] and t["name"] and t["stix_id"]
        assert "relationships" not in t

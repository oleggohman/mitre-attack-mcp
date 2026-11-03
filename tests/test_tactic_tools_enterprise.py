"""Enterprise checks for tactic/matrix tools (dict-safety and D10 fix)."""

from mitre_mcp_server import server


async def test_tactics_by_matrix_enterprise():
    mats = await server.get_all_matrices(domain="enterprise")
    mid = mats["matrices"][0]["stix_id"]
    res = await server.get_tactics_by_matrix(mid, domain="enterprise")
    assert res["count"] > 0
    assert all(t["name"] and t["stix_id"] for t in res["tactics"])


async def test_tactics_by_technique_enterprise():
    obj = await server.get_object_by_attack_id("T1059", "attack-pattern")
    res = await server.get_tactics_by_technique(obj["object"]["stix_id"])
    assert res["count"] > 0
    assert all(t["name"] and t["stix_id"] for t in res["tactics"])

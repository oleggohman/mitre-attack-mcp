"""Output size control: relationships opt-in, pagination, stable ordering."""

import json


async def _gt(**kw):
    from mitre_mcp_server import server

    return await server.get_group_techniques("Scattered Spider", **kw)


async def test_default_is_small():
    res = await _gt()
    assert len(json.dumps(res)) < 30_000
    assert res["count"] == res["total"] == 78
    assert all("relationships" not in t for t in res["techniques"])


async def test_include_relationships():
    res = await _gt(include_relationships=True)
    assert all(t["relationships"] for t in res["techniques"])


async def test_pagination_tail():
    res = await _gt(limit=10, offset=70)
    assert res["returned"] == 8
    assert res["has_more"] is False
    assert res["count"] == 78
    assert res["formatted"].count("STIX ID:") == 8


async def test_pages_disjoint_and_stable():
    p1 = await _gt(limit=10, offset=0)
    p2 = await _gt(limit=10, offset=10)
    again = await _gt(limit=10, offset=0)
    ids1 = [t["attack_id"] for t in p1["techniques"]]
    ids2 = [t["attack_id"] for t in p2["techniques"]]
    assert not set(ids1) & set(ids2)
    assert ids1 == [t["attack_id"] for t in again["techniques"]]
    assert p1["has_more"] is True


async def test_unpaginated_sorted_by_attack_id():
    res = await _gt()
    ids = [t["attack_id"] for t in res["techniques"]]
    assert ids == sorted(ids)
    assert res["limit"] is None


async def test_other_tools_relationships_opt_in():
    from mitre_mcp_server import server

    s = await server.get_object_by_attack_id("S0154", "malware")
    res = await server.get_techniques_used_by_software(s["object"]["stix_id"])
    assert res["count"] == res["total"] and res["count"] > 0
    assert all("relationships" not in t for t in res["techniques"])
    res2 = await server.get_techniques_used_by_software(
        s["object"]["stix_id"], include_relationships=True, limit=5
    )
    assert res2["returned"] == 5 and res2["has_more"] is True
    assert all(t["relationships"] for t in res2["techniques"])


# --- catalogue tools (Task 9) ---------------------------------------------------


async def test_all_techniques_paging():
    from mitre_mcp_server import server

    full = await server.get_all_techniques()
    page = await server.get_all_techniques(limit=5)
    assert page["returned"] == 5 and page["has_more"] is True
    assert page["count"] == page["total"] == full["count"]
    assert page["formatted"].count("STIX ID:") == 5
    ids = [t["attack_id"] for t in full["techniques"]]
    assert ids == sorted(ids)


async def test_modified_after_default_limit():
    from mitre_mcp_server import server

    res = await server.get_objects_modified_after("2025-06-01T00:00:00Z")
    assert res["returned"] <= 100
    assert len(json.dumps(res)) < 300_000
    full = await server.get_objects_modified_after("2025-06-01T00:00:00Z", limit=None)
    assert full["count"] == res["count"] and full["returned"] == full["count"]
    assert full["count"] > 100


async def test_objects_by_type_relationship_pages():
    from mitre_mcp_server import server

    p1 = await server.get_objects_by_type("relationship", limit=50, offset=0)
    p2 = await server.get_objects_by_type("relationship", limit=50, offset=50)
    assert p1["returned"] == p2["returned"] == 50
    assert not {o["stix_id"] for o in p1["objects"]} & {o["stix_id"] for o in p2["objects"]}


async def test_created_after_unlimited_no_error():
    from mitre_mcp_server import server

    res = await server.get_objects_created_after("2025-01-01T00:00:00Z", limit=None)
    assert res["count"] > 0


async def test_description_default_is_off_for_lists():
    from mitre_mcp_server import server

    res = await server.search_techniques("powershell")
    assert all(not t.get("description") for t in res["techniques"])

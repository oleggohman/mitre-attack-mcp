"""include_description=False must leave no object description anywhere in the result."""

import pytest
from mitre_mcp_server import server


def _collect(node, path=""):
    """Collect non-empty '*description*' strings anywhere, including relationship records."""
    found = []
    if isinstance(node, dict):
        for k, v in node.items():
            p = f"{path}.{k}"
            if "description" in k and isinstance(v, str) and v.strip():
                found.append(p)
            else:
                found.extend(_collect(v, p))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            found.extend(_collect(v, f"{path}[{i}]"))
    return found


async def _stix(attack_id, typ="attack-pattern"):
    res = await server.get_object_by_attack_id(attack_id, typ)
    return res["object"]["stix_id"]


async def _call(name):
    if name == "technique_by_id":
        return await server.get_technique_by_id("T1059", include_description=False)
    if name == "object_by_attack_id":
        return await server.get_object_by_attack_id(
            "T1059", "attack-pattern", include_description=False
        )
    if name == "object_by_stix_id":
        return await server.get_object_by_stix_id(
            await _stix("T1059"), include_description=False
        )
    if name == "datacomponents_detecting":
        return server.get_datacomponents_detecting_technique(
            await _stix("T1552.005"), include_description=False
        )
    if name == "group_techniques":
        return await server.get_group_techniques("Scattered Spider", include_description=False)
    if name == "mitigations_mitigating":
        return await server.get_mitigations_mitigating_technique(
            await _stix("T1059"), include_description=False
        )
    if name == "subtechniques":
        return await server.get_subtechniques_of_technique(
            await _stix("T1059"), include_description=False
        )
    if name == "group_techniques_rels":
        return await server.get_group_techniques(
            "Scattered Spider", include_description=False, include_relationships=True
        )
    raise AssertionError(name)


@pytest.mark.parametrize(
    "name",
    [
        "technique_by_id",
        "object_by_attack_id",
        "object_by_stix_id",
        "datacomponents_detecting",
        "group_techniques",
        "mitigations_mitigating",
        "subtechniques",
        "group_techniques_rels",
    ],
)
async def test_no_description_leak(name):
    res = await _call(name)
    assert _collect(res) == []
    assert "Description:" not in (res.get("formatted") or "")


async def test_technique_by_id_with_description():
    res = await server.get_technique_by_id("T1059", include_description=True)
    assert res["technique"]["description"]


async def test_relationship_description_follows_flag():
    off = await server.get_group_techniques(
        "Scattered Spider", include_description=False, include_relationships=True
    )
    on = await server.get_group_techniques(
        "Scattered Spider", include_description=True, include_relationships=True
    )
    rels_off = [r for t in off["techniques"] for r in t["relationships"]]
    rels_on = [r for t in on["techniques"] for r in t["relationships"]]
    assert rels_off and rels_on
    assert all(r["description"] is None for r in rels_off)
    assert any(r["description"] for r in rels_on)

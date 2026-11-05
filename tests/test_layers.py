"""Navigator layer builder and generate_technique_layer."""

import copy
import json
import re

import pytest
from conftest import needs_atlas, require_domain
from mitreattack import release_info
from mitreattack.navlayers import Layer
from mitreattack.navlayers.core.layerobj import _LayerObj

from mitre_mcp_server import server


def _assert_valid_attack_layer(layer, capsys):
    """Validate with navlayers (strict). Layer().layer never returns None (it prints and returns
    a string on failure), so check the type and that nothing was printed to stdout."""
    capsys.readouterr()
    obj = Layer(init_data=layer, strict=True).layer
    assert isinstance(obj, _LayerObj)
    assert capsys.readouterr().out == ""


def _entry(layer, tid):
    return next(t for t in layer["techniques"] if t["techniqueID"] == tid)


async def test_happy_path(capsys):
    res = await server.generate_technique_layer(
        [
            "t1059",
            {"technique_id": "T1003.001", "score": 5, "color": "#ff0000", "comment": "x"},
            "T9999",
        ]
    )
    assert res["success"] is True
    assert res["count"] == 2
    assert res["technique_ids"] == ["T1059", "T1003.001"]
    assert res["unknown_ids"] == ["T9999"]
    assert res["auto_added_parents"] == ["T1003"]
    layer = res["layer"]
    parent = _entry(layer, "T1003")
    assert parent["showSubtechniques"] is True
    assert set(parent) == {"techniqueID", "showSubtechniques"}
    assert not any("tactic" in t for t in layer["techniques"])
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    assert _entry(layer, "T1003.001")["comment"] == "x"
    _assert_valid_attack_layer(layer, capsys)


async def test_listed_parent_with_sub(capsys):
    res = await server.generate_technique_layer(["T1059", "T1059.001"])
    assert res["count"] == 2
    assert res["auto_added_parents"] == []
    assert _entry(res["layer"], "T1059")["showSubtechniques"] is True
    _assert_valid_attack_layer(res["layer"], capsys)


async def test_invalid_inputs():
    res = await server.generate_technique_layer([{"technique_id": "T1059", "color": "red"}])
    assert res["success"] is False and "Item 0" in res["message"]
    res = await server.generate_technique_layer(["T1059", {"technique_id": "T1003", "score": True}])
    assert res["success"] is False and "Item 1" in res["message"]
    res = await server.generate_technique_layer([])
    assert res["success"] is False
    res = await server.generate_technique_layer(["T1059"], domain="nope")
    assert res["success"] is False


@needs_atlas
async def test_atlas_layer_acceptance(capsys):
    res = await server.generate_technique_layer(
        ["aml.t0051.000", "AML.T0000", "AML.T0051"], domain="atlas"
    )
    assert res["success"] is True
    layer = res["layer"]
    # (a) ATLAS domain and versions
    assert layer["domain"] == "atlas-atlas"
    assert layer["versions"] == {"layer": "4.3", "navigator": "4.6.4"}
    assert "attack" not in layer["versions"]
    # (b) structure validated by navlayers as an ATT&CK layer (AML. prefix stripped because the
    # navlayers Technique setter rejects IDs not starting with "T")
    probe = copy.deepcopy(layer)
    probe["domain"] = "enterprise-attack"
    probe["versions"] = {"layer": "4.5", "navigator": "5.1.0"}
    for t in probe["techniques"]:
        t["techniqueID"] = t["techniqueID"].removeprefix("AML.")
    _assert_valid_attack_layer(probe, capsys)
    # (c) IDs well-formed and present in the pinned bundle
    data = server.get_attack_data("atlas")
    for t in layer["techniques"]:
        assert re.match(r"^AML\.T\d{4}(\.\d{3})?$", t["techniqueID"])
        assert data.get_object_by_attack_id(t["techniqueID"], "attack-pattern") is not None
        # (d) only allowed keys
        assert set(t) <= {
            "techniqueID", "tactic", "score", "color", "comment", "showSubtechniques", "enabled"
        }
    assert _entry(layer, "AML.T0051")["showSubtechniques"] is True
    assert res["count"] == 3 and res["auto_added_parents"] == []


@needs_atlas
async def test_atlas_rejects_attack_ids():
    res = await server.generate_technique_layer(["T1059"], domain="atlas")
    assert res["unknown_ids"] == ["T1059"]
    assert res["success"] is False


async def test_duplicates_warn():
    res = await server.generate_technique_layer(["T1059", {"technique_id": "t1059", "score": 3}])
    assert res["count"] == 1 and res["warnings"]
    assert _entry(res["layer"], "T1059")["score"] == 3


@pytest.mark.parametrize("domain", ["mobile", "ics"])
async def test_other_domains(domain, capsys):
    data = require_domain(domain)
    tech = data.get_techniques(include_subtechniques=False, remove_revoked_deprecated=True)[0]
    aid = data.get_attack_id(tech["id"])
    res = await server.generate_technique_layer([aid], domain=domain)
    assert res["success"] is True and res["count"] == 1
    assert res["layer"]["domain"] == f"{domain}-attack"
    _assert_valid_attack_layer(res["layer"], capsys)


async def test_default_score_gradient(capsys):
    res = await server.generate_technique_layer(["T1059", "T1003"], default_score=1)
    grad = res["layer"]["gradient"]
    assert grad["minValue"] == 0 and grad["maxValue"] == 2
    assert isinstance(grad["minValue"], int) and isinstance(grad["maxValue"], int)
    _assert_valid_attack_layer(res["layer"], capsys)


async def test_no_scores_no_gradient():
    res = await server.generate_technique_layer(["T1059"], default_score=None)
    assert "gradient" not in res["layer"]
    assert "score" not in _entry(res["layer"], "T1059")


async def test_save_to_file(tmp_path, monkeypatch):
    base = tmp_path.resolve()
    monkeypatch.setattr(server, "LAYER_DIR", base)
    plain = await server.generate_technique_layer(["T1059", "T1003.001"], name="demo")
    saved = await server.generate_technique_layer(
        ["T1059", "T1003.001"], name="demo", save_to_file=True
    )
    assert saved["layer"] is None
    path = base / saved["layer_path"].rsplit("/", 1)[1]
    assert path.exists()
    assert json.loads(path.read_text()) == plain["layer"]
    again = await server.generate_technique_layer(["T1059"], name="demo", save_to_file=True)
    assert again["layer_path"] != saved["layer_path"]

    for bad in ("../../etc/passwd", "/abs/x"):
        res = await server.generate_technique_layer(["T1059"], name=bad, save_to_file=True)
        assert res["success"] is True
        from pathlib import Path

        assert Path(res["layer_path"]).resolve().parent == base

    res = await server.generate_technique_layer(["T1059"], name="", save_to_file=True)
    fname = res["layer_path"].rsplit("/", 1)[1]
    assert fname.startswith("layer-") and fname.endswith(".json")

    res = await server.generate_technique_layer(["T1059"], name="a" * 5000, save_to_file=True)
    assert len(res["layer_path"].rsplit("/", 1)[1].encode()) <= 255


async def test_layer_metadata_attack_version():
    res = await server.get_layer_metadata("enterprise")
    assert (
        res["metadata"]["versions"]["attack"] == release_info.LATEST_VERSION.split(".")[0]
    )


# --- generate_layer on the shared builder -------------------------------------


async def test_generate_layer_g1015(capsys):
    res = await server.generate_layer("G1015")
    gt = await server.get_group_techniques("Scattered Spider")
    assert res["success"] is True
    assert res["count"] == 78 == gt["count"]
    layer = res["layer"]
    assert len(json.dumps(layer)) < 15_000
    only = {t["attack_id"] for t in gt["techniques"] if not t["direct"]}
    for tid in only:
        assert "C0027" in _entry(layer, tid)["comment"]
    assert not any("tactic" in t for t in layer["techniques"])
    _assert_valid_attack_layer(layer, capsys)


async def test_generate_layer_exclude_campaigns():
    res = await server.generate_layer("G1015", include_campaigns=False)
    assert res["count"] == 64


async def test_generate_layer_m_and_s(capsys):
    m = await server.generate_layer("M1036")
    assert m["count"] == 12
    _assert_valid_attack_layer(m["layer"], capsys)
    s = await server.generate_layer("S0154")
    assert s["count"] == 73
    _assert_valid_attack_layer(s["layer"], capsys)


async def test_generate_layer_datacomponent():
    res = await server.generate_layer("DC0070")
    assert res["success"] is True and res["count"] > 0
    assert "T1552.005" in {t["techniqueID"] for t in res["layer"]["techniques"]}


async def test_generate_layer_technique_id_rejected():
    res = await server.generate_layer("T1059")
    assert res["success"] is False
    assert "generate_technique_layer" in res["message"]


async def test_generate_layer_comments():
    res = await server.generate_layer("M1036", include_comments=True)
    assert all(len(t.get("comment", "")) > 20 for t in res["layer"]["techniques"])


async def test_generate_layer_save(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "LAYER_DIR", tmp_path.resolve())
    res = await server.generate_layer("M1036", save_to_file=True)
    assert res["layer"] is None
    assert json.loads(open(res["layer_path"]).read())["domain"] == "enterprise-attack"


async def test_layer_tools_report_save_failures(tmp_path, monkeypatch):
    require_domain("enterprise")
    blocker = tmp_path / "file"
    blocker.write_text("")
    monkeypatch.setattr(server, "LAYER_DIR", blocker / "layers")
    result = await server.generate_technique_layer(["T1059"], save_to_file=True)
    assert result["success"] is False and "Could not write layer file" in result["message"]
    assert result["layer_path"] is None
    result = await server.generate_layer("G0016", save_to_file=True)
    assert result["success"] is False and "Could not write layer file" in result["message"]

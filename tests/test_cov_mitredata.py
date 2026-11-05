"""`_MitreData` fallbacks and the detection index, on a bare instance with stubbed library calls."""

from types import SimpleNamespace

import pytest
from mitreattack.stix20 import MitreAttackData
from stix2.exceptions import InvalidValueError
from stubs import boom

from mitre_mcp_server import server

pytestmark = pytest.mark.unit


def bare(**src):
    """A `_MitreData` without loading a bundle; `src` provides the stix2 MemoryStore methods."""
    inst = server._MitreData.__new__(server._MitreData)
    inst.src = SimpleNamespace(**src)
    return inst


def invalid(*args, **kwargs):
    raise InvalidValueError(object, "id", "custom object rejected")


def test_attack_id_lookup_falls_back_to_a_query_for_atlas_objects(monkeypatch):
    monkeypatch.setattr(MitreAttackData, "get_object_by_attack_id", invalid)
    seen = []

    def query(filters):
        seen.append([(f.property, f.value) for f in filters])
        return [{"id": "x-mitre-tactic--1"}]

    inst = bare(query=query)
    assert inst.get_object_by_attack_id("aml.ta0001", "x-mitre-tactic") == {
        "id": "x-mitre-tactic--1"
    }
    assert seen == [[("external_references.external_id", "AML.TA0001"), ("type", "x-mitre-tactic")]]
    inst.src.query = lambda filters: []
    assert inst.get_object_by_attack_id("AML.TA9999", "x-mitre-tactic") is None


def test_name_lookup_falls_back_to_a_query_for_atlas_objects(monkeypatch):
    monkeypatch.setattr(MitreAttackData, "get_objects_by_name", invalid)
    seen = []
    inst = bare(
        query=lambda filters: seen.append([(f.property, f.value) for f in filters]) or ["hit"]
    )
    assert inst.get_objects_by_name("Reconnaissance", "x-mitre-tactic") == ["hit"]
    assert seen == [[("type", "x-mitre-tactic"), ("name", "Reconnaissance")]]


def test_stix_id_lookup_falls_back_to_the_store(monkeypatch):
    monkeypatch.setattr(MitreAttackData, "get_object_by_stix_id", invalid)
    inst = bare(get=lambda stix_id: {"id": stix_id})
    assert inst.get_object_by_stix_id("x-mitre-matrix--1") == {"id": "x-mitre-matrix--1"}


def test_attack_id_ignores_foreign_reference_sources():
    inst = bare()
    inst.get_object_by_stix_id = lambda i: {
        "external_references": [{"source_name": "other", "external_id": "X1"}]
    }
    assert inst.get_attack_id("a") is None
    inst.get_object_by_stix_id = lambda i: {"external_references": []}
    assert inst.get_attack_id("a") is None
    inst.get_object_by_stix_id = lambda i: {
        "external_references": [{"source_name": "mitre-ics-attack", "external_id": "T0800"}]
    }
    assert inst.get_attack_id("a") == "T0800"


def index_inst(analytics, dets):
    inst = bare()
    inst.get_analytics = lambda remove_revoked_deprecated: analytics
    inst.get_detectionstrategies = lambda remove_revoked_deprecated: dets
    return inst


def test_detection_index_skips_incomplete_entries_and_dedups():
    an1 = {
        "id": "an1",
        "x_mitre_log_source_references": [
            {"x_mitre_data_component_ref": "dc1"},
            {"x_mitre_data_component_ref": "dc1"},
            {"name": "x"},
        ],
    }
    an_no_id = {"x_mitre_log_source_references": [{"x_mitre_data_component_ref": "dc9"}]}
    det1 = {"id": "det1", "x_mitre_analytic_refs": ["an1", "an1"]}
    det_no_id = {"x_mitre_analytic_refs": ["an1"]}
    inst = index_inst([an1, an_no_id], [det1, det_no_id])
    idx = inst._detection_index()
    assert idx["analytics_by_id"] == {"an1": an1}
    assert idx["analytics_by_dc"] == {"dc1": ["an1"]}
    assert idx["dets_by_analytic"] == {"an1": ["det1"]}
    assert idx["dets_by_id"] == {"det1": det1}
    assert inst._detection_index() is idx  # cached after a successful build


def test_failed_detection_index_build_is_reported_and_retried(capsys):
    inst = bare()
    inst.get_analytics = boom
    inst.get_detectionstrategies = boom
    first = inst._detection_index()
    assert first["analytics_by_id"] == {} and first["dets_by_id"] == {}
    err = capsys.readouterr().err
    assert "get_analytics failed" in err and "get_detectionstrategies failed" in err
    inst.get_analytics = lambda remove_revoked_deprecated: [{"id": "an1"}]
    inst.get_detectionstrategies = lambda remove_revoked_deprecated: []
    assert inst._detection_index()["analytics_by_id"] == {"an1": {"id": "an1"}}


def test_detection_chain_handles_failures_and_duplicates():
    det = {"id": "det1", "x_mitre_analytic_refs": ["an1", "missing"]}
    an1 = {"id": "an1"}
    inst = index_inst([an1], [det])
    inst.get_detection_strategies_detecting_technique = boom
    assert inst.detection_chain_for_technique("t") == []
    inst.get_detection_strategies_detecting_technique = lambda t: [
        {"object": det, "relationships": []},
        {"object": det, "relationships": []},
        {"object": {"name": "no id"}, "relationships": []},
    ]
    assert inst.detection_chain_for_technique("t") == [
        {"detection_strategy": det, "analytics": [an1]}
    ]


def test_techniques_for_datacomponent_filters_and_merges():
    t1 = {"id": "t1"}
    inst = index_inst(
        [
            {"id": "an1", "x_mitre_log_source_references": [{"x_mitre_data_component_ref": "dc1"}]},
            {"id": "an2", "x_mitre_log_source_references": [{"x_mitre_data_component_ref": "dc1"}]},
        ],
        [
            {"id": "det1", "x_mitre_analytic_refs": ["an1", "an2"]},
            {"id": "det2", "x_mitre_analytic_refs": ["an1"]},
            {"id": "det_bad", "x_mitre_analytic_refs": ["an1"]},
        ],
    )

    def detected(det_id):
        if det_id == "det_bad":
            raise RuntimeError("lookup failed")
        return [
            {"object": t1, "relationships": []},
            {"object": {"name": "no id"}},
            {"object": {"id": "old", "x_mitre_deprecated": True}},
            {"object": {"id": "rev", "revoked": True}},
        ]

    inst.get_techniques_detected_by_detection_strategy = detected
    assert inst.techniques_for_datacomponent("dc1") == [(t1, ["det1", "det2"], ["an1", "an2"])]
    assert inst.techniques_for_datacomponent("unknown") == []

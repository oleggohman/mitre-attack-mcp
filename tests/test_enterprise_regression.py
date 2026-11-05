"""The server subclass must not change ATT&CK behaviour."""

from mitreattack.stix20 import MitreAttackData

from mitre_mcp_server import server


def test_subclass_matches_library_on_enterprise():
    path = str(server.get_stix_path("enterprise"))
    plain = MitreAttackData(path)
    sub = server._MitreData(path)

    def ids(objs):
        return sorted(o["id"] for o in objs)

    assert ids(plain.get_tactics()) == ids(sub.get_tactics())
    assert ids(plain.get_matrices()) == ids(sub.get_matrices())

    tech = plain.get_object_by_attack_id("T1059", "attack-pattern")
    assert plain.get_attack_id(tech["id"]) == sub.get_attack_id(tech["id"]) == "T1059"

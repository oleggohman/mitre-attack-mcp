"""Small fake data object for tests of paths real data cannot reach (pre-v18 STIX, odd shapes)."""

from types import SimpleNamespace

from mitre_mcp_server import server


def sid(type_, n):
    return f"{type_}--{n:08d}-0000-4000-8000-000000000000"


def obj(type_, n, name=None, **extra):
    """Plain-dict STIX-like object."""
    return {"id": sid(type_, n), "type": type_, "name": name or f"{type_} {n}", **extra}


def entry(o, *relationships):
    """RelationshipEntry-like dict."""
    return {"object": o, "relationships": list(relationships)}


def install(monkeypatch, objects=(), attack_ids=None, **methods):
    """Replace `server.get_attack_data` with a fake exposing `methods` plus id/object lookups."""
    by_id = {(o["id"] if isinstance(o, dict) else o.id): o for o in objects}
    ids = attack_ids or {}

    def get_object_by_stix_id(stix_id):
        if stix_id not in by_id:
            raise ValueError(f"{stix_id} not found")
        return by_id[stix_id]

    def get_attack_id(stix_id):
        return ids.get(stix_id)

    defaults = dict(
        get_object_by_stix_id=get_object_by_stix_id,
        get_attack_id=get_attack_id,
        remove_revoked_deprecated=lambda objs: [
            o for o in objs if not (o.get("revoked") or o.get("x_mitre_deprecated"))
        ],
    )
    fake = SimpleNamespace(**{**defaults, **methods})
    monkeypatch.setattr(server, "get_attack_data", lambda domain="enterprise": fake)
    return fake


def boom(*args, **kwargs):
    raise RuntimeError("injected")

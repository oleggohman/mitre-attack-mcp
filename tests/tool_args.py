"""Argument table and result cache for the registry-driven smoke suite (testing plan D1-D3).

Not a test module. Holds:
  * `Samples`: deterministic per-domain sample entities derived from the raw STIX bundles (D2);
  * `ToolSpec` / `ARGS`: one entry per registered tool (D1);
  * `RawCheck` helpers proving that an expected-empty cell is empty because the data says so;
  * `NULLABLE`, `SIZE_OVERRIDES`, `DEFAULT_WIRE_BUDGET`;
  * a session-level result cache keyed `(tool, domain, variant)` (D3).
"""

from __future__ import annotations

import functools
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional

from conftest import raw_bundle

from mitre_mcp_server import server

DOMAINS = ["enterprise", "mobile", "ics", "atlas"]
DEFAULT_WIRE_BUDGET = 100_000
GHOST_UUID = "00000000-0000-4000-8000-000000000000"


# ---------------------------------------------------------------------------
# Samples (D2)
# ---------------------------------------------------------------------------


class MissingRole(Exception):
    """A builder asked for a sample role that the domain does not have."""


@dataclass(frozen=True)
class Ent:
    stix_id: str
    attack_id: Optional[str]
    name: str
    type: str
    extra: Dict[str, Any] = field(default_factory=dict, compare=False, hash=False)


def _active(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def _attack_id(obj: dict) -> Optional[str]:
    for ref in obj.get("external_references", []):
        if ref.get("external_id") and str(ref.get("source_name", "")).startswith("mitre-"):
            return ref["external_id"]
    return None


def _sort_key(ent: Ent):
    return (ent.attack_id is None, ent.attack_id or "", ent.stix_id)


def _ghost(type_: str, attack_id: str) -> Ent:
    return Ent(f"{type_}--{GHOST_UUID}", attack_id, "Nonexistent object", type_)


GHOSTS = {
    "technique": _ghost("attack-pattern", "T9999"),
    "group": _ghost("intrusion-set", "G9999"),
    "software": _ghost("malware", "S9999"),
    "campaign": _ghost("campaign", "C9999"),
    "mitigation": _ghost("course-of-action", "M9999"),
    "datacomponent": _ghost("x-mitre-data-component", "DC9999"),
    "asset": _ghost("x-mitre-asset", "A9999"),
    "matrix": _ghost("x-mitre-matrix", "MA9999"),
    "tactic": _ghost("x-mitre-tactic", "TA9999"),
}
GHOST_SCALARS = {"platform": "Windows", "alias": "NonexistentAlias", "word": "nonexistentword"}


class Samples:
    """Sample entities of one domain; `ghost=True` substitutes well-formed unknown objects."""

    def __init__(self, domain: str, roles: Dict[str, Any], ghost: bool = False):
        self.domain = domain
        self._roles = roles
        self.ghost = ghost

    def ghosted(self) -> "Samples":
        return Samples(self.domain, self._roles, ghost=True)

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        value = self._roles.get(name)
        if value is None:
            if self.ghost:
                if name in GHOST_SCALARS:
                    return GHOST_SCALARS[name]
                if name.endswith("_alias"):
                    return GHOST_SCALARS["alias"]
                if name.startswith("timestamp"):
                    return "2100-01-01T00:00:00.000Z"
                key = next((k for k in GHOSTS if name == k or name.startswith(k + "_")), None)
                if key is not None:
                    return GHOSTS[key]
            raise MissingRole(f"{self.domain}: no sample for role {name!r}")
        return value


def _build_samples(domain: str) -> Samples:
    objs = [o for o in raw_bundle(domain)["objects"] if _active(o)]
    by_id = {o["id"]: o for o in objs}

    def ent(o: dict) -> Ent:
        extra = {}
        if o.get("x_mitre_shortname"):
            extra["shortname"] = o["x_mitre_shortname"]
        aliases = o.get("aliases") or o.get("x_mitre_aliases") or []
        extra["aliases"] = [a for a in aliases if a != o.get("name")]
        extra["description"] = o.get("description") or ""
        return Ent(o["id"], _attack_id(o), o.get("name", ""), o["type"], extra)

    ents = {}  # stix_id -> Ent

    def get(stix_id: str) -> Ent:
        if stix_id not in ents:
            ents[stix_id] = ent(by_id[stix_id])
        return ents[stix_id]

    def of_type(*types: str):
        return sorted((get(o["id"]) for o in objs if o["type"] in types), key=_sort_key)

    rels = []
    for o in objs:
        if o["type"] == "relationship" and o["source_ref"] in by_id and o["target_ref"] in by_id:
            rels.append((o["relationship_type"], o["source_ref"], o["target_ref"]))

    def pick(rel_type, src_types, tgt_types, side):
        """First entity (by ATT&CK ID) that is `side` of a matching relationship."""
        found = {}
        for rt, s, t in rels:
            if rt != rel_type:
                continue
            if by_id[s]["type"] not in src_types or by_id[t]["type"] not in tgt_types:
                continue
            found[s if side == "src" else t] = True
        cands = sorted((get(i) for i in found), key=_sort_key)
        return cands[0] if cands else None

    sw = ("malware", "tool")
    ap = ("attack-pattern",)
    roles: Dict[str, Any] = {}
    techs = of_type("attack-pattern")
    roles["technique"] = techs[0] if techs else None
    roles["technique_with_subs"] = pick("subtechnique-of", ap, ap, "tgt")
    roles["subtechnique"] = pick("subtechnique-of", ap, ap, "src")
    roles["technique_used_by_group"] = pick("uses", ("intrusion-set",), ap, "tgt")
    roles["technique_used_by_software"] = pick("uses", sw, ap, "tgt")
    roles["technique_used_by_campaign"] = pick("uses", ("campaign",), ap, "tgt")
    roles["technique_with_mitigation"] = pick("mitigates", ("course-of-action",), ap, "tgt")
    roles["mitigation_with_techniques"] = pick("mitigates", ("course-of-action",), ap, "src")
    roles["technique_targeting_asset"] = pick("targets", ap, ("x-mitre-asset",), "src")
    roles["asset_with_techniques"] = pick("targets", ap, ("x-mitre-asset",), "tgt")
    roles["group_with_techniques"] = pick("uses", ("intrusion-set",), ap, "src")
    roles["group_with_software"] = pick("uses", ("intrusion-set",), sw, "src")
    roles["software_used_by_group"] = pick("uses", ("intrusion-set",), sw, "tgt")
    roles["group_with_campaign"] = pick("attributed-to", ("campaign",), ("intrusion-set",), "tgt")
    roles["campaign_with_groups"] = pick("attributed-to", ("campaign",), ("intrusion-set",), "src")
    roles["software_with_techniques"] = pick("uses", sw, ap, "src")
    roles["campaign_with_techniques"] = pick("uses", ("campaign",), ap, "src")
    roles["campaign_with_software"] = pick("uses", ("campaign",), sw, "src")
    roles["software_used_by_campaign"] = pick("uses", ("campaign",), sw, "tgt")

    # Detection chain: technique <-detects- strategy -> analytics -> log source -> data component.
    dc_to_tech: Dict[str, set] = {}
    tech_has_dc: Dict[str, bool] = {}
    for rt, s, t in rels:
        if rt != "detects" or by_id[s]["type"] != "x-mitre-detection-strategy":
            continue
        for an_id in by_id[s].get("x_mitre_analytic_refs") or []:
            analytic = by_id.get(an_id)
            if not analytic:
                continue
            for ls in analytic.get("x_mitre_log_source_references") or []:
                dc = ls.get("x_mitre_data_component_ref")
                if dc in by_id:
                    dc_to_tech.setdefault(dc, set()).add(t)
                    tech_has_dc[t] = True
    det_techs = sorted((get(i) for i in tech_has_dc), key=_sort_key)
    roles["technique_with_det"] = det_techs[0] if det_techs else None
    dcs = sorted((get(i) for i in dc_to_tech), key=_sort_key)
    roles["datacomponent_with_techniques"] = dcs[0] if dcs else None

    matrices = of_type("x-mitre-matrix")
    roles["matrix"] = matrices[0] if matrices else None
    tactics = of_type("x-mitre-tactic")
    roles["tactic"] = tactics[0] if tactics else None
    for role, types in (
        ("group", ("intrusion-set",)),
        ("software", sw),
        ("campaign", ("campaign",)),
    ):
        found = of_type(*types)
        roles[role] = found[0] if found else None
        with_alias = [e for e in found if e.extra["aliases"]]
        roles[f"{role}_alias"] = (
            with_alias[0].extra["aliases"][0] if with_alias else (found[0].name if found else None)
        )

    platforms = Counter(
        p for o in objs if o["type"] == "attack-pattern" for p in (o.get("x_mitre_platforms") or [])
    )
    roles["platform"] = (
        sorted(platforms.items(), key=lambda kv: (-kv[1], kv[0]))[0][0] if platforms else None
    )

    # A content word taken from a real description, so a full-text search must hit it.
    word = None
    for t in techs:
        m = re.search(r"\b([A-Za-z]{7,})\b", t.extra["description"])
        if m:
            word = m.group(1)
            break
    roles["word"] = word

    def quartile(field_name):
        vals = sorted(
            o[field_name] for o in objs if o["type"] == "attack-pattern" and o.get(field_name)
        )
        return vals[len(vals) // 4] if vals else None

    roles["timestamp_created"] = quartile("created")
    roles["timestamp_modified"] = quartile("modified")
    return Samples(domain, roles)


def active_entities(domain: str, *types: str) -> list:
    """All active objects of the given STIX types as Ent, sorted by ATT&CK ID (None last)."""
    out = []
    for o in raw_bundle(domain)["objects"]:
        if o["type"] in types and _active(o):
            out.append(Ent(o["id"], _attack_id(o), o.get("name", ""), o["type"]))
    return sorted(out, key=_sort_key)


@functools.cache
def samples(domain: str) -> Samples:
    return _build_samples(domain)


# ---------------------------------------------------------------------------
# Raw checks (expected-empty cells must be explained by the data)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RawCheck:
    description: str
    predicate: Callable[[dict], bool]

    def __call__(self, bundle: dict) -> bool:
        return self.predicate(bundle)


def no_active(*types: str) -> RawCheck:
    """The bundle has no active (non-revoked, non-deprecated) object of these STIX types."""
    return RawCheck(
        f"no active {'/'.join(types)} objects",
        lambda b: not any(o["type"] in types and _active(o) for o in b["objects"]),
    )


def no_field(type_: str, field_name: str) -> RawCheck:
    """No active object of `type_` carries a non-empty `field_name`."""
    return RawCheck(
        f"no active {type_} has {field_name}",
        lambda b: (
            not any(o["type"] == type_ and _active(o) and o.get(field_name) for o in b["objects"])
        ),
    )


def no_revoked(type_: str) -> RawCheck:
    return RawCheck(
        f"no revoked {type_} objects",
        lambda b: not any(o["type"] == type_ and o.get("revoked") for o in b["objects"]),
    )


# ---------------------------------------------------------------------------
# ToolSpec and the argument table (D1)
# ---------------------------------------------------------------------------

Builder = Callable[[Samples], Dict[str, Any]]


@dataclass
class ToolSpec:
    args: Builder
    neg: bool = False  # derive a negative variant (unknown well-formed IDs/names)
    expect_empty: Dict[str, RawCheck] = field(default_factory=dict)
    expect_failure: Dict[str, str] = field(default_factory=dict)  # domain -> message substring
    known_bug: Dict[str, str] = field(default_factory=dict)
    na: Dict[str, str] = field(default_factory=dict)  # domain -> reason
    fault_raises: Optional[str] = None  # reason: injected error escapes as UnexpectedToolError
    fault_na: Optional[str] = None  # reason: tool does not read domain data
    no_message: Optional[str] = None  # reason: contract has no message/formatted field
    nullable_fields: Dict[str, str] = field(default_factory=dict)  # per-tool NULLABLE with reason
    bogus_response: Optional[str] = None  # reason: invalid domain is a documented failure response


def a(**kw) -> Builder:
    """Builder from keyword args; callables are evaluated against the samples."""

    def build(s: Samples) -> Dict[str, Any]:
        return {k: (v(s) if callable(v) else v) for k, v in kw.items()}

    return build


def _ref(role: str, attr: str = "stix_id"):
    return lambda s: getattr(getattr(s, role), attr)


def _attr(name: str):
    return lambda s: getattr(s, name)


NA_ALL = {d: "-" for d in DOMAINS}
GROUP_EMPTY = {"atlas": no_active("intrusion-set")}
SOFTWARE_EMPTY = {"atlas": no_active("malware", "tool")}
CAMPAIGN_EMPTY = {"atlas": no_active("campaign")}
DETECT_EMPTY = {"atlas": no_active("x-mitre-data-component", "x-mitre-detection-strategy")}
ASSET_EMPTY = {d: no_active("x-mitre-asset") for d in ("enterprise", "mobile", "atlas")}
PROC_EMPTY = {"atlas": no_active("intrusion-set", "malware", "tool", "campaign")}
F6 = "F6: get_procedure_examples_by_tactic calls a non-existent library method (usage-fixes F6)"
FAULT_FIRST = "first data call outside try; error surfaces as UnexpectedToolError / wire is_error"


def _spec(args, **kw) -> ToolSpec:
    return ToolSpec(args=args, **kw)


ARGS: Dict[str, ToolSpec] = {
    # --- generic lookups ---------------------------------------------------
    "get_data_stats": _spec(
        a(), fault_na="does not read domain data", no_message="returns a plain per-domain file map"
    ),
    "get_technique_by_id": _spec(
        a(technique_id=_ref("technique", "attack_id")), neg=True, fault_raises=FAULT_FIRST
    ),
    "get_object_by_attack_id": _spec(
        a(attack_id=_ref("technique", "attack_id"), stix_type="attack-pattern"), neg=True
    ),
    "get_object_by_stix_id": _spec(a(stix_id=_ref("technique")), neg=True),
    "get_objects_by_name": _spec(
        a(name=_ref("technique", "name"), stix_type="attack-pattern"), neg=True
    ),
    "get_objects_by_content": _spec(
        a(content=_attr("word"), object_type="attack-pattern"), neg=True
    ),
    "get_techniques_by_tactic": _spec(a(tactic=_ref("tactic", "name")), neg=True),
    "search_techniques": _spec(a(query=_ref("technique", "name")), neg=True),
    "get_group_by_name": _spec(
        a(group_name=_ref("group_with_techniques", "name")), neg=True, expect_empty=GROUP_EMPTY
    ),
    # neg=False: the type is parsed from the ID prefix, so an unknown well-formed ID still resolves.
    "get_stix_type": _spec(a(stix_id=_ref("technique"))),
    "search_groups": _spec(a(query=_ref("group", "name")), neg=True, expect_empty=GROUP_EMPTY),
    "get_group_techniques": _spec(
        a(group_name=_ref("group_with_techniques", "name")), neg=True, expect_empty=GROUP_EMPTY
    ),
    "get_software": _spec(a(), expect_empty=SOFTWARE_EMPTY),
    "search_software": _spec(
        a(query=_ref("software", "name")), neg=True, expect_empty=SOFTWARE_EMPTY
    ),
    "get_attack_id": _spec(a(stix_id=_ref("technique")), neg=True),
    "get_name": _spec(a(stix_id=_ref("technique")), neg=True),
    "get_technique_tactics": _spec(a(technique_id=_ref("technique", "attack_id")), neg=True),
    "get_stats": _spec(a()),
    "get_groups_by_alias": _spec(a(alias=_attr("group_alias")), neg=True, expect_empty=GROUP_EMPTY),
    # --- groups ------------------------------------------------------------
    "get_techniques_used_by_group": _spec(
        a(group_stix_id=_ref("group_with_techniques")), neg=True, expect_empty=GROUP_EMPTY
    ),
    "get_software_used_by_group": _spec(
        a(group_stix_id=_ref("group_with_software")), neg=True, expect_empty=GROUP_EMPTY
    ),
    "get_campaigns_attributed_to_group": _spec(
        a(group_stix_id=_ref("group_with_campaign")),
        neg=True,
        expect_empty={"atlas": no_active("campaign", "intrusion-set")},
    ),
    "get_campaigns_by_alias": _spec(
        a(alias=_attr("campaign_alias")), neg=True, expect_empty=CAMPAIGN_EMPTY
    ),
    "get_techniques_used_by_group_software": _spec(
        a(group_stix_id=_ref("group_with_software")), neg=True, expect_empty=GROUP_EMPTY
    ),
    "get_groups_using_technique": _spec(
        a(technique_stix_id=_ref("technique_used_by_group")), neg=True, expect_empty=GROUP_EMPTY
    ),
    "get_groups_using_software": _spec(
        a(software_stix_id=_ref("software_used_by_group")), neg=True, expect_empty=SOFTWARE_EMPTY
    ),
    "get_groups_attributing_to_campaign": _spec(
        a(campaign_stix_id=_ref("campaign_with_groups")), neg=True, expect_empty=CAMPAIGN_EMPTY
    ),
    "get_software_by_alias": _spec(
        a(alias=_attr("software_alias")), neg=True, expect_empty=SOFTWARE_EMPTY
    ),
    "get_software_using_technique": _spec(
        a(technique_stix_id=_ref("technique_used_by_software")),
        neg=True,
        expect_empty=SOFTWARE_EMPTY,
    ),
    "get_techniques_used_by_software": _spec(
        a(software_stix_id=_ref("software_with_techniques")), neg=True, expect_empty=SOFTWARE_EMPTY
    ),
    # --- catalogues ----------------------------------------------------------
    "get_all_techniques": _spec(a()),
    "get_all_subtechniques": _spec(a()),
    "get_all_parent_techniques": _spec(a()),
    "get_all_groups": _spec(a(), expect_empty=GROUP_EMPTY),
    "get_all_software": _spec(a(), expect_empty=SOFTWARE_EMPTY),
    "get_all_mitigations": _spec(a()),
    "get_all_tactics": _spec(a()),
    "get_all_matrices": _spec(a()),
    "get_all_campaigns": _spec(a(), expect_empty=CAMPAIGN_EMPTY),
    "get_all_datasources": _spec(
        a(), expect_empty={d: no_active("x-mitre-data-source") for d in DOMAINS}
    ),
    "get_all_datacomponents": _spec(a(), expect_empty=DETECT_EMPTY),
    "get_all_assets": _spec(a(), expect_empty=ASSET_EMPTY),
    "get_assets_targeted_by_technique": _spec(
        a(technique_stix_id=_ref("technique_targeting_asset")), neg=True, expect_empty=ASSET_EMPTY
    ),
    "get_techniques_targeting_asset": _spec(
        a(asset_stix_id=_ref("asset_with_techniques")), neg=True, expect_empty=ASSET_EMPTY
    ),
    # --- campaigns -----------------------------------------------------------
    "get_campaigns_using_technique": _spec(
        a(technique_stix_id=_ref("technique_used_by_campaign")),
        neg=True,
        expect_empty=CAMPAIGN_EMPTY,
    ),
    "get_techniques_used_by_campaign": _spec(
        a(campaign_stix_id=_ref("campaign_with_techniques")), neg=True, expect_empty=CAMPAIGN_EMPTY
    ),
    "get_campaigns_using_software": _spec(
        a(software_stix_id=_ref("software_used_by_campaign")),
        neg=True,
        expect_empty={"atlas": no_active("campaign", "malware", "tool")},
    ),
    "get_software_used_by_campaign": _spec(
        a(campaign_stix_id=_ref("campaign_with_software")), neg=True, expect_empty=CAMPAIGN_EMPTY
    ),
    # --- techniques ----------------------------------------------------------
    "get_techniques_by_platform": _spec(a(platform=_attr("platform")), neg=True),
    "get_parent_technique_of_subtechnique": _spec(
        a(technique_stix_id=_ref("subtechnique")), neg=True
    ),
    "get_subtechniques_of_technique": _spec(
        a(technique_stix_id=_ref("technique_with_subs")), neg=True
    ),
    "get_techniques_mitigated_by_mitigation": _spec(
        a(mitigation_stix_id=_ref("mitigation_with_techniques")), neg=True
    ),
    "get_mitigations_mitigating_technique": _spec(
        a(technique_stix_id=_ref("technique_with_mitigation")), neg=True
    ),
    # --- detection -----------------------------------------------------------
    "get_datacomponents_detecting_technique": _spec(
        a(technique_stix_id=_ref("technique_with_det")), neg=True, expect_empty=DETECT_EMPTY
    ),
    "get_techniques_detected_by_datacomponent": _spec(
        a(datacomponent_stix_id=_ref("datacomponent_with_techniques")),
        neg=True,
        expect_empty=DETECT_EMPTY,
    ),
    "get_detection_strategies_for_technique": _spec(
        a(technique_id=_ref("technique_with_det", "attack_id")), neg=True, expect_empty=DETECT_EMPTY
    ),
    "get_procedure_examples_by_technique": _spec(
        a(technique_stix_id=_ref("technique_used_by_group")), neg=True, expect_empty=PROC_EMPTY
    ),
    "get_procedure_examples_by_tactic": _spec(
        a(tactic=_ref("tactic", "name")), known_bug={d: F6 for d in DOMAINS}
    ),
    # --- misc ------------------------------------------------------------------
    "get_objects_by_type": _spec(a(stix_type="attack-pattern")),
    "get_tactics_by_matrix": _spec(a(matrix_stix_id=_ref("matrix")), neg=True),
    "get_tactics_by_technique": _spec(a(technique_stix_id=_ref("technique")), neg=True),
    "get_objects_created_after": _spec(a(timestamp=_attr("timestamp_created"))),
    "get_objects_modified_after": _spec(a(timestamp=_attr("timestamp_modified"))),
    "get_revoked_techniques": _spec(a(), expect_empty={"atlas": no_revoked("attack-pattern")}),
    # --- layers ------------------------------------------------------------------
    "generate_layer": _spec(
        a(attack_id=_ref("group_with_techniques", "attack_id")),
        expect_failure={"atlas": "generate_technique_layer"},
        bogus_response="layer tools validate the domain and return success False",
    ),
    "generate_technique_layer": _spec(
        a(
            techniques=lambda s: [
                t
                for t in (
                    s.technique.attack_id,
                    s.technique_with_subs.attack_id,
                    s.subtechnique.attack_id,
                )
            ]
        ),
        bogus_response="layer tools validate the domain and return success False",
    ),
    "get_layer_metadata": _spec(
        a(),
        fault_na="does not read domain data",
        bogus_response="layer tools validate the domain and return success False",
    ),
}


def nonempty(result: dict) -> bool:
    """True when the result carries data (the tool's own primary list / found / success)."""
    if result.get("found") is False or result.get("success") is False:
        return False
    for key in ("count", "returned", "total"):
        if isinstance(result.get(key), (int, float)) and not isinstance(result.get(key), bool):
            return result[key] > 0
    lists = [v for v in result.values() if isinstance(v, (list, dict))]
    if lists:
        return any(bool(v) for v in lists)
    return result.get("found") is True or result.get("success") is True


# ---------------------------------------------------------------------------
# Allow-lists
# ---------------------------------------------------------------------------

# Key-field names allowed to be null in entity dicts (reason required).
NULLABLE: Dict[str, str] = {
    "data_source_stix_id": "no x_mitre_data_source_ref on ATT&CK v18+ data (usage-fixes F1)",
    "data_source_name": "no x_mitre_data_source_ref on ATT&CK v18+ data (usage-fixes F1)",
    "data_source_attack_id": "no x_mitre_data_source_ref on ATT&CK v18+ data (usage-fixes F1)",
}

# {tool: (bytes, reason)}; filled from measurements in Task 3.
_FSIZE = "F-SIZE: no default limit (owner: not in this plan)"
_NOLIMIT = "F-SIZE: result size follows the query; generic sample query matches most techniques"
SIZE_OVERRIDES: Dict[str, tuple] = {
    # (ceil(measured * 1.25), reason); measured on ATT&CK v20.0 enterprise, 2026-11-05
    "get_all_groups": (179_000, _FSIZE),  # measured 142808
    "get_all_parent_techniques": (188_000, _FSIZE),  # measured 149825
    "get_all_software": (591_000, _FSIZE),  # measured 472018
    "get_all_subtechniques": (589_000, _FSIZE),  # measured 470956
    "get_all_techniques": (585_000, _FSIZE),  # measured 467768
    "get_software": (551_000, _FSIZE),  # measured 440745
    "get_objects_by_content": (537_000, _NOLIMIT),  # measured 429549
    "get_objects_by_type": (499_000, _FSIZE),  # measured 398697
    "get_techniques_by_platform": (340_000, _NOLIMIT),  # measured 271410 (most common platform)
}


# ---------------------------------------------------------------------------
# Cells and result cache (D3)
# ---------------------------------------------------------------------------

_ID_ARG_RE = re.compile(r"(^|_)(stix_id|id|attack_id|name|alias|query|content|platform|tactic)$")
_ATTACK_ID_RE = re.compile(r"^([A-Za-z.]*?)(\d+)(\.\d+)?$")


def ghost_value(value: str) -> str:
    """Well-formed but unknown replacement for an ID or name."""
    if "--" in value:
        return f"{value.split('--')[0]}--{GHOST_UUID}"
    m = _ATTACK_ID_RE.match(value)
    if m and any(ch.isdigit() for ch in value):
        return f"{m.group(1)}9999"
    return "Nonexistent-xyz"


def derive_negative(args: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(args)
    for key, value in args.items():
        if isinstance(value, str) and _ID_ARG_RE.search(key):
            out[key] = ghost_value(value)
    return out


def is_na(tool: str, domain: Optional[str]) -> Optional[str]:
    spec = ARGS[tool]
    return spec.na.get(domain) if domain else None


def tool_domains(schema: dict) -> list:
    """Domains a tool is exercised with: all four if it takes `domain`, else one call."""
    return DOMAINS if "domain" in schema.get("properties", {}) else [None]


def cell_args(tool: str, domain: Optional[str], variant: str, schema: dict) -> Dict[str, Any]:
    spec = ARGS[tool]
    if domain is None:
        args = spec.args(Samples("-", {}))
    else:
        s = samples(domain)
        if domain in spec.expect_empty or domain in spec.expect_failure:
            s = s.ghosted()
        args = spec.args(s)
        args["domain"] = domain
    props = schema.get("properties", {})
    if variant == "negative":
        args = derive_negative(args)
    elif variant == "no_description":
        args["include_description"] = False
    elif variant == "bogus_domain":
        args["domain"] = "bogus"
    if variant == "no_description":
        assert "include_description" in props
    return args


@dataclass
class Cell:
    result: Optional[dict]
    wire_bytes: int
    exc: Optional[BaseException]
    structured: Any = None
    text: Optional[str] = None
    is_error: Optional[bool] = None


_CACHE: Dict[tuple, Cell] = {}
CALL_COUNTS: Counter = Counter()
_SCHEMAS: Dict[str, dict] = {}


async def schemas() -> Dict[str, dict]:
    if not _SCHEMAS:
        for t in await server.mcp.list_tools():
            _SCHEMAS[t.name] = t.input_schema
    return _SCHEMAS


async def cell(tool: str, domain: Optional[str], variant: str = "default") -> Cell:
    """Call a tool once per (tool, domain, variant) per session and cache the outcome."""
    key = (tool, domain, variant)
    if key in _CACHE:
        return _CACHE[key]
    schema = (await schemas())[tool]
    if (
        variant == "no_description"
        and schema.get("properties", {}).get("include_description", {}).get("default") is False
    ):
        # Default already omits descriptions: the default cell is the no_description cell.
        _CACHE[key] = await cell(tool, domain, "default")
        return _CACHE[key]
    args = cell_args(tool, domain, variant, schema)
    CALL_COUNTS[key] += 1
    try:
        res = await server.mcp.call_tool(tool, args)
    except BaseException as exc:
        out = Cell(None, 0, exc)
    else:
        result = res.structured_content["result"] if res.structured_content else None
        out = Cell(
            result,
            len(res.model_dump_json(by_alias=True)),
            None,
            res.structured_content,
            res.content[0].text if res.content else None,
            res.is_error,
        )
    _CACHE[key] = out
    return out

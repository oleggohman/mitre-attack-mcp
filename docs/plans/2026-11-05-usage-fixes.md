# Plan: usage fixes — detection mapping, output size, description flag, group provenance, technique layers

Revision 3 (after plan review cycle 2: gradient int bounds ≥2 range, AML prefix strip in 6(b),
explicit path check instead of assert). Status: APPROVED (plan review cycle 3; F5 caveat
completed after approval).

Owner decisions (cycle 1, closed): breaking 0.4.0 defaults accepted and listed under a CHANGELOG
"Breaking" heading; `include_campaigns` defaults to True.

Review cycle 1 resolutions: R1 validator returns a string, not None (Tasks 5/7) · R2 None-safe sort
key · R3 sorting is a behaviour change · R4 chain only when wrapper path is empty · R5 automated
ATLAS acceptance replaces manual load · R6 layer path safety · R7 count excludes auto-added
parents · R8 Task 3 anchor + no `include_relationships` · R9 test inputs · R10 atlas wording ·
R11 seven version locations · R12 pagination only on large tools · R13 analytics are dicts /
revoked filter · R14 no affected tests in Task 8.

Target release: 0.4.0 (0.3.0 is tagged). Priority: correctness (Tasks 1-4) → feature (Tasks 5-7)
→ ergonomics (Tasks 8-9) → docs/version (Task 10). Every task leaves the suite green and is
shippable on its own. Line numbers are pre-change (re-grep before editing).

## Verified facts (2026-11-05, ATT&CK v20.0 cache, ATLAS v1.16.0, mitreattack-python 6.3.1)

Baseline: `.venv/bin/python -m pytest -q` → 52 passed.

### F1. Detection mapping (problem 1)

- STIX counts (raw bundles):

  | domain | detection strategies | analytics | data components | `detects` rels | techniques w/ `x_mitre_data_sources` |
  |---|---|---|---|---|---|
  | enterprise | 705 (2 revoked/deprecated) | 1770 | 109 (3 deprecated) | 703, all `x-mitre-detection-strategy → attack-pattern` | 0 / 706 active |
  | mobile | 124 | 211 | 29 | 124, same shape | 0 |
  | ics | 106 | 302 | 36 | 104, same shape | 0 |
  | atlas | 0 | 0 | 0 | 0 | — |

  No data component is the source of any `detects` relationship → the library's
  `get_datacomponents_detecting_technique` / `get_techniques_detected_by_datacomponent` return
  `[]`, and the server's fallback (`x_mitre_data_sources`, server.py:7261-7358) is dead too.
- Detection strategy: `external_id` `DET####`, `x_mitre_analytic_refs` (list of analytic STIX IDs).
- Analytic: `external_id` `AN####`, `x_mitre_platforms`, `x_mitre_mutable_elements` (list of
  `{field, description}`), `x_mitre_log_source_references` — **a real list of dicts**
  `{x_mitre_data_component_ref, name, channel}` (4206/615/443 entries, all `dict`), absent on
  49/12/12 analytics (enterprise/mobile/ics). All 1770 enterprise analytics are active.
- **Object types differ by accessor:** `get_analytics()` / `get_detectionstrategies()` return
  library classes (`Analytic`, `DetectionStrategy`; `.id` works), but
  `get_analytics_by_detection_strategy` (MAD:774, raw `src.query`) returns **plain dicts** —
  `.id` raises `AttributeError`. Code must use `_field(obj, "id")` / `obj["id"]` throughout.
- Data components are `DC####`; **`x_mitre_data_source_ref` is absent on all of them** (v18+), and
  all 38 enterprise data sources are deprecated → `data_source_*` fields are always null and
  `get_all_datasources` is empty by default (correct behaviour, document only).
- Through `_MitreData`:
  T1552.005 → `get_detection_strategies_detecting_technique` → 1 entry **DET0001** "Detect Access
  to Cloud Instance Metadata API (IaaS)" → **AN0001** `['IaaS']` → log sources DC0082 Network
  Connection Creation (`AWS:VPCFlowLogs`), DC0070 Cloud Service Metadata (`AWS:CloudTrail`),
  DC0085 Network Traffic Content (`ebpf:syscalls`).
  703/706 active enterprise techniques have a DET; max 1 DET per technique. First index build 0.11 s.
- Library methods (MitreAttackData.py): `get_detectionstrategies` :457, `get_analytics` :442,
  `get_analytics_by_detection_strategy` :774, `get_detection_strategies_detecting_technique` :2055,
  `get_techniques_detected_by_detection_strategy` :2095 (both return RelationshipEntry wrappers;
  `get_related` already drops revoked/deprecated *targets*, MAD:~1090).
- Server: `get_datacomponents_detecting_technique` is a **sync** `def` (server.py:7139);
  `get_techniques_detected_by_datacomponent` :7392. Existing test
  `tests/test_relationship_tools.py:141-153` monkeypatches the library wrapper method on the real
  instance to return one entry and asserts `count == 1`.

### F2. Output size (problem 2)

`get_group_techniques("Scattered Spider")` (G1015, 78 techniques), JSON bytes:

| include_description | total | `formatted` | `techniques[]` | technique desc | relationship desc |
|---|---|---|---|---|---|
| True (default) | 317,170 | 127,537 | 186,830 | 118,294 | 24,790 |
| False | 76,927 | 8,151 | 68,071 | 0 | **24,790** |

- `formatted` repeats every description (≈40 % of the payload); relationship descriptions
  (procedure text) and full relationship blobs (`stix_id`, `source_ref`, `target_ref`) are emitted
  **regardless of the flag** (server.py:1601-1625, 2390-2414 and the same block in 10 more tools).
- `generate_layer("G1015")` = 101,995 bytes, of which 95,896 is the `comment` on each of the 64
  techniques = **full technique description** (navlayers `usage_generator.py:110,127`).
- Enterprise sizes with `include_description=False` (compact) — basis for R3's tool list:

  | tool (args) | compact bytes |
  |---|---|
  | `get_objects_modified_after("2025-06-01")` | 7,008,592 |
  | `get_objects_created_after("2025-01-01")` | 1,998,221 |
  | `get_all_subtechniques` | 209,687 |
  | `get_all_software` | 208,045 |
  | `get_all_techniques` | 205,660 |
  | `get_software` | 195,358 |
  | `get_techniques_by_platform("Linux")` | 91,727 |
  | `get_group_techniques` / `get_techniques_used_by_group` (G1015) | ~77,000 (rel. text incl.) |
  | `get_all_parent_techniques` | 65,835 |
  | `get_all_groups` | 62,134 |
  | `get_techniques_used_by_software(S0154)` | 56,052 (rel. text incl.) |
  | `get_objects_by_type("intrusion-set")` | 51,254 (unbounded for other types) |
  | `get_revoked_techniques` | 39,030 |
  | `get_all_datacomponents` | 35,183 |
  | `get_groups_using_software(S0154)` | 26,641 (rel. text incl.) |
  | `get_techniques_used_by_campaign(C0027)` | 23,413 (rel. text incl.) |
  | `get_techniques_by_tactic("Execution")` | 18,432 |
  | `get_all_campaigns` | 15,795 |
  | `get_software_using_technique(T1059)` | 15,632 (rel. text incl.) |
  | `get_groups_using_technique(T1059)` | 14,874 (rel. text incl.) |
  | `search_techniques("powershell")` | 12,168 |
  | `get_all_mitigations` / `get_techniques_targeting_asset` | 11,708 / 11,415 |
  | `get_campaigns_using_technique(T1078)` | 9,959 |
  | everything else | < 9,000 (`get_all_tactics` 4,173, `get_all_matrices` 424, `get_all_datasources` 165) |

  With `include_description=True` the larger ones are 4-10× bigger (e.g. `get_all_techniques`
  2.2 MB, `get_techniques_by_platform` 1.05 MB, `get_techniques_by_tactic` 217 KB).
- The MCP SDK returns each tool result twice (pretty-printed text content **and**
  `structured_content`), so wire size ≈ 2× the numbers above. Not changeable here (non-goal).
- Defaults of `include_description` are inconsistent today: of 57 tools with the flag, 14 default
  False and 43 True.
- `get_objects_created_after("2025-01-01")` returns objects with no ATT&CK ID and/or no name
  (relationships, analytics, detection strategies) → any sort key must be None-safe.

### F3. `include_description=False` audit (problem 3)

Called every tool with `include_description=False` and scanned the result for non-empty
`*description*` strings. Leaks:

| Tool | Leak |
|---|---|
| `get_technique_by_id` (:472, :531) | `technique.description` always full (reported bug) |
| `get_datacomponents_detecting_technique` (:7185) | `technique.description` truncated to 120 chars instead of null |
| 12 relationship tools | `<items>[].relationships[].description` always full: `get_group_techniques`, `get_techniques_used_by_group`, `get_software_used_by_group`, `get_groups_using_technique`, `get_groups_using_software`, `get_groups_attributing_to_campaign`, `get_software_using_technique`, `get_techniques_used_by_software`, `get_campaigns_using_technique`, `get_techniques_used_by_campaign`, `get_campaigns_using_software`, `get_software_used_by_campaign` |

All other tools honour the flag in both structured data and `formatted`. No existing test asserts
on `relationships` or on default descriptions of these tools (checked `tests/`).

### F4. Group technique provenance (problem 4)

- Library `get_techniques_used_by_group` (MAD:1497) = direct `uses` + techniques of campaigns
  `attributed-to` the group (`add_inherited_campaign_relationships` :1140), then
  `remove_duplicates` (:1185) merges relationships per technique. For an inherited entry the
  relationships are `[campaign uses technique, campaign attributed-to group]`.
- G1015 (`intrusion-set--44d37b89-a739-4810-9111-0d2617a8939b`): 78 unique techniques =
  **50 direct only + 14 direct and via campaign + 14 via campaign only** (all via C0027).
  Direct = 64 = today's `generate_layer("G1015")` count (UsageLayerGenerator uses direct `uses`
  only, `usage_generator.py:73-91`). No revoked/deprecated techniques in the result.
- Provenance is derivable per entry: direct ⇔ a `uses` relationship with `source_ref == group`;
  campaigns ⇔ `uses` relationships whose `source_ref` starts `campaign--`.

### F5. Layers (problem 5)

- `generate_layer` (:8427) rejects `atlas` and anything not `^[GMSD]\d+$`. The `D` branch never
  matches a real ID (data components are `DC####`, data sources `DS####`); `D0032` → "Failed to
  generate layer". It re-reads the STIX file from disk on every call (`UsageLayerGenerator(source=
  "local", resource=...)`) and the navlayers code `print()`s warnings to **stdout**
  (`usage_generator.py:42,66,146`, `core/exceptions.py:48`) — stdout is the MCP stream.
- Current counts to preserve: M1036 = 12, S0154 = 73 (G1015 = 64 direct; 78 with campaigns).
- Navigator layer format v4.5 (https://github.com/mitre-attack/attack-navigator/blob/master/layers/spec/v4.5/layerformat.md):
  required `name`, `domain` ∈ {`enterprise-attack`,`mobile-attack`,`ics-attack`};
  `versions.layer` = "4.5", `versions.navigator` ≥ "4.9.0", `versions.attack` optional; technique
  entry needs only `techniqueID`; **omitting `tactic` applies the annotation under every tactic**
  of the technique; `score`, `color`, `comment`, `enabled`, `metadata`, `showSubtechniques` optional.
- navlayers `LayerObj.domain` setter only accepts the three ATT&CK domains
  (`core/layerobj.py:109`) → ATLAS layers must be built as plain dicts.
- **Validator caveat:** `mitreattack.navlayers.Layer(init_data=d, strict=True).layer` never
  returns None. On failure it prints to **stdout** via `handler` and the `layer` property returns
  the string `"No Layer Loaded Yet!"` (`navlayers/core/layer.py:31-35`, `_build` :89-114). A valid
  check is `isinstance(Layer(init_data=d, strict=True).layer, _LayerObj)` (`from
  mitreattack.navlayers.core.layerobj import _LayerObj`) **and** nothing captured on stdout
  (pytest `capsys`). The validator also rejects technique IDs not starting with `"T"`
  (`navlayers/core/technique.py:44-47`, so ATLAS layers are validated with the `AML.` prefix
  stripped, Task 6(b)) and gradients with non-int bounds or a range < 2
  (`navlayers/core/gradient.py:56,67`, hence the D4 bounds rule).
- ATLAS Navigator format — from MITRE's published default layers
  `mitre-atlas/atlas-navigator-data` `dist/default-navigator-layers/atlas_layer_matrix.json` and
  `atlas_case_study_frequency.json` (same repo our ATLAS STIX bundle is pinned from, server.py:30):
  `"domain": "atlas-atlas"`, `"versions": {"layer": "4.3", "navigator": "4.6.4"}` (no `attack`),
  entries `{"techniqueID": "AML.T0000", "tactic": "reconnaissance", "score"|"color",
  "showSubtechniques": true}`, sub-techniques `{"techniqueID": "AML.T0000.000", ...}` without
  tactic. Their 16 tactic values equal the 16 `x_mitre_shortname`s in our pinned bundle.
- Live ATLAS Navigator config (`https://mitre-atlas.github.io/atlas-navigator/assets/config.json`,
  fetched 2026-11-05): version `"4"` ("ATLAS v4") has domain "ATLAS" (data
  `atlas-navigator-data/main/dist/stix-atlas.json`) and domain "ATLAS + ATT&CK Enterprise v15.1"
  with `identifier: "atlas-atlas"` (data `.../main/dist/stix-atlas-attack-enterprise.json`). Data
  comes from the **deprecated** `atlas-navigator-data` main branch (project moved to
  `mitre-atlas/atlas-data` releases). A load test in the live ATLAS Navigator is **not
  executable here** (sandbox blocks browsers) → automated structural acceptance (Task 6) instead.
- `get_layer_metadata` (:8567) hard-codes `"attack": "16"`; data is v20.0
  (`release_info.LATEST_VERSION == "20.0"`).
- MCP SDK schema check: a parameter typed `List[Union[str, Dict[str, Any]]]` produces
  `items.anyOf[string, object]` and accepts mixed lists; `Optional[int] = None` accepts JSON null.

### F6. Extra bugs found during the audit

- **B6 (in scope, Task 3):** `get_techniques_used_by_group_software` (:2869) always returns 0.
  The library method (MAD:736) returns plain `Technique` objects, not wrappers; the tool reads
  `getattr(entry, "object", None)` (:2970-2981) → None → every entry skipped. G1015: library 120
  (all active, 120 unique IDs), tool 0; G0016: library 205. Anchor verified: G1015 uses Mimikatz
  (S0002) and the library result contains **T1003.001** (LSASS Memory); it does not contain T1003.
- **Out of scope (follow-up):** `get_procedure_examples_by_tactic` (:7695) calls
  `attack_data.get_procedure_examples_by_tactic` (:7774), which does not exist on
  `MitreAttackData`; the `AttributeError` is swallowed → always 0.

## Design decisions

- **D1 Detection via detection strategies (problem 1).** Add lazy, per-instance index methods on
  `_MitreData` (cache attribute `_mcp_detection_index`, built from `get_analytics(
  remove_revoked_deprecated=True)` and `get_detectionstrategies(remove_revoked_deprecated=True)`).
  All ID reads use `_field(obj, "id")` / `obj["id"]` — never `.id` (analytics from
  `get_analytics_by_detection_strategy` are plain dicts, F1):
  - `analytics_by_id`, `dets_by_analytic` (analytic → [DET stix]), `analytics_by_dc`
    (data component → [analytic stix]) from `x_mitre_log_source_references`
    (skip entries without `x_mitre_data_component_ref`, tolerate `None` lists).
  - `detection_chain_for_technique(tech_stix_id) -> list[dict]`: DETs from the library's
    `get_detection_strategies_detecting_technique` (unwrap), each with its analytics (from
    `analytics_by_id`) and their log-source refs.
  - `techniques_for_datacomponent(dc_stix_id) -> list[(technique, [DET stix], [AN stix])]`:
    DC → analytics → DETs → `get_techniques_detected_by_detection_strategy` (unwrap), **drop
    revoked/deprecated techniques** (`x_mitre_deprecated` / `revoked`; defensive even though
    `get_related` filters targets), dedupe by technique id.
  Tools:
  - `get_datacomponents_detecting_technique`: order = legacy `detects` relationships (unchanged,
    pre-v18 data) → **detection-strategy chain only if that returned nothing** →
    `x_mitre_data_sources` fallback (unchanged, only if still empty).
    `debug.query_mode = "detection_strategy_analytics"` for the new path. Each data component entry
    keeps all current keys and adds `attack_id` (DC####), `detection_strategies` ([DET####]),
    `analytics` ([AN####]), `log_sources` ([{name, channel}], deduped). Stays sync.
  - `get_techniques_detected_by_datacomponent`: library wrapper path first; **the chain runs only
    when the wrapper path returns `[]`; results are never merged** (keeps
    `test_relationship_tools.py:141-153` → `count == 1`). Each chain-derived technique adds
    `detection_strategies`, `analytics`; wrapper-derived ones get `[]` for both.
  - Both accept an ATT&CK ID as well as a STIX ID (arg without `--` → resolve via
    `get_object_by_attack_id` with `attack-pattern` / `x-mitre-data-component`). Additive.
  - New tool `get_detection_strategies_for_technique(technique_id, domain="enterprise",
    platform=None, include_description=False)`: technique ATT&CK or STIX ID → `{technique,
    count, detection_strategies: [{attack_id, name, stix_id, analytics: [{attack_id, name,
    stix_id, platforms, log_sources: [{data_component_attack_id, data_component_name,
    data_component_stix_id, name, channel}], mutable_elements?, description?}]}], formatted,
    message}`. `platform` filters analytics by `x_mitre_platforms` (case-insensitive);
    `mutable_elements` and analytic `description` only when `include_description=True`. ATLAS /
    data without detection strategies → count 0 with a clear message.
  Rejected: (a) only adding the new tool and leaving the two broken tools documented as legacy —
  the reported tools would still return nothing; (b) building the index at load time — adds
  startup cost to every domain for a rarely used path.
- **D2 Description flag (problem 3).** `include_description=False` means no object description
  anywhere in the result: fix `get_technique_by_id` (`technique.description` → None) and
  `get_datacomponents_detecting_technique` (no 120-char teaser → None). Relationship descriptions
  are procedure text, not object descriptions; they are governed by the new
  `include_relationships` flag (D5), not by `include_description`. Single-object reads switch from
  `getattr(...)` to `_field(...)` at the touched lines.
- **D3 Group provenance (problem 4).** Module-level helper `_group_technique_provenance(attack_data,
  group_stix_id, entry) -> {"direct": bool, "via_campaigns": [C####, ...]}` (campaign ATT&CK IDs
  sorted, resolved via `get_attack_id`). `get_group_techniques` and `get_techniques_used_by_group`
  add per-technique `direct`, `via_campaigns`, response-level `direct_count`,
  `campaign_only_count`, and parameter `include_campaigns: bool = True` (owner decision; False →
  only `direct is True` entries; G1015 → 64). Messages state the split, e.g. "78 technique(s): 64
  direct, 14 only via campaigns (C0027)". `generate_layer` gets the same parameter and default
  (Task 7), so tool and layer agree.
- **D4 Technique layers (problem 5).** One pure module-level builder
  `_build_navigator_layer(domain, name, description, entries) -> dict` (no navlayers objects → no
  stdout prints): ATT&CK domains → `domain: "<d>-attack"`, `versions: {"attack": <major of
  release_info.LATEST_VERSION>, "navigator": "5.1.0", "layer": "4.5"}`; ATLAS → `domain:
  "atlas-atlas"`, `versions: {"layer": "4.3", "navigator": "4.6.4"}`, no `attack` key (mirrors
  MITRE's published ATLAS layers). Entries carry `techniqueID`, optional `score`/`color`/`comment`,
  **no `tactic`** (spec: applies to all tactics — fixes multi-tactic techniques). Entry keys are
  always ⊆ {`techniqueID`, `tactic`, `score`, `color`, `comment`, `showSubtechniques`, `enabled`}.
  Parent handling:
  - a listed parent that has ≥1 listed sub-technique gets `showSubtechniques: true`;
  - a sub-technique whose parent is not listed causes an **auto-added** parent entry
    `{"techniqueID": parent, "showSubtechniques": true}` (no score/colour/comment).
  - **`count` and `technique_ids` cover the selected techniques only; auto-added parents are
    excluded** (so G1015 stays 78, M1036 12, S0154 73). Response adds `auto_added_parents: [...]`.
  If any score: `gradient {colors: ["#ff6666ff","#ffe766ff","#8ec843ff"], minValue, maxValue}`
  with **int** bounds: `minValue = min(0, math.floor(min score))`,
  `maxValue = max(math.ceil(max score), minValue + 2)`. Reason (cycle-2 review): navlayers
  `Layer(strict=True)` rejects gradients with range < 2 ("Unsupported negative number of
  colors") and non-int bounds (`navlayers/core/gradient.py:56,67`); measured (0,1) fails,
  (0,2) passes.
  New tool `generate_technique_layer(techniques: List[Union[str, Dict[str, Any]]], domain=
  "enterprise", name="Custom layer", description="", default_score: Optional[float] = 1,
  save_to_file: bool = False)`. Item = ID string, or dict with `technique_id` (alias
  `techniqueID`) and optional `score` (int/float, **`bool` rejected**), `color`
  (`^#[0-9A-Fa-f]{6}$`), `comment` (str ≤ 2000 chars). 1-2000 items. IDs are trimmed and
  upper-cased (`t1059` → `T1059`, `aml.t0051` → `AML.T0051`), then resolved with
  `get_object_by_attack_id(id, "attack-pattern")` in the domain; unknown → `unknown_ids`,
  revoked/deprecated → `skipped` (not in layer); duplicate IDs → last wins + `warnings`. Invalid
  item → `success: False` with message naming the item index. Response `{success, domain, count,
  technique_ids, auto_added_parents, unknown_ids, skipped, warnings, layer | None, layer_path |
  None, message}`.
- **D5 Size control (problem 2), applied by rule, not per tool:**
  - Rule R1: tools that return a **list** default `include_description=False`; single-object
    lookups (`get_technique_by_id`, `get_object_by_attack_id`, `get_object_by_stix_id`,
    `get_group_by_name`, `get_parent_technique_of_subtechnique`) and the procedure-example tools
    (where the description *is* the payload) keep `True`. **Breaking (defaults).**
  - Rule R2: the 12 relationship tools of F3 gain `include_relationships: bool = False`. False →
    the `relationships` key is omitted; True → the list as today (with relationship descriptions).
    Group tools keep provenance fields (D3) regardless. **Breaking (key omitted by default).**
    Shared helper `_relationships_info(rels) -> list[dict]` replaces the 12 duplicated blocks at
    those sites only. `get_techniques_used_by_group_software` does **not** get
    `include_relationships` (the library returns no relationships, B6) and drops its always-empty
    `relationships` key (documented in CHANGELOG).
  - Rule R3: pagination `limit: Optional[int] = None, offset: int = 0` **only on tools whose
    compact output (after R1/R2) can exceed ~50 KB** (F2 table):
    `get_objects_modified_after`, `get_objects_created_after`, `get_all_subtechniques`,
    `get_all_software`, `get_all_techniques`, `get_software`, `get_techniques_by_platform`,
    `get_all_parent_techniques`, `get_all_groups`, `get_objects_by_type`,
    `get_group_techniques`, `get_techniques_used_by_group`, `get_techniques_used_by_software`,
    `get_techniques_used_by_group_software` (120+ entries).
    Not paginated (compact < 40 KB): `get_all_tactics`, `get_all_matrices`, `get_all_datasources`,
    `get_all_datacomponents`, `get_all_campaigns`, `get_all_mitigations`, `get_all_assets`,
    `get_revoked_techniques`, search/alias tools, the remaining relationship tools.
    Helper `_paginate(items, limit, offset) -> (page, meta)`; meta = `{"total", "returned",
    "offset", "limit", "has_more"}` merged into the response. `count` keeps its meaning =
    **total** matches (backwards compatible); `formatted` covers only the page. `limit` None → no limit,
    `limit <= 0` → no items (count probe); `offset < 0` → 0.
    Ordering: in each paginated tool the full item list is sorted **before slicing and before
    `formatted` is built**, with the None-safe key
    `(aid is None, aid or "", name or "", stix_id or "")` where `aid` = ATT&CK ID. Sorting applies
    even when `limit=None` → **output order changes for these 14 tools (CHANGELOG "Changed")**.
    Default `limit=None` everywhere **except** `get_objects_created_after` /
    `get_objects_modified_after` → default `limit=100` (**Breaking**; default output is 2-19 MB).
  - Rule R4: layers — `generate_layer` and `generate_technique_layer` take `save_to_file: bool =
    False`. True → write layer JSON under `LAYER_DIR` and return `layer: None`,
    `layer_path: "<abs path>"`, plus the summary. Path safety:
    - `LAYER_DIR = Path(os.getenv("MITRE_MCP_LAYER_DIR", Path.home() / f".{APP_NAME}" / "layers"))
      .expanduser().resolve()` (new constant; tests monkeypatch `server.LAYER_DIR`).
    - `slug = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip(".-")[:80] or "layer"`; filename
      `f"{slug}-{UTC %Y%m%dT%H%M%SZ}.json"` (numeric suffix `-1`, `-2`… on collision) → ≤ ~110
      bytes, well under the 255-byte limit.
    - `LAYER_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)` — the mode applies only when the
      directory is created (an existing directory keeps its permissions; intermediate parents get
      the umask default).
    - `path = LAYER_DIR / filename`; explicit check
      `if path.resolve().parent != LAYER_DIR: return {"success": False, ...}` (not `assert`,
      which `python -O` strips); write with `open(path, "x")` (never overwrite).
    No client-chosen path (avoids an arbitrary-file-write primitive for a model-driven client).
    `generate_layer` comments: `include_comments: bool = False` → only short provenance comments
    ("via campaign C0027"); True → technique description + provenance (old behaviour).
    **Breaking (comments default).**
  Rejected: (a) a global response-size guard/truncation decorator — silently loses data and
  breaks JSON shapes; (b) removing `formatted` — big compatibility break; with R1 it is small
  (8 KB for G1015); (c) per-tool ad-hoc fixes — inconsistent for clients; (d) paginating every
  list tool — adds parameters and a sort-order change where output is already small.
- **D6 `generate_layer` rework (Task 7).** Build on loaded `attack_data` + `_build_navigator_layer`
  instead of `UsageLayerGenerator`: `G` → `get_techniques_used_by_group` + D3 provenance (respects
  `include_campaigns`, default True — G1015 becomes 78, campaign-only entries commented "via
  campaign C0027"); `M` → `get_techniques_mitigated_by_mitigation`; `S` →
  `get_techniques_used_by_software`; `DC####` → D1 `techniques_for_datacomponent`. Accept
  `^(G|M|S)\d{4}$|^DC\d{4}$`; `T…` error message points to `generate_technique_layer`; the atlas
  error says "generate_layer does not support ATLAS; use generate_technique_layer(domain=
  \"atlas\")" — valid because Task 6 always ships (D7). Keep the response shape and
  `name`/`description` strings (`"<name> (<stix id>)"`, `"Enterprise techniques used by <name>,
  ATT&CK <type> <id>"`). `count` excludes auto-added parents (D4). Removes the stdout-print risk
  and the per-call file reparse. Layer entries lose `tactic` (spec default = all tactics).
  **Behaviour change**, listed in CHANGELOG.
- **D7 ATLAS layers: automated acceptance (replaces manual load).** Domain value and versions are
  taken from MITRE's published ATLAS layers and match the live ATLAS Navigator config identifier
  (F5). Task 6 ships when the automated checks (a)-(d) in Task 6 pass. README states that the
  format mirrors MITRE's published ATLAS layers and was **not load-tested** in the live ATLAS
  Navigator, which serves data from the deprecated `atlas-navigator-data` main branch, so
  technique IDs newer than that data may be ignored. Loading a generated ATLAS layer and an
  enterprise layer in the Navigators is an **optional owner post-release check**.
  `get_layer_metadata("atlas")` returns the ATLAS template (Task 6); its ATT&CK `attack` version
  is fixed to the real release in Task 5.
- **D8 Docs / version.** 0.4.0 in **7 places**: `pyproject.toml:3`,
  `src/mitre_mcp_server/__init__.py:4`, `package.json:3`, `server.json:9` and `:14`,
  `uv.lock:662` (editable package entry), `README.md:12` ("Version: 0.3.0"). CHANGELOG 0.4.0 with a
  **"Breaking"** heading. README: tool count 65 → 67, detection limitation removed, layer section,
  size/pagination behaviour notes, `MITRE_MCP_LAYER_DIR`, ATLAS layer note (D7).

## Non-goals

- `get_procedure_examples_by_tactic` (F6) — separate follow-up plan.
- Removing the pre-v18 code paths (legacy `detects`, `x_mitre_data_sources` fallback).
- Changing the SDK's double serialization (F2) or removing `formatted`.
- New tools for detection strategies by DET ID / analytics by AN ID.
- Upgrading the pinned ATLAS release or fetching ATLAS layers at runtime.
- Pagination on tools whose compact output is < ~40 KB (D5 R3).
- Refactoring tools not named in a task.

## Test setup

- Run: `.venv/bin/python -m pytest -q` (not `uv run`). Fixtures: `tests/conftest.py`
  (`atlas_loaded`, `needs_atlas`). Mobile/ICS tests `pytest.skip` when the cache file is missing
  (same style as existing ICS tests).
- New files: `tests/test_detection.py`, `tests/test_description_flag.py`,
  `tests/test_group_provenance.py`, `tests/test_layers.py`, `tests/test_output_size.py`,
  `tests/test_version.py`.
- Layer validator helper in `tests/test_layers.py`:
  `_assert_valid_attack_layer(layer, capsys)` → `capsys.readouterr()` (drain), then
  `obj = Layer(init_data=layer, strict=True).layer`; assert `isinstance(obj, _LayerObj)` (`from
  mitreattack.navlayers import Layer`, `from mitreattack.navlayers.core.layerobj import
  _LayerObj`) and `capsys.readouterr().out == ""`. Never assert `... is not None` (F5).
- Layer-file tests monkeypatch `server.LAYER_DIR` to `tmp_path.resolve()`.

## Tasks

### Task 1 — detection strategies chain (problem 1, D1)
- [ ] Add the `_MitreData` index methods (D1; `_field`/`["id"]` only; revoked/deprecated
      techniques dropped in `techniques_for_datacomponent`); index built once (cache attr).
- [ ] Rework `get_datacomponents_detecting_technique` and `get_techniques_detected_by_datacomponent`
      per D1 (chain only when earlier path is empty, never merged; ATT&CK-ID or STIX-ID input;
      new keys; existing keys unchanged).
- [ ] Add tool `get_detection_strategies_for_technique` (D1).
- [ ] Tests: `get_detection_strategies_for_technique("T1552.005")` → 1 strategy `DET0001`, analytic
      `AN0001` platforms `["IaaS"]`, log-source DC IDs == {DC0082, DC0070, DC0085};
      `platform="Windows"` → 0 analytics; ATT&CK ID and STIX ID inputs give equal results.
- [ ] Tests: `get_datacomponents_detecting_technique(<T1552.005 stix>)` → count 3, attack_ids
      {DC0082, DC0070, DC0085}, each `detection_strategies == ["DET0001"]`,
      `debug.query_mode == "detection_strategy_analytics"`.
- [ ] Tests: `get_techniques_detected_by_datacomponent("DC0070")` → count > 0, T1552.005 present
      with `detection_strategies` containing DET0001; no entry is revoked/deprecated; existing
      monkeypatch test (`test_relationship_tools.py:141-153`, `count == 1`) still passes.
- [ ] Tests: mobile and ics — some technique with a DET returns ≥ 1 strategy (skip if cache
      missing); atlas (`needs_atlas`) → count 0, no exception.
- [ ] Run tests — must pass.

### Task 2 — description flag consistency (problem 3, D2)
- [ ] Fix `get_technique_by_id` (description None when False; use `_field`).
- [ ] Fix `get_datacomponents_detecting_technique` technique teaser → None when False.
- [ ] Tests (`test_description_flag.py`): helper that walks a result and collects non-empty
      `*description*` strings, ignoring paths under `relationships`; parametrize over
      `get_technique_by_id("T1059")`, `get_object_by_attack_id`, `get_object_by_stix_id`,
      `get_datacomponents_detecting_technique`, `get_group_techniques("Scattered Spider")`,
      `get_mitigations_mitigating_technique`, `get_subtechniques_of_technique` with
      `include_description=False` → empty; and `"Description:" not in formatted`.
- [ ] Test: `get_technique_by_id("T1059", include_description=True)` → description non-empty.
- [ ] Run tests — must pass.

### Task 3 — techniques via group software (B6)
- [ ] Fix `get_techniques_used_by_group_software`: entries are plain techniques; filter
      revoked/deprecated (`attack_data.remove_revoked_deprecated`); dedupe by id; drop the
      always-empty `relationships` key (no `include_relationships` on this tool, D5 R2).
- [ ] Tests: G1015 STIX ID → count == number of unique active techniques from
      `server.get_attack_data("enterprise").get_techniques_used_by_group_software(...)` after the
      same filter (120 today); **anchor: `"T1003.001"` in the returned attack_ids** (via Mimikatz
      S0002, F6); every entry has `attack_id`/`name`/`stix_id`; no entry has `relationships`.
- [ ] Run tests — must pass.

### Task 4 — group technique provenance (problem 4, D3)
- [ ] Add `_group_technique_provenance`; wire into `get_group_techniques` and
      `get_techniques_used_by_group` with `include_campaigns` (default True), `direct_count`,
      `campaign_only_count`, message.
- [ ] Tests (`test_group_provenance.py`): G1015 default → count 78, `direct_count` 64,
      `campaign_only_count` 14, every campaign-only entry has `via_campaigns == ["C0027"]`,
      14 entries have `direct` True and non-empty `via_campaigns`;
      `include_campaigns=False` → count 64, all `direct`; both tools agree on the set of
      `attack_id`s for each flag value.
- [ ] Run tests — must pass.

### Task 5 — layer builder + `generate_technique_layer` for ATT&CK domains (problem 5, D4, R4)
- [ ] Add `LAYER_DIR` constant, `_build_navigator_layer`, `_save_layer` (R4 path safety), tool
      `generate_technique_layer` (enterprise/mobile/ics; `atlas` temporarily returns a clear error
      until Task 6, which always ships).
- [ ] `get_layer_metadata`: `versions.attack` from `release_info.LATEST_VERSION` major.
- [ ] Tests (`test_layers.py`), happy path: `["t1059", {"technique_id": "T1003.001", "score": 5,
      "color": "#ff0000", "comment": "x"}, "T9999"]` → count 2, `technique_ids ==
      ["T1059", "T1003.001"]` (lowercase input normalised), `unknown_ids == ["T9999"]`,
      `auto_added_parents == ["T1003"]` and T1003 entry has `showSubtechniques` but is not in
      `technique_ids`, no entry has `tactic`, `domain == "enterprise-attack"`,
      `versions.layer == "4.5"`; `_assert_valid_attack_layer(layer, capsys)`.
- [ ] Tests: listed parent with listed sub → `["T1059", "T1059.001"]` → T1059 entry has
      `showSubtechniques: true`, `auto_added_parents == []`, count 2.
- [ ] Tests, invalid input (separate calls): `[{"technique_id": "T1059", "color": "red"}]` →
      `success False`, message names index 0; `["T1059", {"technique_id": "T1003", "score":
      True}]` → `success False`, message names index 1 (bool score rejected); `[]` → `success
      False`.
- [ ] Tests: mobile and ics one ID each → validator passes (skip if cache missing).
- [ ] Test: all-default-score layer (`["T1059", "T1003"]`, `default_score=1`) → gradient
      `minValue == 0`, `maxValue == 2`, both `int`; `_assert_valid_attack_layer` passes.
- [ ] Tests, `save_to_file=True` (`LAYER_DIR` → `tmp_path.resolve()`): file exists, JSON equals the
      layer that would be returned, response `layer is None`; a second call with the same name
      creates a different file; `name="../../etc/passwd"` and `name="/abs/x"` → file's
      `resolve().parent == tmp_path.resolve()`; `name=""` → filename starts `layer-` and ends
      `.json`; `name="a" * 5000` → `len(filename.encode()) <= 255`.
- [ ] Test: `get_layer_metadata("enterprise")["metadata"]["versions"]["attack"]` ==
      `release_info.LATEST_VERSION.split(".")[0]` (`"20"` today).
- [ ] Run tests — must pass.

### Task 6 — ATLAS technique layers (D7, automated acceptance)
- [ ] Enable `domain="atlas"` in `generate_technique_layer` (ATLAS domain/versions per D4);
      `get_layer_metadata("atlas")` returns `{domain: "atlas-atlas", versions: {layer: "4.3",
      navigator: "4.6.4"}}` template (no `attack`, no platform filters).
- [ ] Update `tests/test_atlas.py:122-125` (metadata no longer rejected; assert the template).
- [ ] Acceptance tests (`needs_atlas`), input `["aml.t0051.000", "AML.T0000", "AML.T0051"]`:
      (a) `layer["domain"] == "atlas-atlas"`, `layer["versions"] == {"layer": "4.3", "navigator":
      "4.6.4"}`, `"attack" not in layer["versions"]`;
      (b) structure: `copy.deepcopy(layer)` with `domain = "enterprise-attack"`, versions
      `{"layer": "4.5", "navigator": "5.1.0"}`, and every `techniqueID` stripped of its `"AML."`
      prefix (`AML.T0051.000` → `T0051.000`; navlayers' `Technique.techniqueID` setter rejects IDs
      not starting with `"T"`, `navlayers/core/technique.py:44-47`) passes
      `_assert_valid_attack_layer`. Note this caveat in F5;
      (c) every `techniqueID` matches `^AML\.T\d{4}(\.\d{3})?$` and resolves in the pinned bundle
      (`server.get_attack_data("atlas").get_object_by_attack_id(id, "attack-pattern")`);
      (d) every entry's keys ⊆ {`techniqueID`, `tactic`, `score`, `color`, `comment`,
      `showSubtechniques`, `enabled`}.
      Also: AML.T0051 entry has `showSubtechniques: true`; `"T1059"` with `domain="atlas"` →
      `unknown_ids == ["T1059"]`.
- [ ] Run tests — must pass. Task ships when (a)-(d) pass.

### Task 7 — `generate_layer` on the shared builder (problems 4, 5, D6, R4)
- [ ] Re-implement per D6 with `include_campaigns: bool = True`, `include_comments: bool = False`,
      `save_to_file: bool = False`; drop `UsageLayerGenerator` import.
- [ ] Update `tests/test_atlas.py:116-118` to the new atlas message (mentions
      `generate_technique_layer`).
- [ ] Tests: `generate_layer("G1015")` count 78 and equals `get_group_techniques("Scattered
      Spider")` count (auto-added parents excluded); `include_campaigns=False` → 64; campaign-only
      entries have comment containing "C0027"; `M1036` → 12; `S0154` → 73; `DC0070` → count > 0
      and contains T1552.005; `T1059` → `success False` mentioning `generate_technique_layer`;
      default layer JSON < 15 KB for G1015 (was 102 KB); `include_comments=True` → comments
      contain technique descriptions; `_assert_valid_attack_layer` passes for G1015, M1036, S0154.
- [ ] Run tests — must pass.

### Task 8 — size control for relationship tools (problem 2, R1, R2, R3 part 1)
- [ ] Add `_relationships_info` and `_paginate` (None-safe sort key, sort before slicing and before
      `formatted`).
- [ ] Apply `include_relationships` (R2) and R1 default flip to the 12 relationship tools of F3;
      R1 flip also on `get_campaigns_attributed_to_group` and
      `get_techniques_used_by_group_software`.
- [ ] Apply `limit`/`offset` (R3) to `get_group_techniques`, `get_techniques_used_by_group`,
      `get_techniques_used_by_software`, `get_techniques_used_by_group_software`. Paginate after
      provenance/`include_campaigns` filtering; `direct_count` etc. computed on the full set.
- [ ] Existing tests: none depend on `relationships` or on these defaults (F3); re-run the full
      suite.
- [ ] Tests (`test_output_size.py`): `get_group_techniques("Scattered Spider")` default JSON
      < 30 KB (was 317 KB), no `relationships` key, `count == total == 78`;
      `include_relationships=True` → every entry has `relationships`; `limit=10, offset=70` →
      `returned == 8`, `has_more False`, `formatted` has 8 entries; pages 0-9 and 10-19 disjoint
      and stable across calls; with `limit=None` the order is sorted by attack_id.
- [ ] Run tests — must pass.

### Task 9 — size control for catalogue tools (problem 2, R1, R3 part 2)
- [ ] R1 default flip on: `get_objects_by_content`, `get_techniques_by_tactic`,
      `search_techniques`, `search_groups`, `search_software`, `get_groups_by_alias`,
      `get_software_by_alias`, `get_campaigns_by_alias`, `get_all_mitigations`, `get_all_tactics`,
      `get_all_matrices`, `get_all_campaigns`, `get_all_datasources`, `get_all_datacomponents`,
      `get_all_assets`, `get_assets_targeted_by_technique`, `get_techniques_targeting_asset`,
      `get_techniques_by_platform`, `get_techniques_detected_by_datacomponent`,
      `get_revoked_techniques`, `get_objects_created_after`, `get_objects_modified_after`.
- [ ] R3 `limit`/`offset` on: `get_objects_modified_after`, `get_objects_created_after` (both
      default `limit=100`), `get_all_subtechniques`, `get_all_software`, `get_all_techniques`,
      `get_software`, `get_techniques_by_platform`, `get_all_parent_techniques`, `get_all_groups`,
      `get_objects_by_type`.
- [ ] Update `tests/test_revoked_filters.py:82-87` (`can_include_revoked`) to pass `limit=None`.
- [ ] Tests: `get_all_techniques(limit=5)` → `returned 5`, `count == total` = unpaginated count,
      `has_more True`; `get_objects_modified_after("2025-06-01T00:00:00Z")` default → `returned
      <= 100` and JSON < 300 KB; `limit=None` restores full count;
      `get_objects_by_type("relationship", limit=50, offset=0)` and `offset=50` → no exception
      (None-safe key), 50 each, disjoint stix_ids; `get_objects_created_after(
      "2025-01-01T00:00:00Z", limit=None)` → no exception; atlas
      `get_all_techniques(domain="atlas", limit=3)` works (`needs_atlas`).
- [ ] Run tests — must pass.

### Task 10 — docs and version 0.4.0 (D8)
- [ ] Bump to 0.4.0 in all 7 places (D8).
- [ ] CHANGELOG `[0.4.0] - <date>`:
      **Breaking** — R1 description defaults (list tools), `relationships` opt-in
      (`include_relationships`), `generate_layer` comments off by default / no `tactic` / group
      layers include campaign techniques by default (G1015 64 → 78), time-based tools default
      `limit=100`, `get_techniques_used_by_group_software` no longer has a `relationships` key;
      **Added** — `get_detection_strategies_for_technique`, detection chain in the two detection
      tools, ATT&CK-ID input for them, provenance fields + `include_campaigns`,
      `generate_technique_layer` (incl. ATLAS), `get_layer_metadata("atlas")`, pagination,
      `save_to_file`, `MITRE_MCP_LAYER_DIR`;
      **Changed** — paginated tools return items sorted by ATT&CK ID even without `limit`;
      `generate_layer` built from loaded data, `generate_layer` accepts `DC####`;
      **Fixed** — B6, `get_technique_by_id` description, detection tools on v18+, `generate_layer`
      `D` prefix, `get_layer_metadata` attack version, no navlayers stdout output from layer tools.
- [ ] README: version line, tool count 67, remove the v18 detection limitation, add
      detection-strategy and layer rows, behaviour notes (description defaults, relationships,
      pagination + ordering, provenance, layer files), Configuration row for
      `MITRE_MCP_LAYER_DIR`, ATLAS support table (layers) with the D7 note, known limitation for
      `get_procedure_examples_by_tactic`.
- [ ] Test (`test_version.py`): `server.__version__ == "0.4.0"` and equals
      `tomllib.load(pyproject.toml)["project"]["version"]`.
- [ ] Run tests — must pass.

## Verification

- Full suite green; report counts (baseline 52).
- Re-run the F2 size probe: G1015 tool default < 30 KB, layer default < 15 KB.
- Re-run the F3 audit: no description leaks with `include_description=False`.
- Optional owner post-release checks (not executable in the sandbox): load one generated
  enterprise layer in https://mitre-attack.github.io/attack-navigator/ and one ATLAS layer in
  https://mitre-atlas.github.io/atlas-navigator/.
- Then (main session): commit, Trivy
  (`trivy fs --skip-db-update --scanners vuln,secret,misconfig --skip-dirs .venv --skip-dirs .ruff_cache .`),
  push `fork main`, tag `v0.4.0`.

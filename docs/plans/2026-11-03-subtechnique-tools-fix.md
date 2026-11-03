# Plan: fix relationship-wrapper unwrap bugs and ATLAS parent techniques

Revision 2 (after plan review cycle 1). Status: APPROVED (cycle 2).

Implementation notes from approval review:
- N1 (Task 5): don't use a bare stub. `monkeypatch.setattr` only
  `get_techniques_detected_by_datacomponent` on the real `server.get_attack_data("enterprise")`
  instance; pass a real data-component STIX ID.
- N2 (D1): `_unwrap_mitigation` is nested (~server.py:7051). Add module-level `_unwrap` next to
  `_field` (~server.py:373). Don't refactor the 15 already-correct sites.
- N3 (Task 6): baseline via `server.get_attack_data("enterprise").get_techniques(
  include_subtechniques=False, remove_revoked_deprecated=True)`, not a fresh `MitreAttackData`.
- N4 (Task 1/C): keep per-technique parent lookup; test asserts every entry has a parent.

## Problem (verified 2026-11-03 by calling the tools / library)

Library relationship helpers in `MitreAttackData` return lists of wrapper entries
`{"object": <STIX obj>, "relationships": [<Relationship>]}` (a `RelationshipEntry`). Several
tools treat each entry as the object itself → crash, or every field `None`, and raw wrappers
are passed to `format_objects`. Affected (server.py line numbers pre-change, re-grep):

| # | Tool | Site | Symptom |
|---|---|---|---|
| A | `get_subtechniques_of_technique` | ~6800-6831 | `AttributeError: 'dict' object has no attribute 'id'` (all domains) |
| B | `get_parent_technique_of_subtechnique` | ~6685-6702 | treats returned list as a STIX ID → `TypeError: unhashable type: 'list'` (all domains) |
| C | `get_all_subtechniques` | ~4332, 4351-4356 | `parent_obj` is a list → `parent_attack_id/name/stix_id` None (all domains) |
| D | `get_campaigns_attributed_to_group` | ~2704, 2723-2731, ~2751 | every field None (G0007); formatted gets wrappers |
| E | `get_techniques_mitigated_by_mitigation` | ~6918, 6944-6946 | all entries null (M1036; atlas too) |
| F | `get_techniques_targeting_asset` | ~5722, 5744, ~5755 | `AttributeError` (ics) |
| G | `get_assets_targeted_by_technique` | ~5626, 5648-5656 | 9 entries all null (ics T0800) |
| H | `get_techniques_detected_by_datacomponent` | ~7491, 7512-7516 | same pattern (cannot reproduce on v18+ data: no detects links) |

Sites already correct (no change): 1553, 2336, 2520, 2946, 3134, 3333, 3522, 3834, 4030, 5852,
6040, 6244, 6431, 7035 (`_unwrap_mitigation`), 7204. Procedure-example helpers return plain
`Relationship` objects (MAD:668) — fine.

Separate bug I: `get_all_parent_techniques` (server.py:4419) calls
`get_techniques(remove_revoked_deprecated=...)` (~4459) then skips any `attack_id` containing
`.` (~4497). Every ATLAS ID (`AML.T0051`) contains `.` → 0 results for atlas (should be 101).
Enterprise returns 227.

## Design

- D1. One small helper `_unwrap(entry)` → `entry.get("object", entry)` if dict-like with an
  `"object"` key, else entry (matches existing pattern at ~3333). Each affected tool unwraps
  its list once, reads fields via `_field()`, and passes the **unwrapped** list to
  `format_objects`. If an existing local helper (e.g. `_unwrap_mitigation`) already does
  this generically, reuse/generalise it instead of adding a new one.
- D2. Tool B: `entries = get_parent_technique_of_subtechnique(stix_id)`; empty list → current
  "not a subtechnique / not found" response; else parent = `_unwrap(entries[0])`, take
  `id`/name/attack_id from it; drop the extra `get_object_by_stix_id` lookup.
- D3. Bug I: in `get_all_parent_techniques` replace the `"." in attack_id` filter with
  `_field(t, "x_mitre_is_subtechnique") is not True`. No `_MitreData` override.
- D4. Output shapes of all tools stay as their docstrings promise.
- D5. Docs: README atlas "Returns data" row already lists A, B, C, E, parents — correct after fix.
  CHANGELOG 0.3.0 "Fixed": one bullet listing tools A-H (relationship results returned
  null/crashed) and one for atlas parent techniques. No version bump (0.3.0 unreleased).

## Test setup

- Move the `needs_atlas` marker from `tests/test_atlas.py:7` into `tests/conftest.py`
  (export it; update test_atlas.py to import/use it) so new test files can use it.
- ICS data cached at `~/.mitre-mcp-server/data/v20.0/ics-attack.json`; ics tests
  `pytest.skip` if missing (same style as enterprise tests).
- New file `tests/test_relationship_tools.py`.
- Run: `.venv/bin/python -m pytest -q` (not `uv run`).

## Tasks

### Task 1 — sub-technique/parent tools (A, B, C) + helper D1
- [ ] Implement D1 helper, fix A, B (D2), C.
- [ ] Tests: enterprise `get_subtechniques_of_technique(<T1059 stix>)` count > 0, every entry
      non-null `attack_id` starting `T1059.` and `name`, `formatted` contains a sub-technique
      name; atlas AML.T0051 → attack_ids include `AML.T0051.000/.001/.002`.
- [ ] Tests: `get_parent_technique_of_subtechnique(<T1059.001 stix>)` → T1059; atlas
      AML.T0051.000 → AML.T0051; a parent technique's stix id → not-a-subtechnique response.
- [ ] Tests: `get_all_subtechniques` enterprise and atlas — every entry has non-null
      `parent_attack_id`, `parent_name`, `parent_stix_id`.
- [ ] Run tests — must pass.

### Task 2 — group/campaign (D)
- [ ] Fix D.
- [ ] Test: `get_campaigns_attributed_to_group(<G0007 stix>)` (or a group known to have
      campaigns in v20 — pick one that returns > 0) entries have non-null `name`, `stix_id`,
      `attack_id`; `formatted` contains a campaign name.
- [ ] Run tests — must pass.

### Task 3 — mitigation (E)
- [ ] Fix E.
- [ ] Tests: enterprise M1036 entries non-null `attack_id`/`name`/`stix_id`; atlas mitigation
      (first `AML.M` with ≥1 technique) entries have `attack_id` starting `AML.T`.
- [ ] Run tests — must pass.

### Task 4 — ICS asset pair (F, G)
- [ ] Fix F, G.
- [ ] Tests (skip if ics missing): `get_assets_targeted_by_technique(<T0800 stix>, domain="ics")`
      entries non-null name/stix_id; `get_techniques_targeting_asset(<one of those asset stix>,
      domain="ics")` count > 0, no exception, non-null fields.
- [ ] Run tests — must pass.

### Task 5 — data component (H)
- [ ] Fix H the same way (cannot reproduce on current data).
- [ ] Test: unit test with a stub `attack_data` (monkeypatch `server.get_attack_data` to return
      an object whose `get_techniques_detected_by_datacomponent` returns one wrapper entry
      built from a real enterprise technique) → entry fields non-null.
- [ ] Run tests — must pass.

### Task 6 — ATLAS parent techniques (I, D3)
- [ ] Fix per D3.
- [ ] Tests: atlas count == 101 (bundle is SHA-pinned), no `attack_id` matches `\.\d{3}$`;
      enterprise count == `len(MitreAttackData(path).get_techniques(include_subtechniques=False,
      remove_revoked_deprecated=True))`.
- [ ] Run tests — must pass.

### Task 7 — docs (D5)
- [ ] CHANGELOG, README check.

## Verification

- Full suite green; report counts.
- Then (main session): commit with the README rework, Trivy
  (`trivy fs --skip-db-update --scanners vuln,secret,misconfig --skip-dirs .venv --skip-dirs .ruff_cache .`),
  push `fork main`.

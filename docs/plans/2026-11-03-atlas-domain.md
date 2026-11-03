# Plan: add MITRE ATLAS as a fourth domain

Revision 3 (after plan review cycle 2; reviewer: nothing else outstanding). Status: APPROVED.

## Goal

Serve MITRE ATLAS (adversarial threats to AI systems) the same way the server serves
ATT&CK Enterprise, Mobile and ICS: a new domain value `atlas`, downloaded and cached on
first start, loaded into a `MitreAttackData` instance, and usable through the existing tools
via `domain="atlas"`. No new tool family; existing tools gain the domain.

## Facts established (verified 2026-11-03 against v1.16.0)

- Source: `https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/v1.16.0/dist/stix-atlas.json`
  (latest tag v1.16.0, 443 KB, STIX 2.1).
  SHA-256 `a1bd782257de3c8591797ac863aa9b37fe4ae42ef9284bee98bfc2661fdd1c06`.
  A local copy exists at `$TMPDIR/atlas/v1160.json` (sandbox has no general network).
- Contents: 170 `attack-pattern` (IDs `AML.T####[.###]`, 69 sub-techniques),
  35 `course-of-action` (`AML.M####`), 16 `x-mitre-tactic` (`AML.TA####`), 1 `x-mitre-matrix`
  ("ATLAS Matrix"), 1 `x-mitre-collection`; relationships only `mitigates` (246) and
  `subtechnique-of` (69). No groups, software, campaigns, data sources/components, assets,
  case studies.
- External refs: first ref has `source_name: "mitre-atlas"`; kill chain name `mitre-atlas`;
  `x_mitre_platforms: ["ATLAS"]`. Tactic shortnames: reconnaissance, resource-development,
  initial-access, ai-model-access, execution, persistence, privilege-escalation,
  defense-evasion, credential-access, discovery, lateral-movement, collection,
  ai-attack-staging, command-and-control, exfiltration, impact.
- `atlas` is not in `mitreattack.release_info`; `download_stix` cannot fetch it.
- Library `MitreAttackData` (`.venv/lib/python3.12/site-packages/mitreattack/stix20/MitreAttackData.py`,
  "MAD") problems on ATLAS:
  1. Every path that builds a tactic or matrix through `StixObjectFactory` raises
     `stix2.exceptions.InvalidValueError` (ATLAS IDs are UUIDv5; STIX 2.0 custom classes need
     UUIDv4): `get_objects_by_type`, `get_object_by_stix_id`, `get_object_by_attack_id`,
     `get_objects_by_name` for those types, and therefore `get_tactics`, `get_matrices`,
     `get_tactics_by_technique`, `get_tactics_by_matrix`, `get_attack_id`/`get_name` on tactics.
  2. `get_attack_id` (MAD:983-989) only returns IDs whose first ref has
     `source_name == "mitre-attack"` → None for every ATLAS object. Server calls it ~83 times,
     including `format_objects` (server.py:296).
  3. `get_techniques_by_tactic` rejects domains other than enterprise/mobile/ics-attack.
- Pre-existing server bugs found during review (affect all domains):
  - server.py:7908 calls `get_tactics_by_matrix(matrix_stix_id)` but MAD:606 takes no args →
    TypeError swallowed → tool always returns empty.
  - server.py:860 passes the `tactic` argument straight through as the kill-chain
    `phase_name`; docstring examples use display names ("Initial Access") which return 0.
  - The only ID-format check in server.py is `re.match(r"^[GMSD]\d+$", ...)` at line 8340
    inside `generate_layer`.

## Design decisions

- D1. Domain name `atlas`. `DOMAINS = ["enterprise", "mobile", "ics", "atlas"]`.
  `attack_data` key stays `f"{domain}-attack"` (`atlas-attack`), so lookup code is unchanged.
- D2. Separate version pin: `ATLAS_VERSION = "1.16.0"`, `ATLAS_SHA256 = "<hash above>"`,
  `ATLAS_URL` built from the tag. Not tied to `release_info.LATEST_VERSION`.
- D3. Storage: `DATA_DIR / f"atlas-v{ATLAS_VERSION}" / "stix-atlas.json"`. `get_stix_path("atlas")`
  returns it; ATT&CK paths unchanged. `_compute_data_stats` reports `ATLAS_VERSION` for atlas.
- D4. Download: stdlib `urllib.request.urlopen` with 60 s timeout, read to memory, verify
  SHA-256, write temp file in target dir, `os.replace`. Hash mismatch → raise, no file left.
  No new dependency. Honour `force`.
- D5. Never rewrite STIX IDs.
- D6. **Server-local subclass** `class _MitreData(MitreAttackData)` in server.py, used by
  `load_domain` (server.py:174) for all domains. Overrides:
  - `get_objects_by_type`, `get_object_by_stix_id`, `get_object_by_attack_id`,
    `get_objects_by_name`: call `super()`; on `stix2.exceptions.InvalidValueError` only,
    redo the same query against `self.src` and return the raw stix2 objects (apply the same
    revoked/deprecated filtering the library applies). ATT&CK never hits the error path, so
    its behaviour is identical.
  - `get_attack_id`: return the first ref's `external_id` when `source_name` is in
    `{"mitre-attack", "mitre-atlas"}`.
  - `get_techniques_by_tactic(shortname, domain, remove_revoked_deprecated)`: for
    `domain == "atlas-attack"` query attack-patterns with kill chain `mitre-atlas` and the
    shortname (mirror the library's filter code); otherwise `super()`.
  Library `get_tactics`, `get_matrices`, `get_tactics_by_technique`, `get_tactics_by_matrix`
  route through these methods (MAD:266, 281, 606, 642, 656), so they work without call-site
  edits. Builder must confirm by test, not assume. No monkeypatching of library globals.
- D6a. Fallback results (and `get_tactics_by_matrix()` entries, which the library already
  returns as raw dicts, MAD:619) are plain `dict`s. Every server read of tactic/matrix fields
  must go through the existing `_field()` helper (server.py:254), never `getattr`/`.attr`.
  Known sites: server.py:4824-4826 (`get_all_tactics`), 7629-7631 (tactic lookup),
  7923 (`get_tactics_by_matrix`, `tac.id`), 8005 (`get_tactics_by_technique`, `tac.id`),
  plus the D7 name lookup. Builder greps for `getattr(` / `.id` / `.name` on tactic or matrix
  variables and converts all of them.
- D6b. `get_all_tactics` output entries gain `shortname` (`_field(t, "x_mitre_shortname")`);
  note in CHANGELOG.
- D7. `get_techniques_by_tactic` tool (server.py:818): accept either a tactic display name
  ("Initial Access", "AI Attack Staging") or a shortname ("initial-access"), for all domains.
  Resolve: if a tactic in the domain matches the name case-insensitively, use its
  `x_mitre_shortname`; else use the argument as given. Fix docstring to say both forms work.
- D8. Tools whose data does not exist in ATLAS (groups, software, campaigns, data sources/
  components, assets, procedure examples) return empty results; no special casing.
- D9. `generate_layer`: if `domain == "atlas"`, return the tool's normal error shape with a
  clear message ("ATLAS layers not supported: ATLAS has no groups/software; use ATLAS
  Navigator") **before** the regex check at server.py:8340.
- D10. Fix `get_tactics_by_matrix` tool (server.py:7876-7910): call `get_tactics_by_matrix()`
  with no args and pick the entry for the matrix whose STIX ID matches (resolve the matrix name
  via `get_object_by_stix_id`). Works for all domains.
- D11. Failure isolation: if ATLAS download/load fails, ATT&CK domains still load and the
  server starts (keep per-domain try/except, log to stderr). Known effect: `main()` check
  `len(existing) < len(DOMAINS)` (server.py:8536) retries the download every start while atlas
  is missing; acceptable, document in README. `main()` log lines (8537, 8541) also print the
  ATLAS version.

## Non-goals

- ATLAS case studies (not in STIX bundle; need ATLAS.yaml). Possible follow-up.
- ATLAS Navigator layers.
- Cross-mapping ATLAS ↔ ATT&CK techniques.
- Auto-detecting the latest ATLAS release.

## Test setup (shared)

- New `tests/conftest.py` module-scoped fixture `atlas_loaded`: pick the bundle path —
  `server.get_stix_path("atlas")` if it exists, else `$TMPDIR/atlas/v1160.json` if it exists
  and its SHA-256 equals `ATLAS_SHA256`, else `pytest.skip` with a clear reason. Then set
  `server.attack_data["atlas-attack"] = server._MitreData(path)` and append `"atlas"` to
  `server._loaded_domains`; restore both on teardown. Do not touch `DATA_DIR` here (the
  `DATA_DIR` monkeypatch is only for `tests/test_atlas_download.py`). Enterprise tests keep
  using cached enterprise data as `tests/test_revoked_filters.py` does.
- Run with `.venv/bin/python -m pytest` (`uv run` fails in the sandbox: uv cache not writable).

## Tasks (each ends with: run full test suite, must pass)

1. **Download + paths** (D1-D4, D11 logs). Tests `tests/test_atlas_download.py` (no network;
   `monkeypatch.setattr(server, "DATA_DIR", tmp_path)`; mock `urllib.request.urlopen`):
   hash mismatch raises and leaves no file; match writes file at `get_stix_path("atlas")`;
   existing file not re-downloaded unless `force=True`; `"atlas" in DOMAINS`;
   `_compute_data_stats()["atlas"]["version"] == ATLAS_VERSION` when file exists.
2. **Subclass** (D6). Tests `tests/test_atlas.py` + `tests/test_enterprise_regression.py`:
   - library level on atlas data: `get_tactics()` → 16; `get_matrices()` → 1;
     `get_attack_id` for AML.T0051 technique == "AML.T0051", for a tactic starts "AML.TA",
     for a mitigation starts "AML.M"; `get_tactics_by_technique(AML.T0051 id)` non-empty;
     `get_techniques_by_tactic("ai-attack-staging", "atlas-attack")` > 0.
   - enterprise regression: `_MitreData` vs plain `MitreAttackData` on enterprise file give
     identical tactic IDs, matrix IDs, and `get_attack_id` for a sample technique (T1059).
3. **Tool behaviour on atlas** (D7, D8, D10). Tests in `tests/test_atlas.py` using real tool
   signatures from server.py:
   - `get_all_tactics(domain="atlas")` → 16; every entry has non-null `name` and `stix_id`,
     `attack_id` starting `AML.TA`; one entry has name "AI Attack Staging" and
     `shortname == "ai-attack-staging"`.
   - `get_tactics_by_technique` / `get_tactics_by_matrix` entries have non-null `name`/`stix_id`
     (guards the D6a dict issue) for atlas and enterprise.
   - `get_all_techniques(domain="atlas")` → >0, all `attack_id` start `AML.T`.
   - `get_object_by_attack_id("AML.T0051", ...)` → name "LLM Prompt Injection",
     `attack_id == "AML.T0051"`, and `formatted` output contains `ID: AML.T0051`
     (check the exact formatted field name in server.py).
   - `get_mitigations_mitigating_technique` for AML.T0051 → ≥1 item with `attack_id` `AML.M…`.
   - `get_techniques_by_tactic("AI Attack Staging", "atlas")` and
     `("ai-attack-staging", "atlas")` → same non-zero count.
   - enterprise: `get_techniques_by_tactic("Initial Access", "enterprise")` → >0 (D7 fix).
   - `get_tactics_by_technique` for AML.T0051 → non-empty.
   - `get_all_matrices(domain="atlas")` → "ATLAS Matrix"; `get_tactics_by_matrix` for it → 16;
     enterprise `get_tactics_by_matrix` for the Enterprise matrix → >0 (D10 fix).
   - `get_all_groups(domain="atlas")` → count 0.
4. **generate_layer guard** (D9). Test: `generate_layer("AML.M0000", domain="atlas")` returns
   the atlas message, not "Invalid ATT&CK ID format".
5. **Docstrings**: every `domain:` docstring line lists `"atlas"` (≈50 lines), plus
   `format_objects` (server.py:274), `get_data_stats` (≈337), `generate_layer` (8305-8332),
   `get_techniques_by_tactic` examples. Test: none beyond suite + ruff.
6. **Docs + version**: README (domain list, data dir layout, ATLAS version pin + how to bump,
   behaviour notes incl. tactic-name forms, limitations: no case studies/layers, retry on
   start while atlas missing), CHANGELOG entry (incl. the two pre-existing bug fixes), bump to
   0.3.0 in `pyproject.toml`, `src/mitre_mcp_server/__init__.py`, `package.json`,
   `server.json`, and `uv.lock` project entry if it records the version.

## Verification

- `.venv/bin/python -m pytest` all green (existing + new; report any skips with reason).
- `.venv/bin/ruff check src tests` if available; else say skipped.
- Manual smoke: run `.venv/bin/mitre-mcp-server` with `MITRE_MCP_DATA_DIR` pointing at a temp
  dir seeded with the cached enterprise/mobile/ics files and the local ATLAS copy; confirm
  stderr shows atlas loaded and `Server ready!`; stop.
- After commit to main: `trivy fs --scanners vuln,secret,misconfig .`, fix findings.

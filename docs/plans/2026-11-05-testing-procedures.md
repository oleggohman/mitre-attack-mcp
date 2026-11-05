# Plan: testing procedures — exhaustive smoke suite, invariants, protocol tests, 100 % coverage, CI, lint, definition of done

Revision 3 (after plan review cycle 2). Status: APPROVED (plan review cycle 3).

Approval note (ordering): apply Fix-OS (annotate the 3 tools `-> Dict[str, Any]`) as the FIRST step of Task 1, before the conftest `call_tool` helper and the Task 2 session cache, which read `structured_content["result"]`.

Review cycle 2 resolutions: S1 Owner decisions restated as decided (invalid domain kept, F-SIZE
out of scope, workflow-push stop rule in Task 9 + Verification) · S2 output-schema fix for 3 tools
+ smoke assertion D3 #11 · S3 `fault_na`, pre-listed `fault_raises`, `get_stats` fix (D3 #10,
D13, Task 6) · S4 baseline ca05b49 / 130 tests · S5 README:160.

Review cycle 1 resolutions: R1 protocol fixture = sync module fixture + anyio blocking portal
(D5) · R2 registry-driven fault injection D3 #10 + B-batches provisional (D6, Task 8) · R3 size
follow-up row with measured sizes, D8 decided, open items → Owner decisions · R4 session result
cache (D3) · R5 state-isolation guard (D10) · R6 one checkbox per batch (Task 8) · R7 D3 #9 vs D5
wire check · R8 README count regex (Task 10) · R9 CI concurrency, bundle hash step,
`enable-cache: true` (D7) · R10 YAML check via ruby (Task 9) · R11 `MITRE_MCP_REQUIRE_DATA` scope
(D10) · R12 existing anchor tests kept (D1).

Lands **after** `docs/plans/2026-11-05-usage-fixes.md` (Tasks 1-10, v0.4.0) and is written against
that final API. Line numbers are pre-change and will move — re-grep before editing.

## Owner decisions

- **Full code coverage (owner requirement, received during drafting):** 100 % line + branch of
  `src/mitre_mcp_server/`, enforced in CI and in the Definition of done; exclusions only via
  `# pragma: no cover` with a reason, listed in D6.
- **D8 lockfile: decided (a)** — un-ignore and commit `uv.lock`; CI uses `uv sync --locked`.
- **Invalid domain: decided — keep the exception.** In-process `UnexpectedToolError` with a
  `ValueError` cause (asserted by D3 #9); on the wire `is_error=True` (asserted by D5).
- **Default `limit` on large `get_all_*` tools: decided — not in this plan.** Tracked as
  Follow-ups row F-SIZE; the smoke suite records them in `SIZE_OVERRIDES`.
- **Workflow push: decided — attempt it.** If the push of `.github/workflows/` is rejected for a
  missing `workflow` token scope, **stop and report to the owner; no workaround** (Task 9,
  Verification).
- **Output schema: decided — fix** the 3 tools without a usable return annotation (D13, Task 3).
- **`get_stats` on data-access error: decided — fix** to return a documented failure response
  (D13, Task 6).

## Why

Escaped bugs were found by a real client, not by tests or diff-scoped review. Each row names the
suite in this plan that would have caught it:

| Escaped bug | Caught by |
|---|---|
| 8 relationship-wrapper tools crashed / returned all-null fields (subtechnique-tools-fix A-H) | Smoke: no exception + no-null key fields, every tool × domain |
| `get_techniques_used_by_group_software` always 0 (B6) | Smoke non-empty matrix; invariant "group software techniques == union of software techniques" |
| `get_all_parent_techniques` 0 for ATLAS | Smoke non-empty matrix (atlas cell) |
| `include_description=False` ignored (F3) | Smoke description-flag check on every tool with the flag |
| group tools 78 vs `generate_layer` 64 | Invariant "group tools == group layer count" |
| responses 317 KB / 2-19 MB | Smoke wire-size budget with default args |
| detection mapping empty on ATT&CK v18+ | Smoke non-empty matrix (detection tools, all ATT&CK domains) |

## Verified facts (2026-11-05, ATT&CK v20.0 cache, ATLAS v1.16.0, mcp 2.3.0, mitreattack-python 6.3.1)

Baseline: usage-fixes is committed as **ca05b49** on `main` (v0.4.0);
`.venv/bin/python -m pytest -q` → **130 passed** (31.8 s). Coverage and lint figures below were
measured on the tree shortly before that commit and are refreshed in Task 0 / Task 8a.

### T1. Registry and in-process calls
- `server.mcp` is `MCPServer("mitre-attack-mcp-server", ...)` (server.py:682); tools are registered
  with `@mcp.tool()`. `await server.mcp.list_tools()` → **67** `MCPTool` objects with `name` and
  `input_schema` (`properties`, `required`, defaults) — enough to derive the per-tool domain
  applicability (`"domain" in properties`) and flags (`include_description`, `limit`, …)
  without a hand list.
- `await server.mcp.call_tool(name, args)` (mcp `server/mcpserver/server.py:533`) runs argument
  validation and result conversion in-process and returns `CallToolResult` with
  `structured_content == {"result": <tool dict>}` for tools annotated `-> Dict[str, Any]` (the SDK
  derives an `output_schema` from the annotation and wraps the dict under `"result"`) and
  `content[0].text` = pretty-printed JSON. **Three tools have no usable annotation** →
  `output_schema is None` → `structured_content is None` (only text content):
  `get_datacomponents_detecting_technique` (`-> dict`, server.py:~7285), `get_tactics_by_matrix`
  (no annotation, server.py:8399), `get_tactics_by_technique` (no annotation, server.py:8479).
  Verified by listing tools with `output_schema is None` (exactly these 3 of 67). Tool exceptions surface as
  `UnexpectedToolError` (original in `__cause__`); bad arguments as `ToolError`.
- `domain="bogus"` → `get_attack_data` → `load_domain` raises `ValueError` → in-process
  `UnexpectedToolError` (cause `ValueError`); on the wire `is_error=True`, text "Error executing
  tool …". Current contract; kept (Owner decisions) and tested.
- `mcp.Client(server.mcp)` connects in-process. `mcp.Client` has **no `errlog` parameter**; stderr
  of a stdio subprocess can only be captured via `mcp.client.stdio.stdio_client(params,
  errlog=<real file object>)` (`mcp/client/stdio.py:115`), wrapped as `Client(stdio_client(...))`
  (Client accepts a `Transport`). `StdioServerParameters.env` is merged over
  `get_default_environment()` (`stdio.py:94-131`).
- Protocol probe 1: `sys.executable -m mitre_mcp_server.server` with `MITRE_MCP_DATA_DIR` = temp dir
  of symlinks to the cache and `HTTP(S)_PROXY=http://127.0.0.1:9` → stderr "Using existing data
  (ATT&CK 20.0, ATLAS 1.16.0)", "Loaded 4 domains", connected in **3.1 s**, `list_tools` = 67,
  `call_tool` OK, process exits when the client closes stdin.
- Protocol probe 2 (review cycle 1, `$TMPDIR/proto/test_q.py`): a **module-scoped async** fixture
  fails at teardown (anyio "Attempted to exit cancel scope in a different task"; repo sets
  `asyncio_default_fixture_loop_scope = "function"`). A **sync** module fixture works (2 tests,
  4.4 s):
  ```python
  with open(err_path, "w") as err, start_blocking_portal() as portal:  # anyio.from_thread
      with portal.wrap_async_context_manager(
          Client(stdio_client(params, errlog=err))
      ) as client:
          yield portal, client
  # tests: portal.call(client.call_tool, "get_technique_by_id", {...})
  ```
- Exception handling in server.py: 200 `except` occurrences, 190 `except Exception` — about 94
  top-level tool handlers, about 86 nested per-item, about 19 outside tools. **63 of 67 tools call
  `get_attack_data(domain)` outside any `try`.**

### T2. Startup and data
- `main()` (server.py:~9313) downloads only when `check_existing_data()` < 4 domains, then
  `load_all_domains()`, then `mcp.run(transport="stdio")`. `download_all_domains()` swallows
  per-domain errors (prints a warning) — a download step must assert all four files exist.
- Cache: `~/.mitre-mcp-server/data/v20.0/{enterprise,mobile,ics}-attack.json` and
  `~/.mitre-mcp-server/data/atlas-v1.16.0/stix-atlas.json` (paths from `get_stix_path`,
  server.py:63). ATLAS is also at `$TMPDIR/atlas/v1160.json` (conftest fallback, hash-checked).
- Bundle integrity: SHA-256 of each cached ATT&CK file equals
  `release_info.STIX21[domain][release_info.LATEST_VERSION]` (checked for all three; the same table
  `download_domain_data` passes as `known_hash`, server.py:~145); ATLAS is checked against
  `server.ATLAS_SHA256`.
- Active object counts (raw bundles, revoked/deprecated excluded) — basis of the expected-empty
  matrix:

  | type | enterprise | mobile | ics | atlas |
  |---|---|---|---|---|
  | attack-pattern | 706 | 125 | 104 | 170 |
  | intrusion-set | 178 | 20 | 14 | 0 |
  | malware / tool | 747 / 95 | 126 / 2 | 25 / 0 | 0 / 0 |
  | campaign | 57 | 3 | 10 | 0 |
  | course-of-action | 44 | 13 | 53 | 35 |
  | x-mitre-data-component / detection-strategy / analytic | 106 / 703 / 1770 | 29 / 124 / 211 | 36 / 106 / 302 | 0 |
  | x-mitre-asset | 0 | 0 | 18 | 0 |
  | x-mitre-data-source (active) | 0 | 0 | 0 | 0 |
  | relationships | uses, mitigates, subtechnique-of, detects, attributed-to, revoked-by | same | same + `targets` (933) | only `subtechnique-of` (69), `mitigates` (246) |

### T3. Current coverage (pytest-cov 7.1.0 / coverage 7.17.2, installed to `$TMPDIR` for the probe)
- `server.py`: 2995 statements, 1566 missed, 934 branches, 148 partial → **47 %** line+branch.
  Suite runtime 40 s (101 tests, pre-ca05b49; Task 8a re-measures on the 130-test baseline).
- Missed lines by function (top): `get_datacomponents_detecting_technique` 105 (pre-v18 paths),
  `get_procedure_examples_by_tactic` 61 (dead: F6 bug), the 11 relationship tools ~51-60 each
  (`include_relationships=True` and except paths), `get_all_datacomponents` 41, search tools 35-40,
  `get_group_by_name` 33, `get_all_software`/`get_software` ~30, `main` 14, download/load ~40 total.
- Only genuinely untestable line found: `if __name__ == "__main__": main()` (server.py last 2
  lines). `main()` itself is testable in-process by monkeypatching `server.mcp.run`.
- coverage 7.17 supports `[tool.coverage.run] patch = ["subprocess"]` (coverage/config.py:573);
  not used (D6).
- Some error paths are already covered, e.g. `tests/test_layers.py::test_invalid_inputs` (:60),
  `::test_duplicates_warn` (:110).

### T4. Tooling in the sandbox
- `.venv` has **no pip** (`No module named pip`); `coverage`, `pytest-cov`, `ruff` are not installed.
  `uv pip install --python .venv/bin/python --cache-dir "$TMPDIR/uv-cache" …` works (network to
  `pypi.org`, `files.pythonhosted.org`); `uv lock --check --cache-dir "$TMPDIR/uv-cache"` works.
- `uv.lock` is **gitignored and untracked** (`.gitignore` line `uv.lock`; `git ls-files` has no lock).
  `.ruff_cache/` is not ignored.
- ruff 0.17.3 with only `line-length`/`target-version` set reports 514 findings (its default rule
  set now includes BLE/S/UP/ASYNC) → rules must be selected explicitly.
  `--select E,F,W,I,B` → 41 findings: 24 E501, 9 W291/W293, 2 W292, 6 I001 (tests: first-party
  import grouping). `UP` alone adds ~300 (annotation style). `ruff format --check`: 7 files would
  be reformatted.
- Trivy 0.76.1 `trivy config` on a sample `.github/workflows/ci.yml` → "Detected config files
  num=0": Trivy has no GitHub Actions misconfig checks in this version, so the workflow is
  hardened by design (D7), and the Trivy run must still be clean (secrets/vuln).
- `ruby` is available (`/usr/bin/ruby`, `-ryaml` loads) for a YAML parse check.
- Action tags resolved with `git ls-remote` (lightweight tags → commit SHAs):
  `actions/checkout` v7.0.1 `3d3c42e5aac5ba805825da76410c181273ba90b1`,
  `actions/cache` v6.1.0 `55cc8345863c7cc4c66a329aec7e433d2d1c52a9`,
  `astral-sh/setup-uv` v10.3.3 `68559e99cc807c1eb7e9238fd43a15bba460eec2`.
  setup-uv inputs (README at v10.3.3): `python-version` (sets `UV_PYTHON`), `enable-cache`
  (default `auto`), `cache-dependency-glob` (default includes `pyproject.toml`, `uv.lock`).
- No `CLAUDE.md`, `TESTING.md`, `.github/` in the repo. README "Local development" (README.md:58)
  shows `uv run pytest`; README states the tool count at :3 and :160 ("67 tools").

## Design decisions

- **D1 Smoke suite driven by the registry.** `tests/tool_args.py` holds `ARGS: dict[tool_name,
  ToolSpec]`. `ToolSpec` = per-domain arg builder (`Callable[[Samples], dict]`) or
  `NA("<reason>")`, optional `negative` builder (well-formed but unknown ID), optional
  `expect_empty={domain: RawCheck}`, `known_bug={domain: "<reason>"}`, `fault_raises` and `fault_na`
  (D3 #10). Domains for a tool = all four if `"domain"` is in its `input_schema`, else one call
  without domain.
  `test_registry_matches_table`: `{t.name for t in await server.mcp.list_tools()} == set(ARGS)`
  — a new tool without an entry fails, a stale entry fails.
  Calls go through `server.mcp.call_tool` (validation + serialisation as on the wire; no session
  overhead). Rejected: calling Python functions directly (skips arg validation and JSON
  conversion — a non-serialisable result would pass); in-process `Client` per call (slower, adds
  nothing over `call_tool` for this purpose).
  **Existing tests stay.** `tests/test_output_size.py`, `tests/test_description_flag.py`,
  `tests/test_layers.py::test_generate_layer_g1015` and the other existing files remain as
  fixed-ID anchor tests (exact counts such as G1015 = 78). The smoke and invariant suites check
  generic properties on derived samples; they do not delete, move or duplicate those anchors.
- **D2 Arguments derived from real data, deterministically.** `Samples` (one per domain, built once
  via `functools.cache` from `server.get_attack_data(domain)`): for each role pick the **first
  active object sorted by ATT&CK ID that satisfies a predicate**, e.g. `technique_with_subs`,
  `subtechnique`, `technique_used_by_group`, `technique_used_by_software`,
  `technique_used_by_campaign`, `technique_with_mitigation`, `technique_with_det`,
  `technique_targeting_asset`, `group_with_techniques`, `group_with_software`,
  `group_with_campaign`, `software_with_techniques`, `campaign_with_techniques` /
  `_software` / `_groups`, `mitigation_with_techniques`, `datacomponent_with_techniques`,
  `asset_with_techniques`, `matrix`, `tactic` (name + shortname), `platform` (most common technique
  platform), group/software/campaign `alias`, `name` for name lookups, a content word, a timestamp
  (median `modified`). Role absent in a domain → `None` → the table must say `NA(reason)` for that
  cell (test fails if a builder receives `None`). Rejected: hard-coded IDs per domain (break on ATT&CK
  bumps; the existing anchor tests already pin specific IDs).
- **D3 Smoke assertions.** **Result cache:** a session-level dict in `tests/tool_args.py`
  (or conftest) keyed `(tool, domain, variant)`, variants `default`, `no_description`, `negative`,
  `bogus_domain`; each cell × variant is called **at most once per session** and stores
  `(result_dict | None, wire_bytes, exception | None)`; the assertion tests below only read the
  cache (results are treated as read-only). Fault injection (#10) is not cached.
  Assertions per tool × applicable domain (default args unless stated):
  1. no exception (`call_tool` raises on tool errors) and `is_error is False`;
  2. shape: result dict has a non-empty `message` or `formatted`; `found`/`success` when present
     are `True` for positive args;
  3. **no nulls in entity key fields**: walk the result; every dict whose `stix_id` (or `id` when it
     is a STIX ID) has an entity prefix (`attack-pattern`, `intrusion-set`, `malware`, `tool`,
     `course-of-action`, `campaign`, `x-mitre-tactic`, `x-mitre-matrix`, `x-mitre-data-component`,
     `x-mitre-asset`, `x-mitre-detection-strategy`, `x-mitre-analytic`) has non-null `name` and
     ATT&CK ID (`attack_id` or `id`); keys `parent_*` likewise. `NULLABLE` allow-list (each with a
     reason), starting with `data_source_*` (no `x_mitre_data_source_ref` on v18+ data, usage-fixes
     F1);
  4. **non-empty where data exists**: the primary list (`count`/`returned` > 0 or found) — except
     cells in `expect_empty`, where the tool must return empty **and** the attached `RawCheck`
     (a predicate over the raw bundle, e.g. `no_objects("intrusion-set")`) must hold, so an empty
     cell cannot hide a bug; `known_bug` cells are `pytest.mark.xfail(strict=True)` so a fix flips
     them to a failure that forces the table update;
  5. **count semantics**: if `total` present → `count == total`, `returned == len(items)`,
     `has_more == (offset + returned < total)`; else if `count` present → `count == len(items)`
     (items = the single list-valued entity key);
  6. **wire size**: `len(result.model_dump_json(by_alias=True))` ≤ `DEFAULT_WIRE_BUDGET = 100_000`
     bytes, or ≤ the tool's entry in `SIZE_OVERRIDES` (`{tool: (bytes, reason)}`, set to ⌈measured ×
     1.25⌉ after usage-fixes, hard ceiling 1 MB, each override names why the default is large and
     references Follow-up F-SIZE where applicable);
  7. **description flag**: for tools whose schema has `include_description`, the `no_description`
     variant (`False`) → no non-empty string under any key containing `description` outside a
     `relationships` subtree, and `"Description:" not in formatted`;
  8. **negative input**: tools with a `negative` builder (unknown but well-formed STIX/ATT&CK ID)
     → no exception, empty result / `found False` / `success False`, non-empty `message`;
  9. **invalid domain (in-process contract)**: per tool with a `domain` param, the `bogus_domain`
     variant raises `UnexpectedToolError` whose `__cause__` is `ValueError` mentioning the domain.
     This is the in-process equivalent of the wire behaviour; D5 asserts `is_error=True` on the
     wire (Owner decisions: kept);
  10. **fault injection** (`tests/test_cov_faults.py`, registry-driven, marker `unit`): for each
     `ARGS` cell (positive args), `monkeypatch.setattr(server, "get_attack_data", lambda d=...:
     _Boom())` where `_Boom.__getattr__` returns a callable raising `RuntimeError("injected")`
     (attribute reads that are not calls also raise via a property-like stub where needed). The
     args are built from the real `Samples` **before** patching. Expected outcome, one of:
     (a) a **documented failure response**: non-empty `message`, and `success`/`found` False or the
     primary list empty / `count == 0`; or (b) only for cells listed in `fault_raises` (each with a
     reason, e.g. "first data call outside try") — `UnexpectedToolError` whose cause chain contains
     the injected `RuntimeError`. Anything else is a crash and fails: a different exception type
     (`AttributeError`, `TypeError`, `KeyError` from mishandled partial data), or a success-looking
     response. Cells listed in `fault_na` (reason required) are not injected: tools that do not
     read domain data — `get_layer_metadata`, `get_data_stats` (reason "does not read domain
     data"). Pre-listed `fault_raises` (reviewer probe, cycle 2; outcome (b) verified):
     `get_technique_by_id`, `get_subtechniques_of_technique`,
     `get_techniques_mitigated_by_mitigation` — reason "first data call outside try; error
     surfaces as UnexpectedToolError / wire is_error". Pre-listed finding: `get_stats` swallows
     data-access errors and returns zero counts with a normal message (success-looking → a crash
     by this definition) → fixed in Task 6 (D13). This covers the ~94 top-level tool handlers in
     bulk; the nested per-item handlers need targeted stubs (Task 8 batches). Injection is at the
     **returned object** (not by making `get_attack_data` raise) so the tool's own handlers run;
     (b) stays the documented outcome for calls outside `try` (63/67 tools call `get_attack_data`
     outside `try`; wrapping them is a non-goal);
  11. **output schema**: every registered tool has `output_schema is not None` (registry-wide,
     one test) and every cached `default` result has `structured_content["result"]` equal to
     `json.loads(content[0].text)`.
- **D4 Invariants** (`tests/test_invariants.py`, real data, every applicable domain):
  group: `get_group_techniques(name)` attack_id set == `get_techniques_used_by_group(stix)` ==
  `generate_layer(G).technique_ids` for both `include_campaigns` values; group-software:
  `get_techniques_used_by_group_software(G)` set == ∪ `get_techniques_used_by_software(S)` for
  `S ∈ get_software_used_by_group(G)` (`limit=None`); software/mitigation layers:
  `generate_layer(S|M)` ids == `get_techniques_used_by_software` / `get_techniques_mitigated_by_
  mitigation` ids; sub/parent: every `get_all_subtechniques` entry's `parent_attack_id` ==
  `get_parent_technique_of_subtechnique(stix).parent.attack_id` and the sub is in
  `get_subtechniques_of_technique(parent)`; mitigation↔technique both directions; group↔software
  (`get_software_used_by_group` / `get_groups_using_software`); group↔campaign
  (`get_campaigns_attributed_to_group` / `get_groups_attributing_to_campaign`); technique↔data
  component (`get_datacomponents_detecting_technique` / `get_techniques_detected_by_datacomponent`);
  ID round trip per entity type: `get_object_by_attack_id(aid, type).object.stix_id` →
  `get_object_by_stix_id` name equal, `get_attack_id(stix) == aid`, `get_name(stix) == name`,
  `get_stix_type(stix) == type`; `get_stats` counts == corresponding `get_all_*` counts (builder
  checks which keys exist). Group↔technique reverse direction only for `direct is True` entries
  (provenance may differ by design, usage-fixes D3). Scope: all objects in mobile/ics/atlas;
  enterprise: all if the module runs < 30 s, else first 25 per role sorted by ATT&CK ID
  **including** G1015, M1036, S0154 (builder's call, measured).
- **D5 Protocol tests** (`tests/test_protocol.py`, marker `protocol`). Fixture: **sync**,
  `scope="module"`, anyio blocking portal exactly as in T1 probe 2 (no async module fixture —
  it fails at teardown under the repo's function-scoped loop). It builds `tmp_path_factory`
  `data/` with symlinks to the four cached bundles at their `get_stix_path` layout (missing bundle
  → fail if `MITRE_MCP_REQUIRE_DATA=1`, else skip), env `MITRE_MCP_DATA_DIR`,
  `MITRE_MCP_LAYER_DIR=<tmp>/layers`, `HTTP_PROXY`/`HTTPS_PROXY=http://127.0.0.1:9` (any download
  attempt fails fast — no network); stderr goes to a real file via
  `stdio_client(params, errlog=f)` (`Client` has no `errlog`). Tests are sync and call
  `portal.call(client.call_tool, name, args)` / `portal.call(client.list_tools)`:
  tool count over stdio == in-process `list_tools` count == `len(ARGS)`; every tool has a
  description and an object `inputSchema`; ~6 calls covering all four domains (incl.
  `generate_technique_layer`, a paginated call, an ATLAS call) → `is_error False`,
  `json.loads(content[0].text) == structured_content["result"]`, wire size of
  `get_group_techniques("Scattered Spider")` ≤ budget; `domain="bogus"` → `is_error True` on the
  wire and the next call still succeeds; after the session closes, the stderr file contains "Using
  existing data" and no "Downloading". One test launches the console script (`mitre-mcp-server`
  next to `sys.executable`; skip if absent) with its own short-lived portal and only lists tools.
- **D6 Coverage: 100 % line + branch of `src/mitre_mcp_server/`, enforced.**
  `[tool.coverage.run] branch = true, source = ["src/mitre_mcp_server"]`;
  `[tool.coverage.report] show_missing = true, skip_covered = true, fail_under = 100`.
  `--cov` is **not** in `addopts` (single-test runs would fail the gate); the gate command is
  `.venv/bin/python -m pytest -q --cov --cov-report=term-missing` (pytest-cov applies
  `fail_under` from the coverage config). `main()` is covered in-process (`tests/test_main.py`,
  monkeypatched `server.mcp.run`, `check_existing_data`, `download_all_domains`,
  `load_all_domains`); the protocol subprocess is **not** measured (rejected `patch =
  ["subprocess"]`: adds parallel data files and `coverage combine` for 2 lines that the
  in-process test already covers).
  **Planned exclusions (complete list; any addition needs a plan amendment + review):**
  | # | Location | Pragma text | Reason |
  |---|---|---|---|
  | X1 | server.py `if __name__ == "__main__":` (last 2 lines) | `# pragma: no cover - script entry; main() tested in test_main.py, module launch in test_protocol.py (subprocess, not measured)` | Only runs as `python -m`; subprocess not measured (D6) |
  No other `# pragma: no cover`, no `exclude_also`, no `omit`.
  Order of closing gaps: (1) smoke + invariants + protocol + `test_main` + fault injection
  (D3 #10) land first; (2) Task 8a measures what is **still** missing; (3) batches close only that
  remainder. Every remaining line/branch gets a **behaviour test asserting observable output**
  (response fields, message, file effects, stderr text) — never a call without assertions. Paths
  real data cannot reach use `monkeypatch.setattr` on the real `_MitreData` instance method
  (pattern from subtechnique-tools-fix N1) or a small raising stub; pre-v18 paths (legacy
  `detects`, `x_mitre_data_sources` fallback) are tested with stubs, **not deleted** (usage-fixes
  non-goal). Code may be deleted instead of tested only if provably unreachable for any input
  (not merely for current data), recorded in the Coverage log below with the proof.
- **D7 CI** `.github/workflows/ci.yml`: triggers `push` (main), `pull_request`,
  `workflow_dispatch`; top-level `permissions: contents: read`;
  `concurrency: {group: "${{ github.workflow }}-${{ github.ref }}", cancel-in-progress: true}`
  (expressions are fine outside `run:`); one job `ubuntu-24.04`, `timeout-minutes: 30`; actions
  pinned by commit SHA with the tag in a comment (T4); `actions/checkout` with
  `persist-credentials: false`; setup-uv with `python-version: "3.12"` and
  `enable-cache: true` (explicit); no `${{ }}` expressions inside `run:` scripts (values passed via
  `env:`); no secrets used. Steps:
  1. `uv sync --locked`;
  2. version step: writes `attack=` (`release_info.LATEST_VERSION`) and `atlas=`
     (`server.ATLAS_VERSION`) to `$GITHUB_OUTPUT`;
  3. `actions/cache` on `~/.mitre-mcp-server/data`, key `mitre-data-attack-<attack>-atlas-<atlas>`;
  4. on cache miss: `uv run python -c` that calls `server.download_all_domains()` and exits
     non-zero unless `set(server.check_existing_data()) == set(server.DOMAINS)` (not "run the
     server once": it blocks on stdio and swallows download errors);
  5. **bundle hash check (always, after restore/download):** `uv run python -c` that hashes each
     `server.get_stix_path(d)` with SHA-256 and compares with
     `release_info.STIX21[d][release_info.LATEST_VERSION]` (ATT&CK) and `server.ATLAS_SHA256`
     (ATLAS); mismatch → exit non-zero (guards against a poisoned or partial cache entry);
  6. `uv run ruff check src tests`;
  7. `uv run pytest -q -rs --cov --cov-report=term-missing` with `MITRE_MCP_REQUIRE_ATLAS=1`,
     `MITRE_MCP_REQUIRE_DATA=1`.
  `uv run` is fine on GitHub runners (it only fails in this sandbox).
- **D8 Lockfile — decided (a)** (Owner decisions): remove `uv.lock` from `.gitignore`, commit it,
  CI `uv sync --locked` (reproducible; Trivy's vuln scan then covers locked deps — findings must be
  fixed per the owner's Trivy rule).
- **D9 Lint.** ruff in dev deps pinned `ruff>=0.17.3,<0.18` (default rule set changes between
  minors, T4). `[tool.ruff.lint] select = ["E", "F", "W", "I", "B"]`; `[tool.ruff.lint.isort]
  known-first-party = ["mitre_mcp_server"]`. Fix all findings (41 today: mechanical whitespace,
  import order, 24 long lines) — no baseline/`noqa` file. Not adopted: `UP` (~300 annotation
  rewrites in a 9.4k-line file, no defect value), `ruff format` (whole-file reformat diff). Remove
  the unused `[tool.black]` section (builder's call).
- **D10 Markers, data requirement, state isolation.**
  - Register `unit` (no STIX data), `data` (needs the STIX cache), `protocol` (spawns the server)
    in `[tool.pytest.ini_options] markers`, add `--strict-markers` to `addopts`.
    `tests/conftest.py` `pytest_collection_modifyitems` adds `data` to every test without `unit`
    or `protocol` → existing test files need no edits. Default run = all.
  - `MITRE_MCP_REQUIRE_DATA=1` (new, CI) only affects the **new** suites through a
    `require_domain(domain)` helper in conftest (missing cache → fail instead of skip).
    Existing data tests are unchanged: they call `get_attack_data` directly and **error** (not
    skip) when a bundle is missing; ATLAS tests keep `MITRE_MCP_REQUIRE_ATLAS`.
  - **State isolation:** `test_cov_*` and `unit` tests change module state only via
    `monkeypatch.setattr` / `monkeypatch.setitem` (auto-restored). An autouse conftest fixture,
    active for tests marked `unit` or in `test_cov_*` modules, snapshots
    `{key: id(value)} for server.attack_data` and `list(server._loaded_domains)` before the test
    and asserts afterwards that every pre-existing key still maps to the same object and no
    pre-existing domain was removed (additions from legitimate lazy loading are allowed). A test
    that leaks a stub into `server.attack_data` fails at teardown.
- **D11 Install in the sandbox (settled).** pip is absent from `.venv`, `uv sync` fails on the
  default cache. Use: `uv pip install --python .venv/bin/python --cache-dir "$TMPDIR/uv-cache"
  "pytest-cov>=7.1" "coverage>=7.17" "ruff>=0.17.3,<0.18"` (allowed hosts `pypi.org`,
  `files.pythonhosted.org`), and `uv lock --cache-dir "$TMPDIR/uv-cache"` after editing
  `pyproject.toml`. Run tools as `.venv/bin/python -m pytest`, `.venv/bin/ruff`.
- **D12 Written procedure — one source of truth.** `TESTING.md` (repo root, humans and agents):
  commands, markers, data setup, env vars, coverage policy + exclusion rule, "adding a tool"
  checklist (add `ARGS` entry, expected-empty with raw check, size override only with reason,
  `fault_raises` only with reason), CI description. `CLAUDE.md` (repo root, new; none exists): short
  **Definition of done** checklist that links to TESTING.md for details and states the
  agent-specific rules: `.venv/bin/python -m pytest -q --cov --cov-report=term-missing` must pass
  (100 %), `.venv/bin/ruff check src tests` clean, never `uv run` in the sandbox, smoke suite must
  pass, never claim a tool "works" without calling it on real data (smoke or a direct call), check
  response size of changed tools, update README/CHANGELOG with user-visible changes, run Trivy
  after committing to main (`trivy fs --skip-db-update --scanners vuln,secret,misconfig
  --skip-dirs .venv --skip-dirs .ruff_cache .`) and fix findings. README "Local development" keeps
  its commands and adds one line linking TESTING.md. Rejected: README section (README is
  user-facing and already long) and duplicating commands in both files.
- **D13 Bugs found by the new suites.** Fix in the same task when the fix is ≤ ~30 lines, with a
  regression assertion and a CHANGELOG `[Unreleased]` "Fixed" bullet; otherwise
  `known_bug`/`xfail(strict=True)` with a reason and a row in "Follow-ups" below. Never weaken an
  assertion or add an `expect_empty` cell without a `RawCheck` to make a test pass.
  **Pre-decided fixes (owner):**
  - **Fix-OS** (Task 3): annotate `get_datacomponents_detecting_technique`,
    `get_tactics_by_matrix`, `get_tactics_by_technique` with `-> Dict[str, Any]`. CHANGELOG
    `[Unreleased]` Fixed: "these tools now publish an outputSchema and return a structured
    result". Test: D3 #11.
  - **Fix-STATS** (Task 6): `get_stats` returns a documented failure response on a data-access
    error — `success: False` (or the tool's existing found/stat shape with an explicit failure
    flag; builder keeps existing keys and adds `success`) and a `message` naming the error — instead
    of zero counts with a normal message. CHANGELOG `[Unreleased]` Fixed. Test: D3 #10 outcome (a)
    for `get_stats` plus a direct test with one stubbed accessor raising.

## Non-goals

- Changing tool behaviour or output shapes beyond D13 fixes (Fix-OS, Fix-STATS, and fixes for
  bugs the suites find): no structured errors for an invalid domain, no wrapping of
  `get_attack_data` in `try`, no default `limit` on `get_all_*` (Owner decisions / F-SIZE).
- Fixing `get_procedure_examples_by_tactic` (usage-fixes F6): smoke marks it `known_bug`; its
  formatting code is covered by a stub test.
- Removing pre-v18 detection code paths; `UP` lint rules; `ruff format`; type checking (mypy).
- Measuring coverage in the protocol subprocess; multi-OS / multi-Python CI matrix; release
  automation.
- Editing or replacing existing anchor tests (D1).
- Editing files of usage-fixes before it is committed (precondition, Task 0).

## Test layout (new files)

`tests/tool_args.py` (Samples, ToolSpec, ARGS, NA, RawCheck, NULLABLE, SIZE_OVERRIDES, result cache
— not a test module), `tests/test_smoke_tools.py`, `tests/test_invariants.py`,
`tests/test_protocol.py`, `tests/test_main.py`, `tests/test_cov_faults.py`, coverage batch files
`tests/test_cov_<area>.py` (names follow the 7a table; provisional: `startup`, `mitredata`,
`relationship_tools`, `catalogue_tools`, `detection`, `layers_pagination`, `helpers`).
Conftest additions: marker hook, `require_domain`, state-isolation guard, `raw_bundle(domain)`
(cached `json.load` of the bundle), `call_tool(name, args) -> (result_dict, wire_bytes)`.

## Tasks

### Task 0 — preconditions and baseline
- [ ] Precondition met: usage-fixes committed as **ca05b49** on `main` (v0.4.0, 130 tests pass).
      Re-check `git log --oneline -1 -- src/` still shows ca05b49 or a later commit and
      `git status` is clean for `src/`, `tests/`; otherwise stop and report.
- [ ] Record baseline: `.venv/bin/python -m pytest -q` (all pass, count, runtime) and tool count
      (`list_tools` = 67).

### Task 1 — tooling: deps, markers, coverage config, isolation guard (D6 without the gate, D8, D10, D11)
- [ ] `pyproject.toml` `[dependency-groups].dev`: add `pytest-cov>=7.1`, `coverage>=7.17`,
      `ruff>=0.17.3,<0.18`; `[tool.pytest.ini_options]` `markers` + `addopts = "--strict-markers"`;
      `[tool.coverage.run]` / `[tool.coverage.report]` per D6 but **`fail_under` omitted until
      Task 8i**. Install per D11; `uv lock --cache-dir "$TMPDIR/uv-cache"`.
- [ ] `.gitignore`: remove `uv.lock` (D8); add `.coverage`, `.coverage.*`, `htmlcov/`,
      `.ruff_cache/`.
- [ ] `tests/conftest.py`: marker hook, `require_domain`, state-isolation guard, `raw_bundle`,
      `call_tool` helpers (D10).
- [ ] Tests (`unit`): `require_domain` fails under `MITRE_MCP_REQUIRE_DATA=1` for a missing path
      (monkeypatch `server.get_stix_path`) and skips otherwise; the isolation guard fails a
      deliberately leaking inner check (use `pytester` or call the guard's compare function
      directly with a replaced entry).
- [ ] Run `.venv/bin/python -m pytest -q` — must pass; `-m unit` selects only unit tests;
      `--cov --cov-report=term-missing` prints a report (record the %).

### Task 2 — smoke infrastructure: Samples, ARGS table, registry check, result cache (D1, D2, D3)
- [ ] `tests/tool_args.py`: `Samples` builder (D2) for all four domains; `ARGS` entries for all 67
      tools with builders / `NA` / `negative` / `expect_empty` (+ `RawCheck`) / `known_bug` /
      `fault_raises`; session result cache keyed `(tool, domain, variant)`.
      Expected-empty cells known today (verify each with its RawCheck): atlas — group, software,
      campaign, data-component, detection, asset, procedure-example tools and `get_all_*` of those
      types; mobile/enterprise — `get_all_assets`; all domains — `get_all_datasources` (all data
      sources deprecated). `known_bug`: `get_procedure_examples_by_tactic` (F6) in all domains.
      ATLAS `generate_layer` → expected `success False` with message naming
      `generate_technique_layer` (spec field, not an error).
- [ ] `tests/test_smoke_tools.py`: `test_registry_matches_table`; a test that every builder for an
      applicable domain gets non-`None` samples; a test that the cache calls each cell × variant
      once (counter in the cache).
- [ ] Run tests — must pass.

### Task 3 — smoke assertions (D3 #1-#9, #11) and Fix-OS
- [ ] Fix-OS (D13): annotate the 3 tools `-> Dict[str, Any]`; CHANGELOG `[Unreleased]` Fixed bullet.
- [ ] D3 #11 test: no registered tool has `output_schema is None`.
- [ ] Parametrise over (tool, domain) from `ARGS`; implement assertions 1-9 as separate test
      functions reading the cache (so a failure names the property). Measure default wire sizes,
      set `SIZE_OVERRIDES` with reasons (F-SIZE tools at least).
- [ ] Handle any failure per D13 (fix or `known_bug` + Follow-ups row).
- [ ] Self-check of the guard: temporarily remove one `ARGS` entry → registry test fails; revert.
- [ ] Run tests — must pass; record runtime of the full suite **and** of the full suite with
      `--cov` (target: < 3 min locally without `--cov`; record the `--cov` figure for CI timeout).

### Task 4 — invariants (D4)
- [ ] `tests/test_invariants.py` with the D4 relations; measure runtime, apply the enterprise
      sampling rule if needed.
- [ ] Handle failures per D13.
- [ ] Run tests — must pass.

### Task 5 — protocol tests and in-process `main()` (D5, D6)
- [ ] `tests/test_protocol.py` (marker `protocol`) per D5 — sync module fixture + blocking portal
      (start from `$TMPDIR/proto/test_q.py` if still present).
- [ ] `tests/test_main.py` (`unit`): (a) all data present → no download, "Using existing data" on
      stderr, `load_all_domains` and `mcp.run(transport="stdio")` called; (b) one domain missing →
      `download_all_domains(force=False)` called, "Downloaded n/4" on stderr; stdout stays empty in
      both (stdout is the MCP stream).
- [ ] Run tests — must pass; `-m protocol` runs only these.

### Task 6 — fault injection (D3 #10)
- [ ] `tests/test_cov_faults.py` (`unit`): parametrised over every `ARGS` cell except `fault_na`
      (`get_layer_metadata`, `get_data_stats`); `_Boom` stub; assertions per D3 #10. Start
      `fault_raises` with the 3 pre-listed tools; add others only where the injected error escapes
      a call outside `try`, each with a reason.
- [ ] Fix-STATS (D13): `get_stats` failure response; CHANGELOG `[Unreleased]` Fixed bullet; tests:
      fault-injection cell passes with outcome (a), plus a direct test (one stubbed accessor raises
      → `success False`, non-empty `message`, no zero-count success message).
- [ ] Failures of kind "crash" (wrong exception type, success-looking response) → D13.
- [ ] Run tests — must pass; record coverage %.

### Task 7 — lint (D9)
- [ ] ruff config per D9; `.venv/bin/ruff check --fix src tests`, fix the rest by hand (E501:
      wrap lines; no `noqa`).
- [ ] Run `.venv/bin/ruff check src tests` — clean; run tests — must pass.

### Task 8 — coverage to 100 % (D6), in batches
Batch contents below are **provisional**: the real list is the Task 8a table of what is still
missing after Tasks 2-6. Already-covered paths (e.g. `tests/test_layers.py::test_invalid_inputs`,
`::test_duplicates_warn`) are not re-tested. A batch with nothing left is ticked with "n/a".
- [ ] 8a. Measure: `--cov --cov-report=json:$TMPDIR/cov.json`, group missing lines/branches by
      enclosing function (AST walk in a scratch script under `$TMPDIR`), paste the table into the
      Coverage log below; assign each row to a batch. Apply X1.
- [ ] 8b. B1 startup — `check_existing_data`, `download_domain_data` (invalid domain, existing
      file, ATT&CK path with monkeypatched `download_stix.download_stix`, missing-after-download
      `RuntimeError`), `_download_atlas` (hash mismatch → `RuntimeError` and no file left; write
      failure → temp file removed; `os.unlink` failure tolerated), `download_all_domains` warning
      on stderr, `load_domain` (invalid, missing-file message, loader failure → `RuntimeError`),
      `load_all_domains` warning, `_compute_data_stats` missing domain. Tests in
      `tests/test_cov_startup.py`. Run tests — must pass; update Coverage log.
- [ ] 8c. B2 `_MitreData` fallbacks (`InvalidValueError` paths via ATLAS data or stubs;
      `get_attack_id` without refs) and the detection index (`None` lists, entries without
      ids/refs, accessor exceptions → empty index). Run tests — must pass; update Coverage log.
- [ ] 8d. B3 relationship tools — `include_relationships=True` content, nested per-item except
      paths (one targeted method raises → entry skipped/partial with documented fields),
      provenance edge cases. Run tests — must pass; update Coverage log.
- [ ] 8e. B4 catalogue/search/alias tools — not-found, empty query, revoked included/excluded,
      nested except paths. Run tests — must pass; update Coverage log.
- [ ] 8f. B5 detection — pre-v18 paths with stubs (legacy `detects` entries; `x_mitre_data_sources`
      strings incl. unparsable ones); `get_procedure_examples_by_tactic` formatting via a stubbed
      library method returning real `uses` relationships (asserts group/technique fields). Run
      tests — must pass; update Coverage log.
- [ ] 8g. B6 layers + pagination — remaining `generate_technique_layer` validation branches,
      revoked → `skipped`; `_save_layer` collision suffix and the path-escape refusal (monkeypatch
      so the resolved parent differs → `success False`, no file written); `generate_layer`
      unsupported prefix / unknown ID / ATLAS; `_paginate` `limit<=0`, `offset<0`, `offset>total`.
      Run tests — must pass; update Coverage log.
- [ ] 8h. B7 helpers and leftovers — `format_objects`, `_field`, `_unwrap`, `_safe_attack_id`,
      `_resolve_stix_id`, anything remaining. Bugs → D13; deletions only per D6 rule, logged. Run
      tests — must pass; update Coverage log.
- [ ] 8i. Gate: set `fail_under = 100`; run `.venv/bin/python -m pytest -q --cov
      --cov-report=term-missing` — must pass and print 100 %; `grep -rn "pragma: no cover" src/`
      shows only X1.

### Task 9 — CI workflow (D7, D8)
- [ ] Commit-ready `uv.lock` (Task 1 un-ignored it); `uv lock --check --cache-dir
      "$TMPDIR/uv-cache"` passes.
- [ ] `.github/workflows/ci.yml` per D7 with the SHAs from T4 (re-verify with `git ls-remote` that
      the tags still point there).
- [ ] Checks: `ruby -ryaml -e 'YAML.load_file(ARGV[0])' .github/workflows/ci.yml` (if ruby is
      unavailable, rely on the first GitHub run); `${{` appears in no `run:` block (inspect each
      `run:`; the `concurrency` group and `with:`/`if:` keys are allowed); run the step-5 hash
      script locally against the cache → passes; `trivy fs --skip-db-update --scanners
      vuln,secret,misconfig --skip-dirs .venv --skip-dirs .ruff_cache .` clean. First GitHub run is
      verified after push (main session).
- [ ] Push rule (main session): attempt `git push fork main`. If it is rejected because the token
      lacks the `workflow` scope, **stop and report to the owner — no workaround** (no removing the
      workflow, no other remote/token, no API upload).
- [ ] Run tests — must pass.

### Task 10 — docs (D12)
- [ ] `TESTING.md`, `CLAUDE.md` (DoD), README one-line link, CHANGELOG `[Unreleased]`: "Added —
      exhaustive tool smoke suite, invariants, protocol tests, fault injection, 100 % coverage
      gate, CI, ruff" plus any D13 "Fixed" bullets.
- [ ] Test (`unit`): every match of `\b(\d+) tools\b` in README.md (today :3 and :160) equals
      `len(await server.mcp.list_tools())`, and there is at least one match.
- [ ] Run the full DoD command set — must pass.

## Verification

- `.venv/bin/python -m pytest -q --cov --cov-report=term-missing` → all pass, 100 % line+branch;
  report test count and runtime (with and without `--cov`); `-m unit`, `-m data`, `-m protocol`
  each select a non-empty set.
- `.venv/bin/ruff check src tests` clean; `grep -rn "pragma: no cover" src/` → X1 only.
- Mutation spot-checks (revert after each, record outcome): re-introduce the B6 bug (skip every
  entry in `get_techniques_used_by_group_software`) → smoke non-empty + invariant fail; make
  `get_technique_by_id` ignore `include_description` → smoke description test fails; return
  `None` names from one relationship tool → null-field test fails; remove one tool's `try` around
  a nested call → fault-injection test fails.
- Then (main session): commit, Trivy (command in D12), fix findings, push `fork main` — if rejected
  for a missing `workflow` token scope, **stop and report to the owner, no workaround** — then
  confirm the CI run is green.
- `get_stats` fault cell and Fix-OS tests pass; CHANGELOG `[Unreleased]` lists both fixes.

## Bugs found and fixed by Tasks 1-6 (D13, with CHANGELOG `[Unreleased]` bullets)

| Tool | Bug | Found by | Fix |
|---|---|---|---|
| `get_revoked_techniques` / `_MitreData.get_attack_id` | `id: null` for revoked mobile techniques (legacy `mitre-mobile-attack` source name not in `_ID_SOURCES`) | smoke null-key-field test | add `mitre-mobile-attack`, `mitre-ics-attack` to `_ID_SOURCES` |
| `get_subtechniques_of_technique`, `get_techniques_mitigated_by_mitigation` | tool error (UnexpectedToolError) for an unknown STIX ID | smoke negative-input test | wrap `get_object_by_stix_id` in `try`, return not-found result; the two pre-listed `fault_raises` entries became stale and were removed |
| `get_group_by_name`, `get_group_techniques` | first partial match wins ("APT1" -> APT17, "APT3" -> APT38) | invariant group tools == group layer | `_find_group`: exact name, then exact alias, then partial |
| `get_stats` | zero counts with a normal message on data-access error | fault injection | Fix-STATS (`success`, `null` counts, failure message) |
| `get_techniques_used_by_group_software` | ignored campaign-only software (G1015 120 vs 125) | invariant union-of-software techniques | owner decision: new `include_campaigns` (default true); anchor `test_group_software.py` updated |
| 3 tools | no outputSchema | registry check | Fix-OS |

## Coverage log (filled by the builder in Task 8)

| Batch | Function / area | Lines+branches closed | Test file | Notes (deletions with proof, bugs → D13) |
|---|---|---|---|---|
| 8a | measurement after Tasks 1-6 | 639 lines / 245 branches missing in 80 functions (78 %-class: 50 % -> 78 % with fault/smoke/protocol/variants) | - | 8a table obtained with `--cov-report=json` + AST grouping; most gaps were per-item `except`, `include_relationships`, dict/object branches |
| 8b | startup: `check_existing_data`, `download_*`, `_download_atlas` cleanup, `load_domain`, `load_all_domains`, `get_loaded_domains` | 60 lines / 25 branches | `tests/test_cov_startup.py` | tmp `DATA_DIR`, monkeypatched `download_stix`/`urlopen`/`os.replace`/`os.unlink`; asserts files, stderr warnings, return values |
| 8c | `_MitreData` fallbacks, `_detection_index`, `detection_chain_for_technique`, `techniques_for_datacomponent` | 45 lines / 25 branches | `tests/test_cov_mitredata.py` | bare instance with stubbed library calls; asserts index content, caching/retry, stderr |
| 8d | relationship tools: flags and representations | ~330 lines / ~120 branches | `tests/test_cov_variants.py`, `tests/test_cov_shapes.py` | registry-driven: `include_description`, `include_relationships`, `include_campaigns`, `limit`/`offset`, `remove_revoked_deprecated`; stix2 vs dict vs attribute entries, bare objects, missing ids/phase names, failing `get_attack_id`/relationship queries, empty library results; outputs compared with the normal output |
| 8e | catalogue/search tools | ~20 lines | `tests/test_cov_misc.py`, `test_cov_variants.py` | empty `search_groups` query, listing tools skipping unusable techniques, alias lookup formatting |
| 8f | detection pre-v18 paths | ~190 lines / ~90 branches | `tests/test_cov_detection.py`, `tests/test_cov_misc.py` | legacy `detects`, chain, `x_mitre_data_sources` fallback (unparsable/unknown/filter/dedup), data-source resolution, F6 `get_procedure_examples_by_tactic` formatting via stub |
| 8g | layers | ~35 lines / ~25 branches | `tests/test_cov_layers.py` | every `generate_technique_layer` validation message, revoked -> `skipped`, `_save_layer` collision suffix / path-escape refusal (symlink + frozen clock) / 1000 collisions / OSError, `generate_layer` ID/domain/not-found/tool fallback/provenance |
| 8h | helpers and leftovers | ~15 lines | `tests/test_cov_misc.py` | `_safe_attack_id`, `format_objects` wrapper, `_unwrap_mitigation`, failing group query, revoked fallback filter |
| 8i | gate | `fail_under = 100` set; 100.00 % (3020 stmts, 942 branches) | - | `grep -rn "pragma: no cover" src/` -> X1 only |

Deletions with proof (D6):
- `get_mitigations_mitigating_technique._unwrap_mitigation`: `isinstance(entry.get("object"), (dict, object))` is always true because every Python object is an instance of `object`; replaced by `return entry.get("object")` (identical behaviour).
- `get_techniques_detected_by_datacomponent`: `if techniques:` before `format_objects` directly follows `if not techniques: return`, so it is always true; condition removed.
- `get_software_by_alias` and `get_all_techniques`: `if software_objects_for_format:` / `if technique_objects_for_format:` guard lists that receive an element in every loop iteration of a non-empty input (the empty input returns earlier); guards removed (in `get_all_techniques` the old guard also wrapped only the `total_found` assignment at odd indentation; the assignment is now unconditional).
- Exclusion X1 applied with shortened text `# pragma: no cover - script entry; main() is tested in test_main.py` (the plan's longer text exceeds the 100-column lint limit).

## Follow-ups (filled by the builder per D13; pre-filled rows from planning)

| ID | Tool | Issue | Evidence | Marked as |
|---|---|---|---|---|
| F6 | `get_procedure_examples_by_tactic` | calls non-existent library method → always 0 | usage-fixes F6 | `known_bug` all domains |
| F-SIZE | `get_all_software`, `get_all_subtechniques`, `get_all_techniques`, `get_software`, `get_all_parent_techniques`, `get_all_groups`, `search_groups` | no default `limit`; default wire size 472 KB, 471 KB, 468 KB, 441 KB, 150 KB, 143 KB, 143 KB (enterprise, review cycle 1 measurement) | review cycle 1 | `SIZE_OVERRIDES` with reason "F-SIZE: no default limit (owner: not in this plan)"; re-measure in Task 3 |
| F-SIZE+ | `get_objects_by_content`, `get_objects_by_type`, `get_techniques_by_platform` | same class (no default limit; size follows the query): 430 KB, 399 KB, 271 KB with the generic sample queries (enterprise) | Task 3 measurement | `SIZE_OVERRIDES` (reason F-SIZE) |


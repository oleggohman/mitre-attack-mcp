# Testing

One source of truth for humans and agents. Run everything from the repository root.

## Commands

```bash
uv sync                                                    # dev dependencies (pytest, pytest-cov, ruff)
uv run pytest -q                                           # full suite
uv run pytest -q --cov --cov-report=term-missing           # full suite + coverage gate (must print 100 %)
uv run ruff check src tests                                # lint (must be clean)
```

In sandboxes where `uv run` / `uv sync` fail, call the environment directly:
`.venv/bin/python -m pytest -q --cov --cov-report=term-missing` and `.venv/bin/ruff check src tests`.
Installing the dev tools there:
`uv pip install --python .venv/bin/python --cache-dir "$TMPDIR/uv-cache" "pytest-cov>=7.1" "coverage>=7.17" "ruff>=0.17.3,<0.18"`.

Runtime on a laptop (measured 2026-11-05, 5065 passed + 89 xfailed): about 3 min 20 s without `--cov`,
about 7 min with `--cov` (CI timeout is 30 min). `-m unit` takes under a second.

## Data setup

Most tests run against the real STIX bundles in `~/.mitre-mcp-server/data/` (ATT&CK v20.0
enterprise/mobile/ics and the pinned ATLAS bundle). Start the server once (`uv run mitre-mcp-server`)
or call `server.download_all_domains()` to create them. Protocol tests never touch the network: they
symlink the cached bundles into a temp directory and point the proxy variables at a dead port.

| Variable | Effect |
|---|---|
| `MITRE_MCP_REQUIRE_DATA=1` | new suites fail instead of skip when a bundle is missing (CI) |
| `MITRE_MCP_REQUIRE_ATLAS=1` | ATLAS tests fail instead of skip when the ATLAS bundle is missing (CI) |
| `MITRE_MCP_DATA_DIR`, `MITRE_MCP_LAYER_DIR` | data / layer directories (set by the protocol tests) |

## Markers

`unit` (no STIX data, stubs only), `data` (needs the cache; added automatically to every test that
is neither `unit` nor `protocol`), `protocol` (spawns the server). `--strict-markers` is on.
`uv run pytest -m unit`, `-m data`, `-m protocol` select each group. A module that calls tools on
real data (`test_cov_shapes.py`, `test_cov_faults.py`, ...) must not be marked `unit`. `-m unit`
is kept data-free and CI checks it with an empty data directory:
`MITRE_MCP_DATA_DIR="$(mktemp -d)" uv run pytest -q -m unit`.

## Suites

| File | What it checks |
|---|---|
| `tests/tool_args.py` | not a test module: per-domain samples derived from the raw bundles, the `ARGS` table (one entry per tool), raw checks, size budgets, result cache |
| `tests/test_smoke_tools.py` | every tool x domain: no exception, shape, no null key fields, non-empty where data exists, count semantics, wire size, description flag, negative input, invalid domain, structured == text |
| `tests/test_invariants.py` | tools that describe the same relation agree (group tools vs group layer, inverse relations, ID round trips, stats vs catalogues) |
| `tests/test_protocol.py` | the real stdio server: tool list, calls in all four domains, wire size, invalid domain, stderr |
| `tests/test_main.py` | startup flow of `main()` |
| `tests/test_cov_faults.py` | registry-driven fault injection: a failing data object must give a documented failure response |
| `tests/test_cov_variants.py` | optional flags of every tool: descriptions, relationships, campaigns, paging, revoked |
| `tests/test_cov_shapes.py` | object/entry representations, missing ids, missing phase names, failing lookups |
| `tests/test_atlas_download.py` | ATLAS download, hash check and path helpers (no network) |
| `tests/test_output_size.py` | output size control: relationships opt-in, paging, stable ordering |
| `tests/test_revoked_filters.py` | list/search tools exclude revoked and deprecated objects by default |
| `tests/test_cov_*.py` (others), `tests/stubs.py` | paths real data cannot reach (pre-v18 detection, download, layers, helpers) using small stubs |
| `tests/test_testing_plan_fixes.py` | regression tests for bugs found by the suites |
| other `tests/test_*.py` | fixed-ID anchor tests (exact counts such as G1015 = 78 / 125) |

Tests that change module state use `monkeypatch`. An autouse guard (all tests) fails a test that
leaves a replaced or removed entry in `server.attack_data` or removes a loaded domain from
`server._loaded_domains`. It does not check additions (lazy loading is legitimate) or other module
attributes.

All 67 registered tools are covered: 66 functionally in all four domains, plus
`get_procedure_examples_by_tactic`, a known bug (it always returns 0; the cells are marked
`known_bug`, and its formatting code is tested with a stub). Other known bugs are strict xfails.

Skips are limited to cells that are not applicable (a representation a tool does not support, a
domain without revoked techniques, `generate_layer` on ATLAS) and to missing data, which fails
instead of skipping when `MITRE_MCP_REQUIRE_DATA=1`. `pytest -rs` lists every skip with its reason.

## Coverage policy

100 % line and branch coverage of `src/mitre_mcp_server/` is enforced (`fail_under = 100`) locally
and in CI. `--cov` is not in `addopts`, so single-test runs are not gated.

- Every line or branch gets a behaviour test that asserts observable output (response fields,
  messages, file effects, stderr). A call without assertions does not count.
- Paths real data cannot reach use `monkeypatch` on the real data object or a small stub
  (`tests/stubs.py`). Pre-v18 detection paths are kept and tested with stubs.
- Code may be deleted instead of tested only when it is unreachable for any input, with the proof
  recorded in the plan's Coverage log.
- The only `# pragma: no cover` allowed is the `if __name__ == "__main__":` line in `server.py`
  (script entry; `main()` is tested in `tests/test_main.py`, module launch in `tests/test_protocol.py`).
  `grep -rn "pragma: no cover" src/` must show only that line. No `omit`, no `exclude_also`, and and no `noqa` comments (there are none).

## Adding or changing a tool

1. Add an `ARGS` entry in `tests/tool_args.py` (`test_registry_matches_table` fails otherwise).
   Use sample roles (`_ref("group_with_techniques")` ...); a role absent in a domain needs
   `expect_empty={domain: RawCheck}` proving from the raw bundle why the result is empty.
2. Set `neg=True` for tools that take IDs or names so unknown input is checked.
3. Default responses above 100 kB need a `SIZE_OVERRIDES` entry with a reason (hard ceiling 1 MB).
4. `fault_raises` only with a reason (the injected data error legitimately escapes as a tool error).
5. Tools that handle `include_description`, `include_relationships`, `limit`/`offset`,
   `include_campaigns` or `remove_revoked_deprecated` are picked up by `test_cov_variants.py`
   automatically; check the output, not only that the call returns.
6. Run the full command set above; keep the gate at 100 %.

## CI

`.github/workflows/ci.yml` (push to main, pull requests, manual): Ubuntu 24.04, `uv sync --locked`
(`uv.lock` is committed), cached STIX data keyed by ATT&CK and ATLAS versions, a SHA-256 check of
every bundle against the pinned hashes, `ruff check`, then pytest with the coverage gate. Actions
are pinned by commit SHA, permissions are `contents: read`, no secrets are used.

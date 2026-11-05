# Changelog

All notable changes to this fork are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/).

This fork ([oleggohman/mitre-attack-mcp](https://github.com/oleggohman/mitre-attack-mcp))
branches from upstream
[imouiche/complete-mitre-attack-mcp-server](https://github.com/imouiche/complete-mitre-attack-mcp-server)
at commit `243169c`.

## [0.4.0] - 2026-11-05

### Breaking
- **Description defaults.** Tools that return lists now default to `include_description=False`
  (previously `True` for many, for example `search_techniques`, `get_techniques_by_tactic`,
  `get_techniques_by_platform`, the alias lookups, `get_all_mitigations`, `get_all_campaigns` and
  the relationship tools). Single-object lookups (`get_technique_by_id`,
  `get_object_by_attack_id`, `get_object_by_stix_id`, `get_group_by_name`,
  `get_parent_technique_of_subtechnique`) and the procedure-example tools keep `True`.
- **Relationships are opt-in.** The 12 relationship tools (`get_group_techniques`,
  `get_techniques_used_by_group`, `get_software_used_by_group`, `get_groups_using_technique`,
  `get_groups_using_software`, `get_groups_attributing_to_campaign`,
  `get_software_using_technique`, `get_techniques_used_by_software`,
  `get_campaigns_using_technique`, `get_techniques_used_by_campaign`,
  `get_campaigns_using_software`, `get_software_used_by_campaign`) omit the `relationships`
  key unless `include_relationships=True`.
- **`generate_layer`** no longer writes technique descriptions as comments
  (`include_comments=False` by default), emits no `tactic` per entry (the annotation applies
  under every tactic of the technique), and group layers include techniques inherited through
  campaigns by default (G1015: 64 -> 78 techniques; `include_campaigns=False` restores 64).
- `get_objects_created_after` and `get_objects_modified_after` default to `limit=100`
  (the full output was 2-19 MB). Pass `limit=None` for everything.
  `limit=0` or a negative `limit` returns no items but still reports `total` / `has_more`
  (count probe); only `None` means unlimited. Empty successful results carry the same fields.
- `get_techniques_used_by_group_software` no longer returns a `relationships` key (it was
  always empty).

### Changed
- Paginated tools return items sorted by ATT&CK ID (then name, then STIX ID) even without
  `limit`: `get_objects_modified_after`, `get_objects_created_after`, `get_all_subtechniques`,
  `get_all_software`, `get_all_techniques`, `get_software`, `get_techniques_by_platform`,
  `get_all_parent_techniques`, `get_all_groups`, `get_objects_by_type`, `get_group_techniques`,
  `get_techniques_used_by_group`, `get_techniques_used_by_software`,
  `get_techniques_used_by_group_software`.
- `generate_layer` is built from the loaded data instead of re-reading the STIX file and no
  longer uses `UsageLayerGenerator`. It accepts `DC####` data component IDs. Layers carry extra
  default fields (`sorting`, `layout`, `hideDisabled`, `legendItems`, `metadata`, `links`,
  `tacticRowBackground`).
- `get_detection_strategies_for_technique` with `platform` drops detection strategies that have
  no analytic for that platform, so `count` can be 0.
- `generate_technique_layer` rejects unknown keys in object items (for example `colour`,
  `tactic`) and names the offending item index.

### Added
- `get_detection_strategies_for_technique`: technique -> detection strategy (DET) -> analytics
  (AN) -> log sources, with optional `platform` filter.
- `get_datacomponents_detecting_technique` and `get_techniques_detected_by_datacomponent` use the
  ATT&CK v18+ detection-strategy chain when no legacy `detects` relationship exists, accept an
  ATT&CK ID (for example `T1552.005`, `DC0070`), and return `attack_id`, `detection_strategies`,
  `analytics` and `log_sources`.
- Group technique provenance: `direct`, `via_campaigns`, `direct_count`, `campaign_only_count`
  and `include_campaigns` on `get_group_techniques` and `get_techniques_used_by_group`.
- `generate_technique_layer`: Navigator layer from an explicit technique list, for
  enterprise, mobile, ICS and ATLAS. `get_layer_metadata("atlas")` returns the ATLAS template.
- Pagination (`limit`, `offset`; response fields `total`, `returned`, `offset`, `limit`,
  `has_more`; `count` stays the total) on the 14 tools listed under Changed.
- `include_relationships`, `include_campaigns`, `include_comments` and `save_to_file`
  parameters; `MITRE_MCP_LAYER_DIR` (default `~/.mitre-mcp-server/layers`) for saved layers.

- Exhaustive tool smoke suite (every tool x domain, derived from the tool registry), cross-tool
  invariants, stdio protocol tests, fault injection, representation/variant sweeps, a 100 % line
  and branch coverage gate, a GitHub Actions workflow and ruff linting. See `TESTING.md`.

### Fixed
- `get_techniques_used_by_group_software` always returned 0 techniques.
- `get_technique_by_id` ignored `include_description=False`; the same for the 120-character
  teaser in `get_datacomponents_detecting_technique`.
- The two detection tools returned nothing on ATT&CK v18 and later.
- `generate_layer` `D` prefix never matched a real ID; data components are `DC####`.
- `get_layer_metadata` hard-coded ATT&CK version 16; it now reports the bundled release.
- Layer tools no longer print navlayers warnings to stdout (the MCP stream).
- `get_all_subtechniques(remove_revoked_deprecated=False)` omitted revoked subtechniques (16 in
  ATT&CK v20.0 enterprise) because they have lost their `subtechnique-of` relationship. They are
  now listed with `parent_attack_id`, `parent_name` and `parent_stix_id` set to null. The default
  call is unchanged.
- `get_datacomponents_detecting_technique`, `get_tactics_by_matrix` and `get_tactics_by_technique`
  now publish an outputSchema and return a structured result (they lacked a usable return
  annotation).
- `get_revoked_techniques` (and `get_attack_id`) returned `id: null` for revoked mobile
  techniques whose only external reference uses the legacy `mitre-mobile-attack` source name;
  legacy `mitre-mobile-attack` and `mitre-ics-attack` sources are now recognised.
- `get_stats` reported zero counts with a normal message when a data lookup failed. It now returns
  `success: false`, `null` for the failed counts and a message naming the error (`success: true`
  is added to normal responses).
- `get_techniques_used_by_group_software` ignored software that a group only uses through
  attributed campaigns, so it disagreed with `get_software_used_by_group` (G1015: 120 vs 125
  techniques). New `include_campaigns` parameter (default true, same semantics as the group
  tools); `false` restores the direct-only set.
- `get_subtechniques_of_technique` and `get_techniques_mitigated_by_mitigation` raised a tool
  error for an unknown STIX ID; they now return an empty result (`count` 0) with a "not found"
  message like the other lookups.
- `get_group_by_name` and `get_group_techniques` returned the first group whose name or alias
  merely contained the query (for example "APT1" resolved to APT17, "APT3" to APT38). An exact
  name match now wins over an exact alias match, which wins over a partial match.
- `get_group_by_name` and `get_group_techniques` matched every group for an empty or
  whitespace-only query (returning APT38). An empty query now matches nothing. When a partial
  query matches several groups, the group with the lowest ATT&CK ID is still returned, and the
  response adds `ambiguous_matches` (ATT&CK IDs, at most 10) and says so in the message.
- `get_techniques_used_by_group_software` with `include_campaigns=true` returned no techniques at
  all when the lookup for one software failed. The failing software is now skipped and named in a
  new `warnings` list.

### Known issues
- `get_procedure_examples_by_tactic` is broken: it always returns 0 results because it calls a
  method that does not exist on the library and swallows the error (use
  `get_procedure_examples_by_technique`). Tracked as a known bug in the test suite.

## [0.3.0] - 2026-11-03

### Added
- **MITRE ATLAS as a fourth domain (`atlas`)**, pinned to v1.16.0 and verified by
  SHA-256 on download. Existing tools accept `domain="atlas"`. Groups, software,
  campaigns and data sources do not exist in ATLAS and return empty results.
  `generate_layer` returns a clear error for `atlas`.
- `get_all_tactics` entries include `shortname`.

### Changed
- `get_techniques_by_tactic` accepts a tactic display name or a shortname in all
  domains.
- Failed domain downloads are logged to stderr instead of being silently ignored.

### Fixed
- `get_tactics_by_matrix` always returned an empty result (it called the library
  with an argument it does not take). It now resolves the matrix by STIX ID.
- `get_techniques_by_tactic` returned nothing for display names such as
  "Initial Access", although its docstring showed them as examples.
- Tactic and matrix tools now read fields through mapping-safe access, so plain-dict
  results no longer produce null names.
- Relationship-based tools returned null fields or crashed because they treated the
  library's `{"object", "relationships"}` wrapper entries as the objects themselves:
  `get_subtechniques_of_technique`, `get_parent_technique_of_subtechnique`,
  `get_all_subtechniques` (parent fields), `get_campaigns_attributed_to_group`,
  `get_techniques_mitigated_by_mitigation`, `get_techniques_targeting_asset`,
  `get_assets_targeted_by_technique` and `get_techniques_detected_by_datacomponent`.
- `get_all_parent_techniques` returned no results for `atlas` (every ATLAS ID contains
  a dot). It now filters on the sub-technique flag.

## [0.2.0] - 2026-11-02

### Changed
- **Breaking:** migrated to the MCP Python SDK 2.x (`mcp>=2.3.0,<3`).
  `FastMCP` is replaced by `MCPServer`, and the server runs with an explicit
  `stdio` transport. The server now reports its own version (`0.2.0`) in
  `serverInfo`.
- Require `mitreattack-python>=6.3.1,<7`. `stix2`, `httpx` and `pydantic` are no
  longer direct dependencies (none is imported by the server; `stix2` still
  installs through `mitreattack-python`).
- Dev dependencies: `pytest>=9.2.0`, `pytest-asyncio>=1.4.1`, explicit asyncio
  fixture loop scope.
- `get_techniques_by_platform` docstring lists current ATT&CK platform names
  (`IaaS`, `SaaS`, `Identity Provider`, `Office Suite`, …) instead of the
  retired `Cloud` / `Azure AD`.
- Version is now `0.2.0` everywhere: `pyproject.toml`, `__init__.py`,
  `package.json` and `server.json` (they previously disagreed, 0.1.0–0.1.3).

### Fixed
- **Revoked and deprecated objects leaked into results.** These tools now
  exclude them by default and take a `remove_revoked_deprecated` parameter
  (default `True`), like the `get_all_*` tools:
  `get_techniques_by_platform`, `get_objects_by_name`, `get_objects_by_content`,
  `get_objects_created_after`, `get_objects_modified_after`,
  `get_groups_by_alias`, `get_software_by_alias`, `get_campaigns_by_alias`.
  On ATT&CK v20 this removes, for example, 8 of 112 `IaaS` techniques
  (T1522, T1536, T1081, T1108, …).
- `get_groups_by_alias`, `get_software_by_alias` and `get_campaigns_by_alias`
  also returned revoked objects (for example, "Night Dragon" resolved to revoked
  G0014, and "Darkmoon" to revoked S0209). They take the same
  `remove_revoked_deprecated` parameter now.
- The `formatted` text of every tool that uses `format_objects` never showed
  the ATT&CK ID: the whole object was passed to `get_attack_id` instead of its
  STIX ID, and the error was swallowed. Fields of plain-dict results were also
  dropped. Both are fixed.
- `get_objects_created_after` crashed (`'dict' object has no attribute 'id'`)
  and `get_objects_modified_after` returned `null` STIX IDs once the library
  returned plain dicts. Both now use mapping access.
- **npm launcher (`run.js`)** called a bare `python` and never installed the
  Python dependencies, so `npx @imouiche/mitre-attack-mcp-server` failed with
  `spawn python ENOENT` on systems that only ship `python3`, and with
  `ImportError` everywhere else. It now runs the server through
  `uvx --from <package dir>`, which installs dependencies from the bundled
  `pyproject.toml`, and falls back to `python3`, then `python`.
- Fresh installs crashed with `No module named 'mcp.server.fastmcp'`, because the
  unbounded `mcp>=1.1.0` requirement resolved to mcp 2.x.

### Removed
- `src/mitre_mcp_server/data/`: an unused duplicate of the download code (it also
  printed to stdout on import, which would corrupt the MCP stdio stream). Its
  bundled ATT&CK v18.1 STIX files (~60 MB) were never read and were also packed
  into the wheel. ATT&CK data is downloaded to `~/.mitre-mcp-server/data/` on
  first start.
- `test_parser_quick.py` (imported a module that does not exist) and the empty
  `temp-config.json`.
- Dead code found by lint: a duplicate mid-file import, a discarded
  `format_objects` call, and a write-only variable.

### Added
- Regression tests in `tests/test_revoked_filters.py`.
- `LICENSE` with the Apache-2.0 text. The project was declared Apache-2.0
  but shipped no license file; it is now also part of the npm `files` list.
- This changelog.

### Documentation
- README rewritten to match the code: uvx-based install from this fork,
  Claude Code and Claude Desktop setup, configuration (`MITRE_MCP_DATA_DIR`),
  revoked/deprecated filtering, current platform names, known limitations,
  and all 65 tools by category. Removed badges and install routes that point
  to upstream's npm, PyPI and MCP Registry listings, and claims the code does
  not support.
- Tool count in `package.json` / `server.json` descriptions corrected to 65
  (was "50+").

[0.2.0]: https://github.com/oleggohman/mitre-attack-mcp/compare/243169c...main

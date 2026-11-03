# Changelog

All notable changes to this fork are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/).

This fork ([oleggohman/mitre-attack-mcp](https://github.com/oleggohman/mitre-attack-mcp))
branches from upstream
[imouiche/complete-mitre-attack-mcp-server](https://github.com/imouiche/complete-mitre-attack-mcp-server)
at commit `243169c`.

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

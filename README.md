# MITRE ATT&CK and ATLAS MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io) server that exposes two MITRE knowledge bases to LLM clients through 67 tools:

- **MITRE ATT&CK** (Enterprise, Mobile and ICS domains), loaded with [`mitreattack-python`](https://github.com/mitre-attack/mitreattack-python).
- **MITRE ATLAS** (adversarial threats to AI systems), loaded from the official ATLAS STIX bundle as the fourth domain, `atlas`.

The server serves both over stdio. Most tools take a `domain` argument: `enterprise`, `mobile`, `ics` or `atlas`.

This repository is a fork of [imouiche/complete-mitre-attack-mcp-server](https://github.com/imouiche/complete-mitre-attack-mcp-server) by Dr. Inoussa Mouiche, licensed under Apache-2.0. The original design and tool set are his work. See [Changes in this fork](#changes-in-this-fork).

- Version: 0.4.0
- Python: 3.12 or newer
- Dependencies: `mcp>=2.3.0,<3` (MCPServer API), `mitreattack-python>=6.3.1,<7`
- Tools: 67 (one `@mcp.tool` decorator each in `server.py`)

## Install and run

The server is not published to PyPI or npm from this fork. Run it straight from Git with [uv](https://docs.astral.sh/uv/).

### First start downloads data

On first start the server downloads the STIX data for all four domains (see [Data sources](#data-sources)): about 60 MB for ATT&CK and about 0.4 MB for ATLAS. That can take longer than an MCP client's connect timeout. Run it once in a terminal first, wait for `Server ready!` on stderr, then stop it with Ctrl+C:

```bash
uvx --python 3.12 --from git+https://github.com/oleggohman/mitre-attack-mcp mitre-mcp-server
```

If the ATLAS download fails (network error or SHA-256 mismatch), the ATT&CK domains still load and the server starts without `atlas`. The download is retried on every start while ATLAS is missing.

Later starts reuse the cached data.

### Claude Code

```bash
claude mcp add mitre-attack -s user -- uvx --python 3.12 --from git+https://github.com/oleggohman/mitre-attack-mcp mitre-mcp-server
```

### Claude Desktop

Add to `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`, Windows: `%APPDATA%\Claude\claude_desktop_config.json`), then restart Claude Desktop:

```json
{
  "mcpServers": {
    "mitre-attack": {
      "command": "uvx",
      "args": [
        "--python", "3.12",
        "--from", "git+https://github.com/oleggohman/mitre-attack-mcp",
        "mitre-mcp-server"
      ]
    }
  }
}
```

### Local development

```bash
git clone https://github.com/oleggohman/mitre-attack-mcp.git
cd mitre-attack-mcp
uv sync
uv run mitre-mcp-server   # start the server on stdio
uv run pytest             # run the tests
```

ATLAS tests are skipped when the ATLAS bundle is not available locally. Set `MITRE_MCP_REQUIRE_ATLAS=1` to make them fail instead of skip (useful in CI).

### npm launcher (`run.js`)

`package.json` and `run.js` are inherited from upstream. `run.js` starts the server by trying `uvx`, then `python3`, then `python` (the last two with `src/` on `PYTHONPATH` and the dependencies already installed). It moves to the next launcher only when a command is missing from `PATH`. If `uvx` is present but fails (for example offline on first install), or `python3` lacks the dependencies, it exits with that error and does not try the next one. The npm package `@imouiche/mitre-attack-mcp-server` belongs to upstream and is not published by this fork.

## Data sources

| Domain | Source | Version | Download size | Integrity |
|---|---|---|---|---|
| `enterprise`, `mobile`, `ics` | ATT&CK STIX 2.1 files fetched by `mitreattack-python` (`download_stix`) | `release_info.LATEST_VERSION` of the installed `mitreattack-python`, resolved at runtime (v20.0 at the time of writing) | about 60 MB for the three domains | Expected hash taken from `mitreattack.release_info` |
| `atlas` | `https://raw.githubusercontent.com/mitre-atlas/atlas-navigator-data/v<ATLAS_VERSION>/dist/stix-atlas.json` | Pinned in `server.py`: `ATLAS_VERSION = "1.16.0"` | about 0.4 MB | SHA-256 checked against `ATLAS_SHA256`; a mismatch raises and leaves no file |

ATLAS is not part of `mitreattack.release_info`, so its version does not follow the ATT&CK release and is never updated automatically.

Cache layout under `MITRE_MCP_DATA_DIR` (default `~/.mitre-mcp-server/data`):

```text
<data dir>/
  v20.0/                     # ATT&CK release (v<release_info.LATEST_VERSION>)
    enterprise-attack.json
    mobile-attack.json
    ics-attack.json
  atlas-v1.16.0/             # atlas-v<ATLAS_VERSION>
    stix-atlas.json
```

Bumping ATLAS: in `src/mitre_mcp_server/server.py`, set `ATLAS_VERSION` to the new tag of `mitre-atlas/atlas-navigator-data` and `ATLAS_SHA256` to the SHA-256 of `dist/stix-atlas.json` at that tag. A new `atlas-v<version>/` directory is downloaded on the next start; the old one is left in place.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `MITRE_MCP_DATA_DIR` | `~/.mitre-mcp-server/data` | Directory for downloaded data (layout in [Data sources](#data-sources)). |
| `MITRE_MCP_LAYER_DIR` | `~/.mitre-mcp-server/layers` | Directory for Navigator layers written with `save_to_file=True`. Files are created there only (mode 0600, never overwritten); clients cannot choose a path. |
| `MITRE_MCP_REQUIRE_ATLAS` | unset | Tests only: set to `1` to make ATLAS tests fail instead of skip when the bundle is missing. |

The server logs to stderr only, because stdout carries the MCP stream.

## ATLAS support

`atlas` uses the same tools as the ATT&CK domains. The ATLAS STIX bundle contains techniques, sub-techniques, tactics, one matrix, mitigations and `mitigates` / `subtechnique-of` relationships, so only tools that read those return data.

| Result for `domain="atlas"` | Tools |
|---|---|
| Returns data | Techniques, sub-techniques and parent techniques (`get_all_techniques`, `get_all_parent_techniques`, `get_all_subtechniques`, `get_subtechniques_of_technique`, `get_parent_technique_of_subtechnique`, `get_technique_by_id`); tactics (`get_all_tactics`, `get_techniques_by_tactic`, `get_technique_tactics`, `get_tactics_by_technique`); matrix (`get_all_matrices`, `get_tactics_by_matrix`); mitigations (`get_all_mitigations`, `get_mitigations_mitigating_technique`, `get_techniques_mitigated_by_mitigation`); search and lookup (`search_techniques`, `get_object_by_attack_id`, `get_object_by_stix_id`, `get_objects_by_name`, `get_objects_by_content`) |
| Empty result | Groups, software, campaigns, data sources and data components, ICS assets, procedure examples (`get_all_groups`, `get_all_software`, `get_all_campaigns`, `get_all_datasources`, `get_all_datacomponents`, `get_all_assets`, `get_procedure_examples_by_technique`, and the tools built on those objects) |
| Layers | `generate_technique_layer(domain="atlas")` and `get_layer_metadata("atlas")` (see [Layers](#navigator-layers)). `generate_layer` is rejected for `atlas` with a pointer to `generate_technique_layer` |
| No detection strategies | `get_detection_strategies_for_technique` returns `count: 0` |

ATLAS IDs: `AML.T0051` (technique), `AML.T####.###` for sub-techniques, `AML.M0004` (mitigation), `AML.TA0001` (tactic). Technique and mitigation tools that take a `*_stix_id` need the STIX ID, not the `AML.` ID; resolve it with `get_object_by_attack_id`.

### Example: AI threat-model lookup

Tool names and arguments only; responses depend on the loaded ATLAS release.

1. List the ATLAS tactics: `get_all_tactics(domain="atlas")`. Each entry includes `name`, `shortname` and `attack_id`.
2. List techniques for one tactic: `get_techniques_by_tactic(tactic="AI Attack Staging", domain="atlas")`. The shortname `"ai-attack-staging"` works too.
3. Resolve a technique to its STIX ID: `get_object_by_attack_id(attack_id="AML.T0051", stix_type="attack-pattern", domain="atlas")`. The `stix_id` field of the returned object is the STIX ID.
4. Get mitigations for it: `get_mitigations_mitigating_technique(technique_stix_id="<stix_id from step 3>", domain="atlas")`.
5. Search by keyword: `search_techniques(query="prompt injection", domain="atlas")`.

## Behavior notes

- **Revoked and deprecated objects are excluded by default.** These tools take `remove_revoked_deprecated` (default `True`); pass `False` to include them: `get_objects_by_name`, `get_objects_by_content`, `get_all_techniques`, `get_all_subtechniques`, `get_all_parent_techniques`, `get_all_groups`, `get_all_software`, `get_all_mitigations`, `get_all_matrices`, `get_all_campaigns`, `get_all_datasources`, `get_all_datacomponents`, `get_all_assets`, `get_techniques_by_platform`, `get_objects_by_type`, `get_objects_created_after`, `get_objects_modified_after`, `get_groups_by_alias`, `get_software_by_alias`, `get_campaigns_by_alias`. Use `get_revoked_techniques` to list revoked techniques.
- **Domains** are `enterprise` (default for most tools), `mobile`, `ics` and `atlas`. See [ATLAS support](#atlas-support) for what `atlas` returns.
- **Tactic names**: `get_techniques_by_tactic` accepts a display name (`Initial Access`, `AI Attack Staging`) or a shortname (`initial-access`, `ai-attack-staging`) in every domain. `get_all_tactics` now also returns each tactic's `shortname`.
- **Platform names are case-sensitive** and must match ATT&CK `x_mitre_platforms` values, for example `Windows`, `Linux`, `macOS`, `IaaS`, `SaaS`, `Identity Provider`, `Office Suite`, `Containers`, `ESXi`, `Network Devices`. Used by `get_techniques_by_platform`.
- **Descriptions are off by default for list tools.** Tools that return lists default to `include_description=False`; single-object lookups (`get_technique_by_id`, `get_object_by_attack_id`, `get_object_by_stix_id`, `get_group_by_name`, `get_parent_technique_of_subtechnique`) and the procedure-example tools keep `True`. With `False`, no object description appears anywhere in the result (structured data and `formatted`).
- **Relationships are opt-in.** The 12 relationship tools (for example `get_group_techniques`, `get_techniques_used_by_software`, `get_groups_using_technique`) omit the raw `relationships` records, including procedure text, unless `include_relationships=True`.
- **Pagination and ordering.** `limit` / `offset` exist on `get_objects_modified_after`, `get_objects_created_after` (both default `limit=100`), `get_all_subtechniques`, `get_all_software`, `get_all_techniques`, `get_software`, `get_techniques_by_platform`, `get_all_parent_techniques`, `get_all_groups`, `get_objects_by_type`, `get_group_techniques`, `get_techniques_used_by_group`, `get_techniques_used_by_software` and `get_techniques_used_by_group_software`. The response adds `total`, `returned`, `offset`, `limit` and `has_more`; `count` is the total number of matches and `formatted` covers only the returned page. These tools always return items sorted by ATT&CK ID, so pages are stable. Pass `limit=None` to get everything; `limit=0` (or any negative value) returns no items but still reports `total` and `has_more`, which makes it a cheap count probe. Every successful response, including an empty one, carries these fields; error responses for invalid input (for example an invalid domain or timestamp) may omit them.
- **Group provenance.** `get_group_techniques` and `get_techniques_used_by_group` mark each technique with `direct` (the group uses it) and `via_campaigns` (campaigns attributed to the group that use it), plus `direct_count` and `campaign_only_count`. `include_campaigns=False` keeps only direct techniques.
- **Detection (ATT&CK v18+).** `get_detection_strategies_for_technique` returns detection strategies (DET), their analytics (AN) and log sources (data component, name, channel); `platform` filters analytics (case-insensitive) and strategies without a matching analytic are dropped. `get_datacomponents_detecting_technique` and `get_techniques_detected_by_datacomponent` use the same chain when no legacy `detects` relationship exists and accept ATT&CK IDs (`T1552.005`, `DC0070`) as well as STIX IDs. Data sources (`DS####`) are deprecated in v18+, so `data_source_*` fields are null and `get_all_datasources` is empty by default.

### Navigator layers

- `generate_layer` takes group, mitigation, software or data component IDs (`G####`, `M####`, `S####`, `DC####`). Technique IDs are rejected with a pointer to `generate_technique_layer`. Parameters: `score`, `include_campaigns` (groups, default `True`), `include_comments` (default `False`; adds technique descriptions) and `save_to_file`.
- `generate_technique_layer` builds a layer from a list of technique IDs or objects `{technique_id, score?, color?, comment?}` (1-2000 items, IDs are case-insensitive, unknown keys are rejected). It reports `unknown_ids`, revoked/deprecated `skipped` IDs and `auto_added_parents`. `count` covers the selected techniques only.
- Entries carry no `tactic`, so each annotation applies under every tactic of the technique. A sub-technique whose parent is not listed gets a bare parent entry with `showSubtechniques`.
- `save_to_file=True` writes the layer to `MITRE_MCP_LAYER_DIR` and returns `layer_path` instead of the layer. Filenames are built from the layer name plus a UTC timestamp and are ASCII-only (other characters in the name become `-`) for portability.
- Layer tools build plain dictionaries and print nothing to stdout.
- **ATLAS layers** use the domain `atlas-atlas` and layer format 4.3, mirroring MITRE's published ATLAS Navigator layers. The format was checked by automated structural tests only and **has not been load-tested in the live ATLAS Navigator**, which serves data from the deprecated `atlas-navigator-data` main branch; technique IDs newer than that data may be ignored.

## Known limitations

- ATLAS case studies are not included (they are not in the STIX bundle). ATLAS layers are not load-tested in the live ATLAS Navigator (see [Navigator layers](#navigator-layers)).
- `get_procedure_examples_by_tactic` always returns 0 results: it calls a method that does not exist on the library and swallows the error. Use `get_procedure_examples_by_technique` meanwhile.
- The ATLAS release is pinned and not auto-updated (see [Data sources](#data-sources)).
- The first start needs network access to download the ATT&CK and ATLAS STIX data (see [First start downloads data](#first-start-downloads-data)).

## Tools

67 tools, grouped here by purpose. Each takes a `domain` argument (`enterprise`, `mobile`, `ics`, `atlas`) where it applies; groups, software, campaigns, data sources and assets are empty for `atlas` (see [ATLAS support](#atlas-support)). See the docstrings in [`src/mitre_mcp_server/server.py`](src/mitre_mcp_server/server.py) for full parameters and return shapes.

### Data and statistics

| Tool | Description |
|---|---|
| `get_data_stats` | Download status and statistics of the STIX data on disk |
| `get_stats` | Basic statistics about the loaded data for a domain |

### Lookup and conversion

| Tool | Description |
|---|---|
| `get_object_by_attack_id` | Any object by ATT&CK ID and STIX type |
| `get_object_by_stix_id` | Any object by STIX ID (UUID) |
| `get_objects_by_name` | Objects by exact, case-sensitive name |
| `get_objects_by_content` | Objects whose description contains given text |
| `get_objects_by_type` | All objects of a STIX type |
| `get_stix_type` | STIX type for a STIX ID |
| `get_attack_id` | ATT&CK ID for a STIX UUID |
| `get_name` | Object name for a STIX ID |
| `get_objects_created_after` | Objects created after a timestamp |
| `get_objects_modified_after` | Objects modified after a timestamp |

### Techniques

| Tool | Description |
|---|---|
| `get_technique_by_id` | Technique by ATT&CK ID (for example `T1055`) |
| `search_techniques` | Keyword search over technique names and descriptions |
| `get_all_techniques` | All techniques in a domain |
| `get_all_parent_techniques` | Parent techniques only |
| `get_all_subtechniques` | All subtechniques |
| `get_subtechniques_of_technique` | Subtechniques of a parent technique |
| `get_parent_technique_of_subtechnique` | Parent of a subtechnique |
| `get_techniques_by_tactic` | Techniques under a tactic |
| `get_techniques_by_platform` | Techniques that apply to a platform |
| `get_technique_tactics` | Tactic names for a technique |
| `get_revoked_techniques` | Revoked techniques |
| `get_procedure_examples_by_technique` | How groups used a technique |
| `get_procedure_examples_by_tactic` | Procedure examples for all techniques in a tactic |

### Tactics and matrices

| Tool | Description |
|---|---|
| `get_all_tactics` | All tactics in a domain |
| `get_all_matrices` | All matrices in a domain |
| `get_tactics_by_matrix` | Tactics in a matrix |
| `get_tactics_by_technique` | Tactics associated with a technique |

### Groups

| Tool | Description |
|---|---|
| `get_group_by_name` | Group by name or alias (case-insensitive) |
| `search_groups` | Search groups by name, alias or description |
| `get_all_groups` | All groups in a domain |
| `get_groups_by_alias` | Groups matching an alias |
| `get_group_techniques` | Techniques used by a group |
| `get_techniques_used_by_group` | Techniques used by a group, by STIX ID |
| `get_techniques_used_by_group_software` | Techniques via the software a group uses |
| `get_software_used_by_group` | Software used by a group |
| `get_campaigns_attributed_to_group` | Campaigns attributed to a group |
| `get_groups_using_technique` | Groups that use a technique |
| `get_groups_using_software` | Groups that use a software entry |
| `get_groups_attributing_to_campaign` | Groups attributed to a campaign |

### Software

| Tool | Description |
|---|---|
| `get_software` | All software (malware and tools) in a domain |
| `get_all_software` | All software in a domain, with revoked/deprecated filtering |
| `search_software` | Search software by name, alias or description |
| `get_software_by_alias` | Software by alias |
| `get_software_using_technique` | Software that uses a technique |
| `get_techniques_used_by_software` | Techniques used by a software entry |

### Campaigns

| Tool | Description |
|---|---|
| `get_all_campaigns` | All campaigns in a domain |
| `get_campaigns_by_alias` | Campaigns by alias |
| `get_campaigns_using_technique` | Campaigns that use a technique |
| `get_campaigns_using_software` | Campaigns that use a software entry |
| `get_techniques_used_by_campaign` | Techniques used in a campaign |
| `get_software_used_by_campaign` | Software used in a campaign |

### Mitigations

| Tool | Description |
|---|---|
| `get_all_mitigations` | All mitigations in a domain |
| `get_mitigations_mitigating_technique` | Mitigations that address a technique |
| `get_techniques_mitigated_by_mitigation` | Techniques a mitigation addresses (by STIX ID) |

### Data sources and detection

| Tool | Description |
|---|---|
| `get_all_datasources` | All data sources in a domain |
| `get_all_datacomponents` | All data components in a domain |
| `get_detection_strategies_for_technique` | Detection strategies, analytics and log sources for a technique (ATT&CK v18+) |
| `get_datacomponents_detecting_technique` | Data components that detect a technique (detection-strategy chain on v18+) |
| `get_techniques_detected_by_datacomponent` | Techniques detected by a data component (detection-strategy chain on v18+) |

### ICS assets

| Tool | Description |
|---|---|
| `get_all_assets` | All assets in a domain (primarily ICS) |
| `get_assets_targeted_by_technique` | ICS assets targeted by a technique |
| `get_techniques_targeting_asset` | Techniques that target an ICS asset |

### Navigator layers

| Tool | Description |
|---|---|
| `generate_layer` | Navigator layer for a group, mitigation, software or data component ID (`G`/`M`/`S`/`DC`), with `score` and `domain` |
| `generate_technique_layer` | Navigator layer from an explicit list of technique IDs (ATT&CK domains and ATLAS) |
| `get_layer_metadata` | Default Navigator layer metadata template for a domain (including `atlas`) |

To view a layer, use `save_to_file=True` (or save the returned `layer` JSON) and open it in the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) or, for ATLAS, the [ATLAS Navigator](https://mitre-atlas.github.io/atlas-navigator/).

## Example prompts

- "What techniques does APT29 use?"
- "List Windows techniques under the persistence tactic."
- "Which mitigations address T1055?"
- "Generate a Navigator layer for group G0016."
- "Which campaigns used Cobalt Strike?"
- "List the ATLAS tactics."
- "Which ATLAS techniques fall under AI Attack Staging?"
- "What mitigations does ATLAS list for AML.T0051?"

## Repository layout

- `src/mitre_mcp_server/server.py` - server, data download/loading, all tools
- `tests/` - pytest suite: revoked/deprecated filtering, ATLAS download and tools, tactic tools, enterprise regression
- `run.js`, `package.json`, `server.json` - upstream npm launcher and registry metadata
- `CHANGELOG.md` - change history of this fork

## Changes in this fork

This fork branches from upstream commit `243169c`. In short: migration to the MCP Python SDK 2.x and current dependencies, MITRE ATLAS as a fourth domain (`atlas`), exclusion of revoked/deprecated objects by default, fixed `get_tactics_by_matrix` and tactic-name handling in `get_techniques_by_tactic`, removal of dead code and stale bundled ATT&CK data, a fixed npm launcher, and lint cleanup. Details are in [CHANGELOG.md](CHANGELOG.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

## Credits

- Original project: [imouiche/complete-mitre-attack-mcp-server](https://github.com/imouiche/complete-mitre-attack-mcp-server) by Dr. Inoussa Mouiche (WASP Lab, University of Windsor).
- [MITRE ATT&CK](https://attack.mitre.org/) data via [mitreattack-python](https://github.com/mitre-attack/mitreattack-python).
- [MITRE ATLAS](https://atlas.mitre.org/) data from [mitre-atlas/atlas-navigator-data](https://github.com/mitre-atlas/atlas-navigator-data).

MITRE ATT&CK is a registered trademark of The MITRE Corporation.

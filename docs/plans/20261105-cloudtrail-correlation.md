# Plan: CloudTrail store with GuardDuty / Security Hub correlation and ATT&CK / ATLAS mapping

Revision 3 (after plan review cycle 2, 2026-11-05). Status: APPROVED (plan review cycle 3).

Approval notes for the builder (Task 8 sample test wording):
- N1: no sample finding carries ATTACKER_SESSION_KEY, so ASIA events get no key signal. Expect: at default min_score the ASIA call from ATTACKER_IP is absent; at min_score=40 it is present with reasons == {principal, source_ip} and key_class null; the ASIA call from the third IP is absent at every threshold. The access_key_temporary class is covered by unit tests (b)(c)(d) only.
- N2: assert StopLogging is rank 1 with score >= 90 (a merged finding's resource ARN may add +15, capped at 100).

Review cycle 2 resolutions (owner accepted the reviewer's fixes verbatim): C1 long-term access
keys (AKIA) score 50 and qualify alone; temporary keys (ASIA / other) score 40 and need a second
signal; key points are not time-decayed (D15) · C2 sample has attacker-key calls from a second IP
(`ATTACKER_IP_2`) · C3 `test_cov_shapes` classification: empty tactic catalogue = data failure,
matrix order from `x-mitre-matrix` `tactic_refs`, per-tool classification by measurement.

Owner requirement (verbatim): "research the best practice, in the end SOC must be able to search
for events in your simulated cloudtrail DB of logs".

Review cycle 1 resolutions (R-numbers match the review items):
R1 tool counts in README/package.json/server.json updated in every task that adds tools; tests
assert `len(tools) == len(ARGS)`, never a literal · R2 `tests/test_cov_shapes.py` guard + tool
classification · R3 `load_*` responses: `files` int, `records` aggregate, string-only lists ·
R4 `store.connect()` context manager closes · R5 entity predicates in SQL, 7-day span cap,
`window_clamped` · R6 scoring: principal signals only without key match, `min_score` 50, ≥ 2
entity signals (owner: adopt) · R7 Defense Evasion → `["TA0112", "TA0005"]` · R8 confidence
model (owner: adopt) · R9 file open/walk/decompression hardening · R10 `sort` Literal, backslash
escaping, `in_guardduty`/`in_securityhub` · R11 entity union + `raw_guardduty`/`raw_asff`
(owner decision) · R12 case-insensitive GuardDuty matching · R13 exact "Invalid domain" message,
domain check first · R14 session-DB isolation rule · R15 tasks split and renumbered (owner:
adopt); Security Hub EventBridge envelope and Insights records dropped; scale task optional ·
R16 secrets scan scope, no secret-key-shaped values · R17 import size guidance, duration, no
stdout.

## Overview

SOC analysts get MCP tools to:

1. load CloudTrail logs, GuardDuty findings and Security Hub (ASFF) findings from local files
   or pasted JSON into a local SQLite store (the "simulated CloudTrail DB");
2. load a built-in, deterministic, synthetic attack scenario (stolen access key → discovery →
   LLMjacking on Amazon Bedrock → persistence → log tampering) so the store is usable with no
   real logs;
3. search events by time range, eventName, eventSource, principal ARN, user name, access key ID,
   source IP, region, account, errorCode, resource ARN, user agent, success/readOnly, mapped
   technique and free text, and stack-count them ("top N by field");
4. search findings and correlate one finding with the CloudTrail events around it (shared access
   key, principal, IP, API, resource, time window) with an explainable score;
5. map events and findings to ATT&CK Enterprise (IaaS) and ATLAS techniques with a confidence
   level, using a vendored, provenance-tagged mapping file validated against the server's
   ATT&CK v20.0 / ATLAS 1.16.0 data;
6. build an incident timeline and an ATT&CK / ATLAS Navigator layer of observed techniques
   (reusing `_build_navigator_layer` and `_save_layer`).

MVP is offline only: no AWS credentials, no network at runtime, zero new dependencies. 11 new
tools (67 → 78).

## Context (from discovery)

Repository facts (verified 2026-11-05 on `main` @ `95c181e`):

- `src/mitre_mcp_server/server.py` is 9,681 lines with 67 `@mcp.tool()` tools on one
  `MCPServer` instance `mcp` (server.py:717). Helpers to reuse: `_field` (:505), `_paginate`
  (:606, limit None = no limit, ≤0 = count probe, negative offset → 0), `_build_navigator_layer`
  (:9246, handles `atlas` → `atlas-atlas`, layer 4.3), `_save_layer` (:9314, slug + UTC stamp,
  0700 dir / 0600 file, refuses paths outside `LAYER_DIR`), `_layer_error` (:9343),
  `_MAX_LAYER_COMMENT = 2000` (:9238), `get_attack_data` (:452). Directory constants are module
  globals from env read at import: `DATA_DIR` (:41, `MITRE_MCP_DATA_DIR`), `LAYER_DIR` (:50,
  `MITRE_MCP_LAYER_DIR`, `.expanduser().resolve()`).
- The protocol test runs the server as `python -m mitre_mcp_server.server`
  (tests/test_protocol.py:62). Under `-m` the module is `__main__`; a sub-module that did
  `from mitre_mcp_server import server` would import a **second copy** of server.py and register
  tools on a different `mcp`. The new package therefore must never import `server`; server.py
  passes itself in (D3). (Reviewer verified this wiring.)
- ruff selects E/F/W/I/B, so a late `import` at the bottom of server.py fails E402 and `noqa` is
  banned. Import at the top, call `register()` at the bottom.
- **Tool counts are tested.** `tests/test_testing_plan_fixes.py:97-106` requires every
  `"<N> tools"` in README.md to equal the registry size; README.md:3, :15, :163 say 67.
  `package.json` description and `server.json` description also say 67 (not tested, kept in
  sync). Every task that adds tools updates all of them in the same task.
- Test harness constraints every new tool must satisfy (tests/tool_args.py,
  tests/test_smoke_tools.py, tests/test_cov_variants.py, tests/test_cov_faults.py,
  tests/test_cov_shapes.py):
  - one `ARGS` entry per tool (`test_registry_matches_table`);
  - default call non-empty (`nonempty()`: `count`/`returned`/`total` > 0), non-empty `message`,
    `success`/`found` True;
  - count semantics (test_smoke_tools.py:255-276): with `total` → `count == total`,
    `returned == len(some list)`, `has_more` consistent; with only `count` → if any list of dicts
    exists, `count` must equal the length of one of them; if `count == 0` all lists are empty;
  - tools with `limit` are paged by `test_cov_variants.py` with `limit=None`, `1`, `0`, `-1`,
    `offset` beyond the end, comparing `item["stix_id"]` (test_cov_variants.py:196, 205, 298);
  - tools with a `domain` parameter run in all four domains plus `bogus`;
  - `neg=True` replaces string args whose key matches
    `(^|_)(stix_id|id|attack_id|name|alias|query|content|platform|tactic)$` with ghost values
    (tool_args.py:569) — e.g. `access_key_id`, `event_name`, `finding_id`, `technique_id`;
  - fault injection replaces `server.get_attack_data`; a tool that does not read ATT&CK data
    needs `fault_na`, and `test_fault_na_cells_have_reasons` hard-codes the allowed set
    `{"get_layer_metadata", "get_data_stats"}` (tests/test_cov_faults.py:60);
  - `tests/test_cov_shapes.py` builds `CELLS` from every tool with `fault_na is None`
    (:22-27) and its `run()` (:129-130) calls `require_domain(domain)` unconditionally, so a
    no-domain tool (`domain is None`) fails there under `MITRE_MCP_REQUIRE_DATA=1`. The tools
    that read ATT&CK (`map_cloud_activity`, `build_incident_timeline`, `generate_incident_layer`)
    also need a classification in `UNAFFECTED_BY_FAILING_QUERIES` / `UNAFFECTED_BY_EMPTY_RESULTS`
    (:238-262) or a reasoned exclusion;
  - default wire size ≤ 100,000 bytes; the SDK sends each result twice (text + structured), so
    aim for ≤ 60 kB measured.
- `tests/conftest.py` has an autouse state guard for `server.attack_data` / `_loaded_domains`
  only; nothing isolates new on-disk state — a session fixture must redirect the store to a temp
  dir, or tests would write into `~/.mitre-mcp-server/`.
- `package.json` `files` ships only `src/**/*.py`; the JSON mapping file needs `src/**/*.json`.
  Wheel builds (hatch) include package data.
- Local data: ATT&CK v20.0 and ATLAS 1.16.0 in `~/.mitre-mcp-server/data/`. Python 3.12.16 in
  `.venv`, SQLite 3.53.1 with FTS5 and JSON functions compiled in; DuckDB not installed.
- **ATT&CK v20 changes that break published cloud mappings** (verified in the local bundle,
  confirmed by the reviewer): TA0005 is now named "Stealth" (shortname `stealth`); new tactic
  TA0112 "Defense Impairment" (`defense-impairment`); all of T1562 is revoked, e.g. T1562.008 →
  T1685.002 "Disable or Modify Cloud Log", T1562.001 → T1685, T1562.007 → T1686.001 "Cloud
  Firewall". CTID (ATT&CK 16.1), Stratus Red Team and the AWS Threat Technique Catalog still cite
  T1562.*. T1496.004 "Cloud Service Hijacking" lists platform `SaaS` only (not IaaS); T1580,
  T1619 are `IaaS`; T1530 is IaaS/SaaS/Office Suite.

## Research findings

Sources fetched 2026-11-05. "Unverified" marks claims not confirmed from a primary source.

### How SOCs search and correlate today

- **CloudTrail record fields** (eventTime, eventSource, eventName, awsRegion, sourceIPAddress,
  userAgent, errorCode/errorMessage, requestParameters ≤100 KB, responseElements, eventID GUID
  "use as a primary key", readOnly, resources[ARN, accountId, type], recipientAccountId,
  eventCategory, sharedEventID, tlsDetails, sessionCredentialFromConsole). sourceIPAddress can be
  a service DNS name or `AWS Internal/#`.
  <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html>
- **LookupEvents** returns `Events[]` with `EventId, EventName, ReadOnly, AccessKeyId, EventTime,
  EventSource, Username, Resources, CloudTrailEvent` where `CloudTrailEvent` is a JSON *string*
  of the full record. <https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_Event.html>
- **CloudTrail Lake** (SQL over event data stores) is closed to new customers from 2026-05-31;
  the AWS-documented alternatives are trails to S3 + Athena and Security Lake. So raw S3 trail
  files (gzipped JSON `{"Records": [...]}`) are the primary input format.
  <https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake.html>,
  <https://docs.aws.amazon.com/athena/latest/ug/cloudtrail-logs.html>
- **Security Lake** normalises CloudTrail to OCSF 1.1.0 classes "API Activity", "Authentication",
  "Account Change" and Security Hub CSPM findings to "Detection/Compliance/Vulnerability Finding",
  stored as Parquet.
  <https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html>
- **New AWS Security Hub** (distinct from "Security Hub CSPM") produces and receives findings in
  OCSF; ASFF remains the CSPM format.
  <https://docs.aws.amazon.com/securityhub/latest/userguide/what-is-securityhub-v2.html>
- **Amazon Detective** sets an investigation's scope time to the finding's first/last observed
  window, minimum 1 hour, on hour boundaries, and compares with the 45 days before.
  <https://docs.aws.amazon.com/detective/latest/userguide/scope-time-managing.html>.
  Detective's exact entity list is **unverified** (page did not render).
- **Join keys**:
  - GuardDuty `resource.accessKeyDetails{accessKeyId, principalId, userName, userType}` ↔
    CloudTrail `userIdentity.accessKeyId / principalId / userName`.
    <https://docs.aws.amazon.com/guardduty/latest/APIReference/API_AccessKeyDetails.html>
  - GuardDuty `service.action.awsApiCallAction{api, serviceName, callerType, errorCode,
    userAgent, remoteIpDetails.ipAddressV4, affectedResources}` ↔ CloudTrail `eventName`,
    `eventSource`, `errorCode`, `userAgent`, `sourceIPAddress`.
    <https://docs.aws.amazon.com/guardduty/latest/APIReference/API_AwsApiCallAction.html>
  - GuardDuty `service.eventFirstSeen / eventLastSeen / count` bound the activity window;
    findings are aggregated and updated over time.
    <https://docs.aws.amazon.com/guardduty/latest/APIReference/API_Service.html>,
    <https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_eventbridge.html>
  - ASFF `Resources[]{Type, Id}` with `AwsIamAccessKey{AccessKeyId, PrincipalId, PrincipalName}`,
    `Action.AwsApiCallAction{Api, ServiceName, RemoteIpDetails.IpAddressV4}`,
    `Network.SourceIpV4`, `ProductFields` (`aws/guardduty/service/...` flattened keys),
    `FindingProviderFields.Types`, `FirstObservedAt/LastObservedAt`.
    <https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format-syntax.html>
  - A GuardDuty finding in ASFF has `Id` = the GuardDuty finding ARN (example in
    <https://docs.aws.amazon.com/guardduty/latest/ug/securityhub-integration.html>), so native and
    ASFF copies merge on that ARN.
- **Casing differs by export path**: `aws guardduty get-findings` (CLI/boto3) is PascalCase
  <https://docs.aws.amazon.com/cli/latest/reference/guardduty/get-findings.html>; the API and the
  EventBridge `detail` object are camelCase (`$.detail.accountId`, envelope
  `"detail-type": "GuardDuty Finding"`)
  <https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_eventbridge.html>. The
  parser reads keys case-insensitively. The Security Hub EventBridge envelope is **unverified**
  and is not supported in the MVP (follow-up).

### Existing mappings to ATT&CK / ATLAS

- **GuardDuty finding types** follow `ThreatPurpose:ResourceTypeAffected/ThreatFamilyName.
  DetectionMechanism!Artifact`; threat purposes Backdoor, Behavior, CredentialAccess,
  Cryptocurrency, DefenseEvasion, Discovery, Execution, Exfiltration, Impact, InitialAccess,
  Pentest, Persistence, Policy, PrivilegeEscalation, Recon, Stealth, Trojan,
  UnauthorizedAccess. Note the docs spell "Cryptocurrency"/"Pentest" while finding types use
  `CryptoCurrency:`/`PenTest:` → matching must be case-insensitive.
  <https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-format.html>
- **GuardDuty → ASFF Types table** (authoritative tactic per finding type, e.g.
  `Recon:IAMUser/*` → `TTPs/Discovery/...`, `Stealth:IAMUser/CloudTrailLoggingDisabled` →
  `TTPs/Defense Evasion/...`). Category spelling is inconsistent ("Defense Evasion" vs
  "DefenseEvasion"), and some classifiers drop the threat purpose
  (`TTPs/Credential Access/IAMUser-AnomalousBehavior`). Includes
  `DefenseEvasion:IAMUser/BedrockLoggingDisabled`.
  <https://docs.aws.amazon.com/guardduty/latest/ug/securityhub-integration.html>
- **ASFF Types taxonomy**: `namespace/category/classifier`; TTPs categories align with ATT&CK
  tactics; Effects: Data Exposure, Data Exfiltration, Data Destruction, Denial of Service,
  Resource Consumption.
  <https://docs.aws.amazon.com/securityhub/latest/userguide/asff-required-attributes.html>
- **GuardDuty attack-sequence and custom-detection findings** carry MITRE tactics/techniques as
  signal indicators (`ATTACK_TACTIC`, `ATTACK_TECHNIQUE`); value format **unverified** →
  follow-up. <https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-summary.html>
- **MITRE CTID Mappings Explorer – AWS** (Apache-2.0):
  `mappings/aws/attack-16.1/aws-12.12.2024/enterprise/aws-12.12.2024_attack-16.1-enterprise.json`,
  497 mapping objects, ATT&CK 16.1, granularity = AWS service (`amazon_guardduty` 69 rows);
  finding types only in free-text comments; extraction is noisy and cites revoked T1562.*.
  Reference for curated rows, not vendored.
  <https://github.com/center-for-threat-informed-defense/mappings-explorer>
- **Threat Technique Catalog for AWS** (AWS CIRT, MIT-0, 82 entries incl. T1496.A007 "Bedrock
  LLM Abuse": `InvokeModel`, `InvokeModelWithResponseStream`, `Converse`, `ConverseStream`;
  `servicequotas:RequestServiceQuotaIncrease` → T1578.005). Prose only.
  <https://aws-samples.github.io/threat-technique-catalog-for-aws/Techniques/T1496.A007.html>
- **Stratus Red Team** (Datadog, Apache-2.0): `docs/index.yaml`, 46 AWS techniques with tactics
  only and occasional TTC IDs; includes `aws.impact.bedrock-invoke-model`.
  <https://raw.githubusercontent.com/DataDog/stratus-red-team/main/docs/index.yaml>
- **LLMjacking** (Sysdig): `InvokeModel` probe with an invalid parameter (expects
  `ValidationException`), `GetModelInvocationLoggingConfiguration`, then invocations.
  <https://www.sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack>.
  ATLAS 1.16.0: AML.T0040 "AI Model Inference API Access", AML.T0034 "Cost Harvesting" (a
  volume/impact technique — finding-level only, R8), AML.T0075 "Cloud Service Discovery".
- **Detection-rule repos** (reference only): SigmaHQ DRL 1.1 (attribution required in match
  output — not vendored); Elastic detection-rules ELv2; Splunk `security_content` Apache-2.0.

### Sample data

- **splunk/attack_data** (Apache-2.0) has AWS datasets incl. Bedrock log tampering; real lab
  captures → not committed.
- **flaws.cloud CloudTrail dataset**: 1,939,207 events, 2017-02-12 → 2020-10-07, ~240 MB tar of
  gzipped `{Records}` files; no licence stated → not committed; optional local scale test.
  <https://summitroute.com/blog/2020/10/09/public_dataset_of_cloudtrail_logs_from_flaws_cloud/>
- **Invictus IR** `invictus-ir/aws-dataset` returned 404.
- Conclusion: commit no third-party log data; generate the scenario in code.

### Storage

| Option | Pros | Cons |
|---|---|---|
| **SQLite (stdlib)** | zero dependency; file DB survives restarts and is shared by several stdio server processes (WAL + busy timeout); indexes on join keys; FTS5/JSON available; trivial temp-file isolation in tests | row store, slower than columnar on 10M+ rows |
| DuckDB | fast analytics, reads JSON/Parquet directly | new ~40 MB binary dependency; changes `uv.lock`, CI and npm launcher assumptions; single-writer file locks across processes |
| In-memory dicts | simplest | lost on restart, per-process copy, no "DB" |

Recommendation: SQLite, raw CloudTrail schema (not OCSF). OCSF import is a follow-up.

### Live fetch

Not in the MVP: needs AWS credentials in the MCP process, network at runtime, boto3, and
LookupEvents covers only 90 days of management events per region. Offline import covers every
real export (S3 trail files, `lookup-events`, `get-findings`, EventBridge archives). Separate plan.

## Decisions (builder's calls)

- **D1 Package.** `src/mitre_mcp_server/cloudtrail/` (`store.py`, `parsers.py`, `mapping.py`,
  `correlate.py`, `sample.py`, `tools.py`, `data/attack_mappings.json`).
- **D2 No `server` import inside the package** (double-module problem under `python -m`).
- **D3 Registration.** server.py top: `from mitre_mcp_server.cloudtrail import tools as
  cloud_tools`; after the last `@mcp.tool()` (before `main()`):
  `cloud_tools.register(mcp, sys.modules[__name__])`. `register` stores `srv` in a module global
  and applies `mcp.tool()` to the module-level async functions. ATT&CK is reached only through
  `srv.get_attack_data`, and STIX fields only through `srv._field` (works for STIX objects and
  plain dicts, which `test_cov_shapes.py` injects).
- **D4 Paths.** Module globals read from env at import, resolved like `LAYER_DIR`
  (`.expanduser().resolve()`): `DB_PATH` = `MITRE_MCP_CLOUDTRAIL_DB` (default
  `~/.mitre-mcp-server/cloudtrail/cloudtrail.db`); `IMPORT_DIR` =
  `MITRE_MCP_CLOUDTRAIL_IMPORT_DIR` (default `~/.mitre-mcp-server/cloudtrail/imports`, created
  0700 on first use). DB dir created 0700, DB file pre-created 0600 with
  `os.open(..., O_CREAT|O_EXCL, 0o600)` before `sqlite3.connect`; test asserts DB, -wal, -shm are
  0600. DB path is operator-only (env), never a tool argument.
- **D5 Import path safety** (R9). `load_cloud_logs(path=...)`:
  1. reject a path containing `\x00` with a failure response (not an exception);
  2. resolve relative to `IMPORT_DIR` (absolute must be inside it) with
     `Path.resolve(strict=True)` + `is_relative_to(IMPORT_DIR)`;
  3. directories: `os.walk(top, followlinks=False)`; count files as they are seen and stop at
     10,000 with a failure response (no full listing first); skip hidden entries and the store's
     own files (`DB_PATH`, `-wal`, `-shm`) if they sit under `IMPORT_DIR`;
  4. each file: `fd = os.open(p, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)`, `os.fstat(fd)` must be
     `S_ISREG` and its `(st_dev, st_ino)` must equal those of the `lstat` taken during the walk
     (defeats symlink swaps and FIFOs); read via `os.fdopen(fd, "rb")`.
  Error messages name the relative path and a reason, never file content. Inline `content` is the
  alternative for clients that cannot place files: ≤ 5 MB measured as
  `len(content.encode("utf-8"))`.
- **D6 Limits** (constants in `parsers.py`): ≤ 10,000 files per call; compressed file ≤ 100 MB;
  one gzip layer only (a decompressed payload that again starts with `1f 8b` is rejected);
  decompressed ≤ 256 MB per file via chunked read with a running cap; ≤ 1 GB decompressed and
  ≤ 2,000,000 records per call. `json.loads` errors, `RecursionError` and `MemoryError` become a
  per-file rejection reason. Recommended per-call size (README): ≤ ~200 MB compressed, because MCP
  clients typically time out tool calls after ~60 s (**unverified** client default; documented as
  guidance); responses include `duration_ms`.
- **D7 Connections** (R4). `store.connect()` is a `contextlib.contextmanager`: open,
  `PRAGMA journal_mode=WAL`, `busy_timeout=5000`, `foreign_keys=ON`, schema check (D8), yield;
  `commit()` on success, `rollback()` on exception, `conn.close()` in `finally`. One connection
  per tool call; test asserts the connection is closed after the block (a further `execute`
  raises `sqlite3.ProgrammingError`). No module-level connection.
- **D8 Schema version** in `meta(schema_version=1)`; mismatch → tool failure response telling the
  operator to delete or move the DB. No migrations in MVP.
- **D9 Raw CloudTrail schema + normalised columns**; raw record kept as compact JSON.
- **D10 Dedupe** (R10, R11). Events: `UNIQUE(dataset, event_id)`, `INSERT OR IGNORE`. Findings:
  key `(dataset, finding_key)` where `finding_key` is the GuardDuty finding ARN when known (native
  `arn`, or ASFF `Id` of a GuardDuty product), else ASFF `Id`. Upsert: scalar columns from the
  copy with the newer `updated_at`; `in_guardduty` / `in_securityhub` (int 0/1) OR-ed;
  `raw_guardduty` and `raw_asff` stored separately (each replaced only by a newer copy of the same
  kind); `finding_entities` is the **union** over both copies (dedupe on `(kind, value)`).
- **D11 Mapping at query time** from the static file, not stored per event. Store-only tools do
  not read ATT&CK data (`fault_na`); IDs in the file are current (validated by a data test).
- **D12 Mapping file curated by hand (JSON)**, each row with `sources` (keys into a `sources`
  table with URL + licence), a `confidence`, and `source_id` where the source cited a revoked ID.
  No third-party text copied; attribution in README Credits.
- **D13 Rule matching** (R12). Event rules: `(event_source, event_names[], when?)`, `when`
  limited to `success` (bool) and `error_code` (exact); all matching rules apply (union; a
  technique matched by several rules keeps its highest confidence). Finding rules: exact
  `finding_type` → longest `finding_type_prefix` → threat-purpose tactic fallback. Finding-type,
  prefix and threat-purpose comparisons are **case-insensitive** (`PenTest:`, `CryptoCurrency:`).
  ASFF: `TTPs/<category>` and `Effects/<category>` → tactics by normalised name (lowercase, no
  spaces). GuardDuty-in-ASFF classifiers are converted back to native types
  (`Stealth:IAMUser-CloudTrailLoggingDisabled` → `Stealth:IAMUser/CloudTrailLoggingDisabled`;
  a classifier without `:` takes the purpose from the category) and flagged
  `finding_type_derived`.
- **D14 Tactic fallback** (R7). `DefenseEvasion`, `Stealth` and ASFF `defenseevasion` map to the
  list `["TA0112", "TA0005"]` with note "ATT&CK v20 split of Defense Evasion into Defense
  Impairment and Stealth". All fallback values are lists. A data test reads both tactic names
  from the bundle ("Defense Impairment", "Stealth").
- **D15 Correlation score** (R6, C1; owner: adopt) — transparent, additive over *entity
  signals* (Technical Details). `key_class`: access key IDs starting `AKIA` → `long_term` (IAM
  user key, stable credential); `ASIA` or any other prefix → `temporary` (STS session, shorter-lived,
  shared role sessions). Key points: `access_key_long_term` 50, `access_key_temporary` 40; they
  are **not** time-decayed. `score = min(100, key_points + round(other_points × time_factor))`.
  An event qualifies iff `score ≥ min_score` (default 50) **and** (`key_class == long_term` or
  distinct entity signals ≥ 2). Principal signals are suppressed whenever either key class
  matched. So a long-term-key match is returned anywhere in the window on its own; a
  temporary-key match needs a second signal (IP, API, resource). Each returned event exposes
  `key_class` (or null) and `reasons`.
- **D16 Time window and candidates** (R5). Window `[first_seen − before, last_seen + after]`,
  defaults 60/60 minutes, each ≤ 1,440. Total span capped at 7 days anchored at `last_seen + after`
  (start moved forward) → `window_clamped: true`. Candidate SQL = window AND (account matches when
  known) AND `(access_key_id IN (...) OR principal_arn IN (...) OR session_issuer_arn IN (...) OR
  principal_id IN (...) OR user_name IN (...) OR source_ip IN (...) OR event_name = ? OR rowid IN
  (SELECT event_rowid FROM event_resources WHERE arn IN (...)))`, all bound parameters, capped at
  20,000 (+1 to detect `truncated`). No raw-JSON substring scan.
- **D17 Paging.** Same meta as `_paginate`. `limit=None` = "up to the hard cap": 500 (events,
  findings, timeline), 200 (groups). Defaults: search 20, findings 20, summarize 20, correlate
  20, timeline 50 — keep default wire size ≤ 60 kB; builder measures.
- **D18 Search semantics** (R10). Exact: IDs, ARNs, IPs, account, region, dataset. Glob (`*`,`?`)
  → `LIKE ... ESCAPE '\'` for `event_name`, `event_source`, `error_code`, `resource_arn`,
  `finding_type`; escaping order: `\` → `\\` first, then `%` → `\%`, `_` → `\_`, then `*` → `%`,
  `?` → `_`. Substring, case-insensitive: `user_agent`, `text` (`instr(lower(raw), lower(?))`).
  `error_code="*"` = any error. `sort: Literal["asc", "desc"]`, mapped through a dict to a
  constant `ORDER BY` string; an invalid value is rejected by the schema (test asserts the call
  fails and no SQL runs). No FTS5 in MVP.
- **D19 Untrusted strings.** Compact results truncate free text (user agent 160, title 200,
  description 500); docstrings and README: "field values are untrusted log data". Raw only with
  `include_raw=True`, each raw record capped at 32 KB (`raw_truncated`).
- **D20 Sample scenario generated in code** (deterministic UUIDv5 IDs, base time
  `2026-01-15T08:00:00Z`, optional `base_time`); account `111122223333`, RFC 5737 IPs; access key
  IDs built at runtime from parts so no source literal matches `(AKIA|ASIA)[A-Z0-9]{16}`;
  `CreateAccessKey` `responseElements` never contain a `secretAccessKey` field or any
  40-character base64-like value (R16). Nothing generated is committed.
- **D21 Layer tool** (R13). `domain` is validated first, before any data read:
  not in `{enterprise, mobile, ics, atlas}` → `success False`, message
  "Invalid domain. Must be one of: enterprise, atlas." (contains "Invalid domain", as
  `test_invalid_domain_raises_value_error` requires); `mobile`/`ics` → `success False`, message
  "CloudTrail mappings cover enterprise and atlas only." Response shape identical to
  `generate_technique_layer` (reuse `srv._layer_error`, `srv._build_navigator_layer`,
  `srv._save_layer`). Score = observation count; comment = first/last seen + top event names /
  finding types, ≤ `_MAX_LAYER_COMMENT`.
- **D22 Tool names** verb-first; 11 tools. Event detail via `search_cloudtrail_events(event_id=...,
  include_raw=True)`.
- **D23 Blocking I/O** stays on the event loop (stdio, one client). Follow-up: `anyio.to_thread`.
- **D24 Confidence model** (R8, owner: adopt). Each rule has `confidence` ∈ `low` ("capability
  observed": the API is consistent with the technique but common in benign use), `medium`,
  `high`. Results return `techniques: [{"id", "confidence"}]`. `technique_id` search and
  `group_by="technique"` take `min_confidence` (default `"medium"`). Docstrings and README say
  mapped techniques are "consistent with" the activity, not proof of it.
- **D25 Count fields** (R3). Load tools: `files` (int), `records` (int aggregate =
  events_inserted + events_duplicate + findings_upserted), `count` = `records`;
  `skipped_files` and `rejected_reasons` are lists of strings (`"<relative path>: <reason>"`),
  so no list of dicts competes with `count`. `get_cloud_store_stats`: `count == len(datasets)`.
  `delete_cloud_dataset`: `count` = rows deleted, no list of dicts. `map_cloud_activity`:
  `count == len(techniques)`.
- **D26 No stdout.** Nothing in the package prints to stdout (stdio transport); diagnostics go to
  stderr only, and only in `main()`-level code (none planned). A test runs an import with
  `capsys` and asserts empty stdout.
- **D27 Session-DB isolation rule** (R14). The session store (datasets `sample-llmjacking`,
  `smoke-scratch`, `smoke-sample`, `smoke-import`) is read-only for tests except the smoke cells:
  `delete_cloud_dataset` only ever targets `smoke-scratch`; the two load cells write only
  `smoke-sample` / `smoke-import`. Every other test that loads or deletes uses the function
  fixture `cloud_db` (fresh temp store). Documented in TESTING.md.

## Development Approach

- Testing approach: **Regular** (code, then tests in the same task), under the project gate:
  `.venv/bin/python -m pytest -q --cov --cov-report=term-missing` at 100 % line + branch,
  `.venv/bin/ruff check src tests` clean, no `noqa`, no new `# pragma: no cover`.
- Every task leaves the suite green and is shippable. Never `uv run` / `uv sync` in the sandbox.
- Each new tool gets its `ARGS` entry and the README/package.json/server.json count update in the
  task that adds it. Tests never hard-code tool counts; they assert `len(tools) == len(ARGS)`.
- Line numbers are pre-change; re-grep before editing.

## Testing Strategy

- **Markers.** Sample, parsers, store, scoring, path safety: `unit`. Mapping validation,
  `map_cloud_activity`, timeline, layer: `data` (default).
- **Isolation.** Session-scoped autouse fixture `cloud_store_session` in `tests/conftest.py`:
  `pytest.MonkeyPatch` sets `store.DB_PATH` / `store.IMPORT_DIR` to a `tmp_path_factory` dir,
  writes the sample files into `IMPORT_DIR/sample/`, loads the sample into `sample-llmjacking`
  and `smoke-scratch`. Function fixture `cloud_db` gives a fresh store. Rule D27.
- **Smoke / variants / faults / shapes.**
  - ARGS per tool (table below).
  - `tests/test_cov_variants.py`: helper `_item_id(x)` = first present of `stix_id`,
    `event_id`, `finding_id`, `id`, `value`, used in the two paging tests.
  - `tests/test_cov_faults.py`: allowed `fault_na` set += the 8 store-only tools, reason "reads
    only the cloud store and the static mapping file".
  - `tests/test_cov_shapes.py`: `run()` gets `if domain: require_domain(domain)`.
    `map_cloud_activity`, `build_incident_timeline` and `generate_incident_layer` read ATT&CK
    only via `get_object_by_attack_id` (techniques), `get_objects_by_type("x-mitre-tactic")` and
    `get_objects_by_type("x-mitre-matrix")` (both `_MitreData` overrides) and read fields only via
    `srv._field`; matrix/tactic order comes from `_field(matrix, "tactic_refs")`, never
    `get_tactics_by_matrix` / `get_matrices`. An empty tactic catalogue for a domain whose tactics
    are needed is a **data failure**: `success False`, `count 0`, every item list empty, message
    names the domain. Each tool is classified **by measurement** into
    `UNAFFECTED_BY_FAILING_QUERIES` / `UNAFFECTED_BY_EMPTY_RESULTS` (or neither) with the
    reason written next to the set; expected: all three unaffected by failing queries;
    `map_cloud_activity` and `build_incident_timeline` affected by empty results (they need
    tactics); `generate_incident_layer` emits no tactics (layer spec) and may be unaffected —
    decided by the measurement, not assumed.
- **Protocol.** `_env` adds both env vars under the temp root; one stdio test:
  `load_sample_cloud_dataset` → `search_cloudtrail_events`.
- **Invariants** (`tests/test_cloud_invariants.py`): summarize group counts sum to the search
  `total` for the same filters; every correlated event appears in the timeline of that finding;
  layer `technique_ids` == timeline technique IDs of that domain.
- **Security tests**: D5 (null byte, `../`, absolute outside, symlink out, FIFO, symlink swap via
  inode mismatch, hidden file, DB files skipped, file cap during walk), D6 (oversize, double gzip,
  bomb, deep nesting → RecursionError), SQL injection strings and `%`/`_`/`\` literal, invalid
  `sort`, file modes, no stdout.
- **Secrets** (R16): a unit test scans `sample.py`, `tests/`, `attack_mappings.json` and the
  generated sample output for `(AKIA|ASIA)[A-Z0-9]{16}` literals in source files and for
  `secretAccessKey` / 40-char base64 values in generated records.
- **Real-data rule**: call every new tool on the sample before claiming done; optional external
  dataset in Task 12.

## Progress Tracking

- Mark `[x]` when done; a task is done only when its last item ("run tests") passes.
- Deviations: a line under the task prefixed `➕` (added) or `⚠️` (changed/blocked) with reason;
  update Decisions if a decision changes.
- Record measured numbers in Task 13 and Task 14.

## Solution Overview

```
files / pasted JSON ──► parsers.py (safe open, detect format, normalise, case-insensitive keys)
                              │ normalised events / findings
built-in scenario ──► sample.py ──► store.py (SQLite: events, event_resources, findings,
                                     finding_entities, ingests, meta)
                                         │ parameterised SQL (filters, paging, group-by)
mapping.py (attack_mappings.json) ◄── correlate.py (window, SQL candidates, score, timeline)
          └────────────► tools.py (11 MCP tools) ──► srv.get_attack_data / _field /
                                                      _build_navigator_layer / _save_layer / _layer_error
```

## Technical Details

### DB schema (`store.py`, schema_version 1)

```sql
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE ingests (
  ingest_id INTEGER PRIMARY KEY, dataset TEXT NOT NULL, label TEXT NOT NULL,  -- relative path, "content", or "sample:<scenario>"
  started_at TEXT NOT NULL, duration_ms INTEGER, events_inserted INTEGER, events_duplicate INTEGER,
  findings_upserted INTEGER, rejected INTEGER);
CREATE TABLE events (
  rowid INTEGER PRIMARY KEY, dataset TEXT NOT NULL, event_id TEXT NOT NULL,
  event_time TEXT NOT NULL, event_epoch INTEGER NOT NULL,
  event_source TEXT NOT NULL, event_name TEXT NOT NULL, aws_region TEXT,
  source_ip TEXT, source_ip_is_ip INTEGER NOT NULL,
  user_agent TEXT, error_code TEXT, error_message TEXT,
  success INTEGER NOT NULL,            -- 0 if errorCode or responseElements.ConsoleLogin == "Failure"
  read_only INTEGER, event_type TEXT, event_category TEXT, recipient_account_id TEXT,
  user_type TEXT, principal_id TEXT, principal_arn TEXT, user_account_id TEXT,
  access_key_id TEXT, user_name TEXT, session_issuer_arn TEXT, invoked_by TEXT,
  mfa_authenticated INTEGER, raw TEXT NOT NULL, ingest_id INTEGER REFERENCES ingests,
  UNIQUE (dataset, event_id));
CREATE INDEX ix_events_time ON events(dataset, event_epoch);
CREATE INDEX ix_events_name ON events(event_name, event_epoch);
CREATE INDEX ix_events_key ON events(access_key_id);
CREATE INDEX ix_events_principal ON events(principal_arn);
CREATE INDEX ix_events_issuer ON events(session_issuer_arn);
CREATE INDEX ix_events_pid ON events(principal_id);
CREATE INDEX ix_events_user ON events(user_name);
CREATE INDEX ix_events_ip ON events(source_ip);
CREATE INDEX ix_events_source ON events(event_source);
CREATE TABLE event_resources (event_rowid INTEGER NOT NULL REFERENCES events ON DELETE CASCADE,
  arn TEXT NOT NULL, type TEXT, account_id TEXT);
CREATE INDEX ix_res_arn ON event_resources(arn);
CREATE TABLE findings (
  rowid INTEGER PRIMARY KEY, dataset TEXT NOT NULL, finding_key TEXT NOT NULL,
  finding_id TEXT NOT NULL,
  in_guardduty INTEGER NOT NULL DEFAULT 0, in_securityhub INTEGER NOT NULL DEFAULT 0,
  product TEXT, finding_type TEXT, finding_type_derived INTEGER NOT NULL DEFAULT 0,
  asff_types TEXT, title TEXT, description TEXT, severity REAL, severity_label TEXT,
  first_seen TEXT, first_epoch INTEGER, last_seen TEXT, last_epoch INTEGER,
  created_at TEXT, updated_at TEXT, account_id TEXT, region TEXT,
  api_name TEXT, service_name TEXT, raw_guardduty TEXT, raw_asff TEXT,
  ingest_id INTEGER REFERENCES ingests,
  UNIQUE (dataset, finding_key),
  CHECK (raw_guardduty IS NOT NULL OR raw_asff IS NOT NULL));
CREATE TABLE finding_entities (finding_rowid INTEGER NOT NULL REFERENCES findings ON DELETE CASCADE,
  kind TEXT NOT NULL,                  -- access_key | principal_id | principal_arn | user_name | ip | resource
  value TEXT NOT NULL, UNIQUE (finding_rowid, kind, value));
CREATE INDEX ix_fent ON finding_entities(kind, value);
```

Severity: GuardDuty `severity` × 10 → normalised; label Low < 4, Medium < 7, High < 9, Critical
≥ 9. ASFF: `Severity.Normalized` / `Severity.Label`. Times: ISO-8601 (`Z`, offsets, fractions)
or numeric epoch seconds; stored UTC.

### Input formats (`parsers.py`, auto-detected by content; gzip by magic bytes `1f 8b`)

| Shape | Detected by | Produces |
|---|---|---|
| CloudTrail S3 log file `{"Records": [...]}` | `Records` list of records with `eventVersion` | events |
| CloudTrail digest file | `digestStartTime` / `logFiles` | skipped, "digest file" |
| `aws cloudtrail lookup-events` `{"Events": [{"CloudTrailEvent": "<json>"}]}` | `Events[].CloudTrailEvent` | events |
| JSON lines / list of CloudTrail records | `eventVersion` + `eventTime` + `eventName` | events |
| GuardDuty `get-findings` `{"Findings": [...]}` (PascalCase) or API list (camelCase) | `type` + `service` (any case), no `SchemaVersion`+`ProductArn` | findings |
| EventBridge `{"detail-type": "GuardDuty Finding", "detail": {...}}` | `detail-type` | findings |
| ASFF `{"Findings": [...]}` (`get-findings`, `BatchImportFindings` body) or list | `SchemaVersion` + `ProductArn` | findings |

Not supported in MVP (follow-ups): CloudTrail Insights records (`eventType` `AwsCloudTrailInsight`,
rejected with reason "insights record"), Security Hub EventBridge envelope (unverified shape),
OCSF. Rejected records are counted with up to 5 reason strings (field names only).

### Tools (all `async`, return dicts with `success` and `message`)

```python
async def get_cloud_store_stats() -> Dict[str, Any]
    # {success, db_path, schema_version, count (== len(datasets)), datasets: [{dataset, events,
    #  findings, first_event_time, last_event_time, findings_guardduty, findings_securityhub}], message}

async def load_cloud_logs(path: Optional[str] = None, content: Optional[str] = None,
                          dataset: str = "default") -> Dict[str, Any]
    # exactly one of path/content. {success, dataset, files (int), records (int), count (== records),
    #  events_inserted, events_duplicate, findings_upserted, rejected,
    #  rejected_reasons: [str], skipped_files: ["<rel path>: <reason>"], time_range: {first, last},
    #  duration_ms, message}

async def load_sample_cloud_dataset(scenario: str = "llmjacking",
                                    dataset: str = "sample-llmjacking",
                                    base_time: Optional[str] = None) -> Dict[str, Any]
    # same response as load_cloud_logs (files = 0); idempotent

async def delete_cloud_dataset(dataset: str, confirm: bool = False) -> Dict[str, Any]
    # confirm False → success False "set confirm=true". {success, dataset, count (rows deleted),
    #  events_deleted, findings_deleted, message}

async def search_cloudtrail_events(
    start_time: Optional[str] = None, end_time: Optional[str] = None,
    event_name: Optional[str] = None, event_source: Optional[str] = None,
    principal_arn: Optional[str] = None, user_name: Optional[str] = None,
    access_key_id: Optional[str] = None, source_ip: Optional[str] = None,
    account_id: Optional[str] = None, region: Optional[str] = None,
    error_code: Optional[str] = None, resource_arn: Optional[str] = None,
    user_agent: Optional[str] = None, success: Optional[bool] = None,
    read_only: Optional[bool] = None, technique_id: Optional[str] = None,
    min_confidence: Literal["low", "medium", "high"] = "medium",
    text: Optional[str] = None, event_id: Optional[str] = None,
    dataset: Optional[str] = None, include_raw: bool = False,
    sort: Literal["asc", "desc"] = "asc", limit: Optional[int] = 20, offset: int = 0)
    # principal_arn matches principal_arn OR session_issuer_arn; account_id matches
    # user_account_id OR recipient_account_id; technique_id expands via the reverse index to
    # (event_source, event_name, when) predicates of rules with confidence ≥ min_confidence.
    # {success, filters, count, total, returned, offset, limit, has_more,
    #  events: [{event_id, event_time, event_source, event_name, aws_region, source_ip,
    #   user_type, principal_arn, user_name, access_key_id, account_id, error_code, success,
    #   read_only, user_agent, resources: [arn ≤ 5], techniques: [{id, confidence}],
    #   raw?, raw_truncated?}], message}

async def summarize_cloudtrail_events(group_by: str = "event_name", <search filters minus
                                      include_raw/sort/event_id>, limit: Optional[int] = 20,
                                      offset: int = 0)
    # group_by whitelist {event_name, event_source, principal_arn, user_name, access_key_id,
    #  source_ip, aws_region, account_id, error_code, user_agent, technique}; technique groups
    #  honour min_confidence. {success, group_by, count, total, ..., groups: [{value, count,
    #  first_seen, last_seen}], message}; count desc, value asc.

async def search_security_findings(
    source: Optional[Literal["guardduty", "securityhub"]] = None,
    finding_type: Optional[str] = None, severity_min: Optional[float] = None,
    start_time: Optional[str] = None, end_time: Optional[str] = None,
    access_key_id: Optional[str] = None, principal: Optional[str] = None,
    source_ip: Optional[str] = None, resource: Optional[str] = None,
    dataset: Optional[str] = None, limit: Optional[int] = 20, offset: int = 0)
    # {success, count, total, ..., findings: [{finding_id, finding_type, in_guardduty,
    #  in_securityhub, title, severity, severity_label, first_seen, last_seen, account_id, region,
    #  entities, techniques: [{id, confidence}], tactics: [TA ids]}], message}

async def map_cloud_activity(event_name: Optional[str] = None,
                             event_source: Optional[str] = None,
                             finding_type: Optional[str] = None,
                             error_code: Optional[str] = None,
                             success: Optional[bool] = None) -> Dict[str, Any]
    # names/tactics via srv.get_attack_data(domain); data failure → success False.
    # {success, count (== len(techniques)), techniques: [{technique_id, name, domain,
    #  tactics: [{id, name}], confidence, sources: [{key, url, license}], source_id?}],
    #  tactics_only: [{id, name}], message}

async def correlate_finding(finding_id: str, dataset: Optional[str] = None,
                            before_minutes: int = 60, after_minutes: int = 60,
                            min_score: int = 50, limit: Optional[int] = 20,
                            offset: int = 0) -> Dict[str, Any]
    # {success, finding: {...compact}, window: {start, end}, window_clamped, candidates,
    #  truncated, count, total, ..., events: [{...compact event, score, key_class, reasons: [...]}],
    #  message}

async def build_incident_timeline(finding_ids: Optional[List[str]] = None,
                                  access_key_id: Optional[str] = None,
                                  principal_arn: Optional[str] = None,
                                  source_ip: Optional[str] = None,
                                  start_time: Optional[str] = None,
                                  end_time: Optional[str] = None,
                                  dataset: Optional[str] = None, min_score: int = 50,
                                  min_confidence: Literal["low", "medium", "high"] = "medium",
                                  limit: Optional[int] = 50, offset: int = 0)
    # ≥ 1 scope argument; ≤ 50 finding_ids. {success, scope, count, total, ...,
    #  entries: [{id, kind, time, summary, techniques: [{technique_id, name, domain, confidence}],
    #  score?, finding_refs}], summary: {first_seen, last_seen, events, findings, principals,
    #  access_key_ids, source_ips, techniques_by_tactic: [{domain, tactic_id, tactic,
    #  techniques: [{technique_id, name, count, first_seen}]}]}, truncated, message}

async def generate_incident_layer(<timeline scope args>, domain: str = "enterprise",
                                  name: str = "Observed cloud techniques",
                                  save_to_file: bool = False) -> Dict[str, Any]
    # response keys identical to generate_technique_layer; D21 messages.
```

### ARGS entries (tests/tool_args.py)

| Tool | args | flags |
|---|---|---|
| get_cloud_store_stats | `a()` | `fault_na` |
| load_cloud_logs | `a(path="sample", dataset="smoke-import")` | `fault_na` |
| load_sample_cloud_dataset | `a(dataset="smoke-sample")` | `fault_na` |
| delete_cloud_dataset | `a(dataset="smoke-scratch", confirm=True)` | `fault_na` |
| search_cloudtrail_events | `a(dataset="sample-llmjacking", access_key_id=<attacker key>)` | `neg=True`, `fault_na` |
| summarize_cloudtrail_events | `a(dataset="sample-llmjacking", group_by="event_name")` | `fault_na` |
| search_security_findings | `a(dataset="sample-llmjacking")` | `fault_na` |
| correlate_finding | `a(dataset="sample-llmjacking", finding_id=<CloudTrailLoggingDisabled id>)` | `neg=True`, `fault_na` |
| map_cloud_activity | `a(event_source="cloudtrail.amazonaws.com", event_name="StopLogging")` | `neg=True` |
| build_incident_timeline | `a(dataset="sample-llmjacking", access_key_id=<attacker key>)` | `neg=True` |
| generate_incident_layer | `a(dataset="sample-llmjacking", access_key_id=<attacker key>)` | `neg=True`, `expect_failure={"mobile": "enterprise and atlas", "ics": "enterprise and atlas"}`, `bogus_response` |

Sample constants are exported by `sample.py`.

### Mapping data format and provenance (`cloudtrail/data/attack_mappings.json`)

```json
{
  "schema_version": 1,
  "attack_version": "20.0",
  "atlas_version": "1.16.0",
  "sources": {
    "aws-guardduty-docs": {"url": "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-format.html", "license": "facts from AWS documentation"},
    "aws-securityhub-gd-types": {"url": "https://docs.aws.amazon.com/guardduty/latest/ug/securityhub-integration.html", "license": "facts from AWS documentation"},
    "ctid-aws": {"url": "https://github.com/center-for-threat-informed-defense/mappings-explorer", "license": "Apache-2.0", "attack_version": "16.1"},
    "aws-ttc": {"url": "https://aws-samples.github.io/threat-technique-catalog-for-aws/", "license": "MIT-0"},
    "stratus": {"url": "https://stratus-red-team.cloud/attack-techniques/AWS/", "license": "Apache-2.0"},
    "sysdig-llmjacking": {"url": "https://www.sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack", "license": "facts from public report"},
    "maintainer": {"url": null, "license": "project judgement (Apache-2.0)"}
  },
  "event_rules": [
    {"event_source": "cloudtrail.amazonaws.com",
     "event_names": ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"],
     "techniques": [{"id": "T1685.002", "domain": "enterprise", "source_id": "T1562.008"}],
     "confidence": "high", "sources": ["stratus", "aws-ttc"]}
  ],
  "finding_rules": [
    {"finding_type": "Stealth:IAMUser/CloudTrailLoggingDisabled",
     "techniques": [{"id": "T1685.002", "domain": "enterprise", "source_id": "T1562.008"}],
     "confidence": "high", "sources": ["ctid-aws"]},
    {"finding_type_prefix": "CryptoCurrency:", "techniques": [{"id": "T1496.001", "domain": "enterprise"}],
     "confidence": "medium", "sources": ["maintainer"]}
  ],
  "threat_purpose_tactics": {"InitialAccess": ["TA0001"], "Execution": ["TA0002"],
    "Persistence": ["TA0003"], "PrivilegeEscalation": ["TA0004"],
    "DefenseEvasion": ["TA0112", "TA0005"], "Stealth": ["TA0112", "TA0005"],
    "CredentialAccess": ["TA0006"], "Discovery": ["TA0007"], "Recon": ["TA0007"],
    "Exfiltration": ["TA0010"], "Backdoor": ["TA0011"], "Impact": ["TA0040"],
    "CryptoCurrency": ["TA0040"], "ResourceConsumption": ["TA0040"]},
  "asff_category_tactics": {"initialaccess": ["TA0001"], "execution": ["TA0002"],
    "persistence": ["TA0003"], "privilegeescalation": ["TA0004"],
    "defenseevasion": ["TA0112", "TA0005"], "credentialaccess": ["TA0006"],
    "discovery": ["TA0007"], "lateralmovement": ["TA0008"], "collection": ["TA0009"],
    "commandandcontrol": ["TA0011"], "dataexfiltration": ["TA0010"],
    "datadestruction": ["TA0040"], "denialofservice": ["TA0040"],
    "resourceconsumption": ["TA0040"]},
  "notes": {"defense_evasion": "ATT&CK v20 split of Defense Evasion into Defense Impairment (TA0112) and Stealth (TA0005)"}
}
```

Seed event rules (IDs active in ATT&CK v20.0 / ATLAS 1.16.0 on 2026-11-05, re-confirmed by the
reviewer; builder adds `sources` per row and may add rows only with a source):

| eventSource | eventNames (`when`) | techniques | confidence |
|---|---|---|---|
| signin | ConsoleLogin (success true) | T1078.004 | low |
| signin | ConsoleLogin (success false) | T1110 | low (single failure; volume analysis is a follow-up) |
| sts | GetCallerIdentity | T1087.004 | low |
| sts | GetFederationToken, GetSessionToken | T1078.004 | low |
| iam | ListUsers, ListRoles, ListAccessKeys, GetAccountAuthorizationDetails | T1087.004 | medium |
| iam | ListGroups, ListGroupsForUser, ListAttachedUserPolicies, ListAttachedRolePolicies | T1069.003 | medium |
| iam | GetAccountPasswordPolicy | T1201 | medium |
| iam | CreateUser | T1136.003 | medium |
| iam | CreateAccessKey, CreateLoginProfile, UpdateLoginProfile | T1098.001 | medium |
| iam | AttachUserPolicy, AttachRolePolicy, PutUserPolicy, PutRolePolicy, AddUserToGroup, UpdateAssumeRolePolicy, CreateRole | T1098.003 | medium |
| iam | DeactivateMFADevice, DeleteVirtualMFADevice | T1556.006 | medium |
| iam | CreateSAMLProvider, UpdateSAMLProvider | T1484.002 | medium |
| cloudtrail | StopLogging, DeleteTrail, UpdateTrail, PutEventSelectors | T1685.002 (source T1562.008) | high |
| ec2 | DeleteFlowLogs | T1685.002 | high |
| logs | DeleteLogGroup, DeleteLogStream | T1685.002 | medium |
| config | StopConfigurationRecorder, DeleteConfigurationRecorder, DeleteDeliveryChannel | T1685.002 | high |
| guardduty | DeleteDetector, UpdateDetector, DisassociateFromMasterAccount | T1685 | high |
| ec2 | AuthorizeSecurityGroupIngress | T1686.001 (source T1562.007) | low |
| ec2 | DescribeInstances, DescribeRegions, DescribeSnapshots, DescribeImages, DescribeVolumes, DescribeSecurityGroups | T1580 | low |
| ec2 | RunInstances | T1578.002 | low |
| ec2 | ModifyInstanceAttribute | T1578.005 | medium |
| ec2 | GetPasswordData | T1552 | medium |
| ec2 | ModifySnapshotAttribute, ModifyImageAttribute | T1537 | medium |
| rds | ModifyDBSnapshotAttribute | T1537 | medium |
| ec2-instance-connect | SendSSHPublicKey | T1021.008 | medium |
| ssm | SendCommand, StartSession | T1651 | medium |
| ssm | GetParameter, GetParameters | T1555.006 | low |
| secretsmanager | GetSecretValue, BatchGetSecretValue | T1555.006 | medium |
| s3 | ListBuckets | T1580 | low |
| s3 | ListObjects, ListObjectsV2 | T1619 | low |
| s3 | GetObject | T1530 | low |
| s3 | PutBucketPolicy, PutBucketAcl | T1537 | low |
| s3 | DeleteObject, DeleteObjects, DeleteBucket | T1485 | low |
| lambda | CreateFunction20150331, UpdateFunctionCode20150331v2, AddPermission20150331v2 | T1648 | low |
| organizations | LeaveOrganization | T1666 | high |
| servicequotas | RequestServiceQuotaIncrease | T1578.005 | low |
| bedrock | ListFoundationModels, GetFoundationModelAvailability, GetModelInvocationLoggingConfiguration | T1526 + AML.T0075 | medium |
| bedrock | InvokeModel, InvokeModelWithResponseStream, Converse, ConverseStream (success true) | T1496.004 + AML.T0040 | low |
| bedrock | InvokeModel (error_code ValidationException) | AML.T0040 | medium (Sysdig probe pattern) |
| bedrock | PutUseCaseForModelAccess, CreateFoundationModelAgreement | T1496.004 | low |
| bedrock | DeleteModelInvocationLoggingConfiguration, PutModelInvocationLoggingConfiguration | T1685.002 | high |
| bedrock | DeleteGuardrail | T1685 | low |
| sagemaker | CreatePresignedNotebookInstanceUrl | T1078.004 | low |
| sagemaker | CreateNotebookInstanceLifecycleConfig, UpdateNotebookInstance | T1648 | low |

Notes: T1496.004 lists platform `SaaS` only in ATT&CK v20 (Bedrock is AWS-managed AI, which ATT&CK
places under Cloud Service Hijacking; recorded as a `note` on the rows). AML.T0034 Cost
Harvesting is a volume/impact technique and appears only in finding rules (e.g. Bedrock
`Impact:IAMUser/AnomalousBehavior` in the sample), never per event. Lambda versioned event names
and the Bedrock `eventSource` must be checked against one AWS doc example per row; rows the builder
cannot confirm stay `low` with a `note`.

Seed finding rules: `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.*` → T1552.005 +
T1078.004 (high); `UnauthorizedAccess:IAMUser/MaliciousIPCaller*` → T1078.004 (medium);
`UnauthorizedAccess:IAMUser/TorIPCaller` → T1078.004 + T1090.003 (medium);
`UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` → T1078.004 (medium);
`Stealth:IAMUser/CloudTrailLoggingDisabled`, `Stealth:IAMUser/LoggingConfigurationModified`,
`DefenseEvasion:IAMUser/BedrockLoggingDisabled` → T1685.002 (high);
`Persistence:IAMUser/AnomalousBehavior` → T1098.001 + T1098.003 (medium);
`PrivilegeEscalation:IAMUser/AdministrativePermissions` → T1098.003 (high);
`Discovery:IAMUser/AnomalousBehavior`, `Recon:IAMUser/*` → T1580 + T1087.004 (medium);
`Exfiltration:S3/*` → T1530 (medium); `Impact:S3/AnomalousBehavior.Delete` → T1485 (medium);
`Impact:IAMUser/AnomalousBehavior` → T1496.004 + AML.T0034 (low; AML.T0034 only when the finding's
API is a Bedrock invocation — expressed as a separate rule with `api_service: bedrock`);
`Policy:IAMUser/RootCredentialUsage` → T1078.004 (medium); `PenTest:IAMUser/*` → T1078.004
(low); `CryptoCurrency:*` → T1496.001 (high); `ResourceConsumption:IAMUser/ComputeResources` →
T1578.002 + T1496.001 (medium).

Mapping tests (data): every technique ID exists and is active in its domain's bundle; every
`source_id` ≠ `id` is revoked with `revoked-by` → `id`; every row has a known `sources` key and a
valid `confidence`; no duplicate keys; every fallback tactic list resolves; the TA0112/TA0005
names are read from the bundle. Bump procedure (README): on an ATT&CK/ATLAS bump this test lists
rows to remap.

### Correlation algorithm and scoring (`correlate.py`)

1. Load the finding (GuardDuty id, finding ARN or ASFF Id); entities from `finding_entities`
   (union of both copies, D10) plus `api_name` / `service_name`.
2. Window (D16) incl. 7-day clamp; no times → `created_at ± window`.
3. Candidates: the D16 SQL (entity predicates, bound parameters), `LIMIT 20001`.
4. Entity signals and points (constants in `correlate.py`):

   | Signal (reason text) | Points | Condition |
   |---|---|---|
   | `access_key_long_term` | 50 (not decayed) | `access_key_id` equal and starts `AKIA` |
   | `access_key_temporary` | 40 (not decayed) | `access_key_id` equal, any other prefix (`ASIA`, unknown) |
   | `principal` | 25 | no key match; `principal_arn`/`session_issuer_arn` or full `principal_id` equal |
   | `principal_role` | 15 | no key match, no `principal`; role-ID prefix of `principal_id` (`AROA…:`) equal |
   | `user_name` | 10 | no key match, no principal signal; `user_name` equal |
   | `source_ip` | 20 | `source_ip` equal and `source_ip_is_ip` |
   | `api` | 20 | `event_name` == finding API and (`event_source` == service or service unknown) |
   | `resource` | 15 | an `event_resources.arn` equals a finding resource |

   `score = min(100, key_points + round(other_points × time_factor))`; `time_factor` = 1.0 inside
   `[first_seen, last_seen]`, decaying linearly to 0.5 at the window edge. Qualifies iff
   `score ≥ min_score` (default 50) and (`key_class == "long_term"` or distinct signals ≥ 2).
   Worked examples (inside the span unless stated):
   - AKIA key only, anywhere in the window (even at the edge) → 50, returned, reasons
     `[access_key_long_term]`;
   - ASIA key only → 40, hidden (fails both the score and the ≥ 2-signal rule);
   - ASIA + IP → 60, ASIA + API → 60, returned (at the window edge: 40 + 10 = 50, still returned);
   - benign event by the same role from the same NAT IP → 25 + 20 = 45, hidden;
   - StopLogging by the attacker AKIA key from the attacker IP → 50 + 20 + 20 = 90, top result;
   - AKIA + IP (≥ 70) ranks above AKIA only (50).
5. Sort by score desc, time asc; page.
6. Timeline: seed findings (given IDs, or findings whose entities match the scope filters in
   range) → union of their correlated events and events matching the scope filters → dedupe →
   sort by time → page; techniques per entry (≥ `min_confidence`); `techniques_by_tactic` in
   matrix order from `get_objects_by_type("x-mitre-tactic")` + the domain matrix; cap 5,000 events
   before paging (`truncated`).

## What Goes Where

| Path | Change |
|---|---|
| `src/mitre_mcp_server/cloudtrail/__init__.py` | new |
| `src/mitre_mcp_server/cloudtrail/sample.py` | new: scenario + writers per input shape |
| `src/mitre_mcp_server/cloudtrail/parsers.py` | new: safe open/read, detection, normalisation, time parsing |
| `src/mitre_mcp_server/cloudtrail/store.py` | new: paths, `connect()` context manager, schema, ingest/upsert, filter → SQL, paging, group-by, delete, stats, import walk |
| `src/mitre_mcp_server/cloudtrail/mapping.py` | new: load/validate JSON, lookups, reverse index, confidence |
| `src/mitre_mcp_server/cloudtrail/data/attack_mappings.json` | new |
| `src/mitre_mcp_server/cloudtrail/correlate.py` | new: window, candidates, scoring, timeline |
| `src/mitre_mcp_server/cloudtrail/tools.py` | new: `register(mcp, srv)` + 11 tools |
| `src/mitre_mcp_server/server.py` | top import + `register` call before `main()` |
| `tests/conftest.py` | `cloud_store_session`, `cloud_db` |
| `tests/tool_args.py` | 11 ARGS entries |
| `tests/test_cov_variants.py` | `_item_id()` in paging tests |
| `tests/test_cov_faults.py` | allowed `fault_na` set |
| `tests/test_cov_shapes.py` | `if domain:` guard; classify 3 tools |
| `tests/test_protocol.py` | env vars + one stdio test |
| `tests/test_cloud_*.py` | new suites (sample, parsers, store, tools, mapping, correlation, invariants) |
| `README.md` (lines 3, 15, 163 + new section), `package.json`, `server.json` | tool counts per task; docs in Task 14; `files` += `src/**/*.json` |
| `CHANGELOG.md` (`[Unreleased]`), `TESTING.md` | docs |

## Implementation Steps

### Task 1: Sample scenario generator

**Files:**
- Create: `src/mitre_mcp_server/cloudtrail/__init__.py`, `src/mitre_mcp_server/cloudtrail/sample.py`
- Create: `tests/test_cloud_sample.py`

- [ ] `build_scenario(name="llmjacking", base_time=None)` → `(cloudtrail_records, guardduty_findings, asff_findings)` per D20: benign baseline (console user with MFA from 198.51.100.10, CI role via AssumeRole with Describe*/List* noise from a shared NAT IP, two failed ConsoleLogin from 203.0.113.77); attacker key from 203.0.113.50: GetCallerIdentity → IAM/EC2/S3 discovery → Bedrock ListFoundationModels, GetModelInvocationLoggingConfiguration, InvokeModel ValidationException probe, PutUseCaseForModelAccess, ≥ 20 InvokeModel/Converse → DeleteModelInvocationLoggingConfiguration → CreateUser/CreateAccessKey/AttachUserPolicy(AdministratorAccess) → GetSecretValue → S3 GetObject → StopLogging; plus ≥ 2 calls by `ATTACKER_KEY` (an `AKIA…` long-term key) from a second RFC 5737 IP `192.0.2.66` inside the MaliciousIPCaller finding's window (not the finding's API); plus one call by the same attacker principal with an `ASIA…` session key from a third IP and one `ASIA…` call from the attacker IP. ≥ 150 events. Findings: GuardDuty `UnauthorizedAccess:IAMUser/MaliciousIPCaller`, `Discovery:IAMUser/AnomalousBehavior`, `DefenseEvasion:IAMUser/BedrockLoggingDisabled`, `Persistence:IAMUser/AnomalousBehavior`, `Stealth:IAMUser/CloudTrailLoggingDisabled`, `Impact:IAMUser/AnomalousBehavior` (Bedrock API); ASFF: the CloudTrailLoggingDisabled finding as Security Hub sees it (Id = GuardDuty ARN), a CSPM `CloudTrail.1`-style control finding on the trail ARN, one `Unusual Behaviors/User/...` finding. Export `ATTACKER_KEY`, `ATTACKER_IP`, `ATTACKER_IP_2`, `ATTACKER_SESSION_KEY`, `FINDING_IDS`.
- [ ] `write_files(dir)`: one file per supported shape (gz S3 file, lookup-events, JSONL, GuardDuty CLI PascalCase, EventBridge camelCase, ASFF get-findings, digest file).
- [ ] write tests: determinism; `base_time` shifts all times; schema completeness; secrets test (R16 scope: `sample.py`, `tests/`, `attack_mappings.json` once it exists — test skips that path until Task 7 creates it, then asserts) and generated `CreateAccessKey` responseElements have no `secretAccessKey`/40-char base64 value.
- [ ] run `trivy fs --skip-db-update --scanners secret --skip-dirs .venv --skip-dirs .ruff_cache .` on the working tree: no findings.
- [ ] run tests (`-m unit` and full gate) - must pass before next task

### Task 2: Parsers and safe file reading

**Files:**
- Create: `src/mitre_mcp_server/cloudtrail/parsers.py`
- Create: `tests/test_cloud_parsers.py`

- [ ] `open_regular_file(path, expected_stat)` (D5 step 4), `read_payload(fd_or_bytes)` (gzip magic, one layer, per-file and running caps D6), `iter_records(obj)` per the format table, Insights records rejected with reason.
- [ ] `normalise_event(rec)`, `normalise_finding(rec)` (case-insensitive key access; GuardDuty native + ASFF + ASFF-of-GuardDuty type derivation D13), `parse_time()`; rejection reasons as strings.
- [ ] write tests: every shape from `write_files` parses to the expected counts; PascalCase == camelCase normalisation; ASFF classifier derivation table (rows from the AWS GuardDuty→ASFF table incl. `TTPs/Credential Access/IAMUser-AnomalousBehavior` and `TTPs/DefenseEvasion/EC2:Unusual-DNS-Resolver` → tactic only); time formats; `AWS Internal/3` → `source_ip_is_ip` 0; ConsoleLogin Failure → success 0.
- [ ] write tests: malformed line rejected; oversize; double gzip; bomb over 256 MB cap (streamed synthetic); deeply nested JSON → RecursionError → rejection; FIFO and symlink refused by `open_regular_file`; inode mismatch refused.
- [ ] run tests - must pass before next task

### Task 3: SQLite store (no tools yet)

**Files:**
- Create: `src/mitre_mcp_server/cloudtrail/store.py`
- Create: `tests/test_cloud_store.py`

- [ ] `DB_PATH`, `IMPORT_DIR` (D4); `connect()` (D7, D8); schema; file modes.
- [ ] `ingest(conn, dataset, label, events, findings)` (D10: dedupe, upsert with `in_*` flags, `raw_guardduty`/`raw_asff`, entity union, `event_resources`), `stats()`, `delete_dataset()`, `walk_import(path)` (D5 steps 1-3, file cap during walk, skips hidden and DB/WAL/SHM files).
- [ ] write tests: schema once; version mismatch → error; connection closed after the block (`ProgrammingError` on reuse); rollback on exception; DB/-wal/-shm 0600, dirs 0700; re-import → duplicates; GuardDuty native + ASFF merge (flags both, both raws kept, entities = union, newer scalars win regardless of import order); delete cascade.
- [ ] write tests: path checks (null byte, `../x`, absolute outside, symlink out, hidden, DB files under IMPORT_DIR skipped, 10,001 files stops at the cap without listing all).
- [ ] run tests - must pass before next task

### Task 4: Tool wiring, load/stats/delete tools, harness integration (integration risk)

**Files:**
- Create: `src/mitre_mcp_server/cloudtrail/tools.py`, `tests/test_cloud_tools.py`
- Modify: `src/mitre_mcp_server/server.py`, `tests/conftest.py`, `tests/tool_args.py`, `tests/test_cov_faults.py`, `tests/test_cov_shapes.py`, `tests/test_protocol.py`, `README.md`, `package.json`, `server.json`

- [ ] `tools.py`: `register(mcp, srv)` (D2, D3); `get_cloud_store_stats`, `load_cloud_logs` (D5, D6, D25, `duration_ms`), `load_sample_cloud_dataset`, `delete_cloud_dataset`; server.py top import + `register` call.
- [ ] harness: `cloud_store_session` + `cloud_db` (D27); 4 ARGS entries; `fault_na` allowed set; `test_cov_shapes.run()` `if domain:` guard; protocol `_env` + stdio test (load sample → stats).
- [ ] tool counts 67 → 71 in README.md (3 places), `package.json`, `server.json`.
- [ ] write tests: load responses satisfy D25 (`files` int, `records` == `count`, lists are strings); content vs path exclusivity; `content` > 5 MB UTF-8 bytes refused (multi-byte characters counted as bytes); delete without `confirm` refused; no stdout during import (D26); in-process and stdio tool lists both equal `set(ARGS)` (proves D2/D3; no literal counts).
- [ ] run tests - must pass before next task

### Task 5: Event search and stack counting

**Files:**
- Modify: `src/mitre_mcp_server/cloudtrail/store.py`, `src/mitre_mcp_server/cloudtrail/tools.py`, `tests/tool_args.py`, `tests/test_cov_variants.py`, `README.md`, `package.json`, `server.json`
- Modify: `tests/test_cloud_store.py`, `tests/test_cloud_tools.py`

- [ ] `store.py`: filter builder (D18) from a whitelist; glob escaping order; time errors → failure response; paging (D17); `group_counts()` with column whitelist; compact projection + truncation (D19); raw cap 32 KB; `ORDER BY` from a constant dict.
- [ ] `tools.py`: `search_cloudtrail_events` (`technique_id`/`min_confidence` arrive in Task 7) and `summarize_cloudtrail_events` (`technique` group in Task 7); untrusted-data docstrings. ARGS; `_item_id()` in variants; counts 71 → 73.
- [ ] write tests: each filter alone and combined (expected counts derived from `build_scenario()`); `error_code="*"`; glob `Delete*`; literal `%`, `_`, `\` in values; injection strings return 0 rows and tables survive; `sort="sideways"` rejected by the schema; stable sort; `event_id` + `include_raw`; paging None/0/-1/beyond end; summarize ordering, invalid `group_by` failure.
- [ ] measure default wire size of both tools (≤ 60 kB; record in Task 13).
- [ ] run tests - must pass before next task

### Task 6: Findings search

**Files:**
- Modify: `src/mitre_mcp_server/cloudtrail/store.py`, `src/mitre_mcp_server/cloudtrail/tools.py`, `tests/tool_args.py`, `README.md`, `package.json`, `server.json`
- Modify: `tests/test_cloud_store.py`, `tests/test_cloud_tools.py`

- [ ] `store.py`: findings filters (source flags, type glob, severity, time overlap, entity filters via `finding_entities`), compact projection.
- [ ] `tools.py`: `search_security_findings` (techniques/tactics empty until Task 7). ARGS; counts 73 → 74.
- [ ] write tests: each filter; overlap at boundaries; merged finding listed once with both flags; `principal` matches ARN, ID and user name; entity filter finds a merged finding by an entity present only in the ASFF copy.
- [ ] run tests - must pass before next task

### Task 7: ATT&CK / ATLAS mapping

**Files:**
- Create: `src/mitre_mcp_server/cloudtrail/mapping.py`, `src/mitre_mcp_server/cloudtrail/data/attack_mappings.json`, `tests/test_cloud_mapping.py`
- Modify: `src/mitre_mcp_server/cloudtrail/tools.py`, `src/mitre_mcp_server/cloudtrail/store.py`, `tests/tool_args.py`, `tests/test_cov_shapes.py`, `package.json`, `server.json`, `README.md`

- [ ] `attack_mappings.json` per format and seed tables (confidence per row, D24), each row sourced; verify Bedrock/Lambda event names.
- [ ] `mapping.py`: `importlib.resources` load; structural validation (unknown keys, bad `when`/`confidence` → `ValueError`, tested with a temp file); case-insensitive finding matching (D13); event/finding/ASFF lookups returning `{id, confidence}`; reverse index honouring `min_confidence`.
- [ ] wire in: `techniques` in search and finding results, `technique_id` + `min_confidence`, `group_by="technique"`; tool `map_cloud_activity` (D3 access only; data failure → success False); ARGS; classify in `test_cov_shapes.py` by measurement; `package.json` `files` += `src/**/*.json`; counts 74 → 75.
- [ ] write tests (data): mapping validation rules; remaps T1562.008 → T1685.002 and T1562.007 → T1686.001 asserted from the raw bundle; TA0112/TA0005 names from the bundle; `map_cloud_activity` for StopLogging, ConsoleLogin success vs failure, InvokeModel success vs ValidationException, exact / prefix / tactic-only / unknown finding types; `pentest:iamuser/kalilinux` and `CRYPTOCURRENCY:EC2/BitcoinTool.B` match case-insensitively.
- [ ] write tests (unit): `technique_id` result == union of its predicates at that confidence; `min_confidence="low"` ⊇ default; `group_by="technique"` counts.
- [ ] run tests - must pass before next task

### Task 8: Finding ↔ event correlation

**Files:**
- Create: `src/mitre_mcp_server/cloudtrail/correlate.py`, `tests/test_cloud_correlation.py`
- Modify: `src/mitre_mcp_server/cloudtrail/tools.py`, `tests/tool_args.py`, `README.md`, `package.json`, `server.json`

- [ ] `correlate.py`: entities, window + 7-day clamp (`window_clamped`), candidate SQL with entity predicates (D16), scoring (D15 table, time factor, ≥ 2 signals, `min_score`), truncation.
- [ ] `tools.py`: `correlate_finding`; ARGS; counts 75 → 76.
- [ ] write tests (unit, synthetic rows): (a) AKIA-only at the window edge (time factor 0.5) is returned with score 50 and `reasons == ["access_key_long_term"]`, `key_class == "long_term"`; (b) ASIA-only is not returned for any `min_score` ≤ 40; (c) ASIA + IP and ASIA + API are returned; (d) an unknown key prefix behaves like ASIA (`key_class == "temporary"`); (e) benign same-role + same-NAT-IP event is below default; (f) principal signals suppressed for both key classes; (g) AKIA-only (50) ranks below AKIA + IP (≥ 70). Also: each other signal; `AWS Internal` never scores; account mismatch excluded; time factor at edges for non-key points; 7-day clamp; candidate cap → `truncated`; resource-only match via `event_resources`.
- [ ] write tests (sample): CloudTrailLoggingDisabled → top event StopLogging, reasons ⊇ {access_key_long_term, source_ip, api}, score 90; `correlate_finding(MaliciousIPCaller)` at default returns the `ATTACKER_IP_2` calls with `access_key_long_term` and without `source_ip` in reasons; the `ATTACKER_SESSION_KEY` (ASIA) events appear only when they share the finding's IP or API; BedrockLoggingDisabled → DeleteModelInvocationLoggingConfiguration; ASFF copy ID gives identical events; CSPM control finding returns nothing at default and its trail event at `min_score=10` only if it has ≥ 2 signals (else documented empty).
- [ ] run tests - must pass before next task

### Task 9: Incident timeline

**Files:**
- Modify: `src/mitre_mcp_server/cloudtrail/correlate.py`, `src/mitre_mcp_server/cloudtrail/tools.py`, `tests/tool_args.py`, `tests/test_cov_shapes.py`, `README.md`, `package.json`, `server.json`
- Modify: `tests/test_cloud_correlation.py`, `tests/test_cloud_tools.py`

- [ ] `correlate.py`: scope resolution, merge/dedupe/sort, summary, `techniques_by_tactic` in matrix order (via `get_objects_by_type("x-mitre-tactic")` and `srv._field`).
- [ ] `tools.py`: `build_incident_timeline`; ARGS; classify in `test_cov_shapes.py`; counts 76 → 77.
- [ ] write tests: attacker-key timeline in order discovery → Bedrock → persistence → log tampering; at default confidence `techniques_by_tactic` includes T1087.004, T1136.003, T1098.001, T1098.003, T1555.006, T1685.002, AML.T0075, AML.T0040 (medium probe) and, from findings, AML.T0034 only with `min_confidence="low"`; low rows (T1580, T1530, T1496.004) appear only with `min_confidence="low"`; benign user absent; no scope → failure; > 50 finding_ids → failure; paging.
- [ ] run tests - must pass before next task

### Task 10: Observed-technique Navigator layer

**Files:**
- Modify: `src/mitre_mcp_server/cloudtrail/tools.py`, `tests/tool_args.py`, `tests/test_cov_shapes.py`, `README.md`, `package.json`, `server.json`
- Modify: `tests/test_cloud_tools.py`

- [ ] `generate_incident_layer` (D21: domain checked before any data read; exact messages), timeline scope code, `srv._build_navigator_layer` / `_save_layer` / `_layer_error`; unknown/revoked → `unknown_ids`/`skipped`.
- [ ] ARGS (`expect_failure` mobile/ics, `bogus_response`); classify in `test_cov_shapes.py`; counts 77 → 78.
- [ ] write tests: bogus domain → "Invalid domain" with no data access (monkeypatched `get_attack_data` raising is never called); enterprise layer domain `enterprise-attack`, scores = counts, comments ≤ 2000, parents auto-added; atlas layer `atlas-atlas`, only `AML.*`; `save_to_file` inside monkeypatched `LAYER_DIR`; mobile failure message.
- [ ] run tests - must pass before next task

### Task 11: Invariants and security pass

**Files:**
- Create: `tests/test_cloud_invariants.py`
- Modify: `src/mitre_mcp_server/cloudtrail/*.py` only if a test finds a bug

- [ ] invariants from Testing Strategy.
- [ ] write tests: docstrings of tools returning log strings mention untrusted data and "consistent with"; the filter builder never places a filter value in the SQL text (assert on builder output for malicious values); no stdout across a full sample load + search.
- [ ] `grep -rn "pragma: no cover" src/` → only the server.py line; `grep -rn "noqa" src tests` → empty.
- [ ] run tests - must pass before next task

### Task 12: Optional scale check with an external dataset (no repo changes)

**Files:**
- none in the repo (scratch under `$TMPDIR`)

- [ ] if the sandbox allows network: download the flaws.cloud tar to `$TMPDIR/flaws/`, **extract the tar first** (the loader reads `.json.gz`, not tar), point `MITRE_MCP_CLOUDTRAIL_IMPORT_DIR` / `MITRE_MCP_CLOUDTRAIL_DB` at scratch dirs, import in batches (≤ ~200 MB compressed per call, D6); record files, events, rejected, `duration_ms`. If network is blocked: mark `⚠️ skipped (no network)` and continue.
- [ ] if imported: time 5 searches and one `summarize` on ≥ 1M events; a search > 2 s → add an index (new item with test) or record a follow-up.
- [ ] write tests: none (measurement only).
- [ ] run tests - must pass before next task

### Task 13: Verify acceptance criteria

**Files:**
- Modify: this plan (record numbers)

- [ ] SOC walk-through on the sample in-process and once over stdio: load sample → stats → search by key / IP / time range / `error_code=ValidationException` / `event_name=Delete*` / `technique_id=T1685.002` → summarize by `source_ip` → findings `severity_min=70` → correlate CloudTrailLoggingDisabled → timeline → enterprise + atlas layers (one saved). Record key numbers.
- [ ] full gate 100 % + ruff clean; `MITRE_MCP_DATA_DIR="$(mktemp -d)" .venv/bin/python -m pytest -q -m unit` passes. Record pass/xfail counts and runtime.
- [ ] default wire sizes of all 11 tools recorded, all ≤ 60 kB; README/package.json/server.json say 78; `test_readme_tool_counts_match_registry` passes.
- [ ] write tests: none new unless a criterion fails (then fix + regression test).
- [ ] run tests - must pass before next task

### Task 14: [Final] Update documentation

**Files:**
- Modify: `README.md`, `CHANGELOG.md`, `TESTING.md`, this plan

- [ ] README section "Cloud logs (CloudTrail, GuardDuty, Security Hub)": env vars, supported formats, AWS export commands (`aws cloudtrail lookup-events`, S3 trail sync, `aws guardduty get-findings`, `aws securityhub get-findings`), recommended per-call import size and client timeout note (D6), sample scenario, untrusted-data and "consistent with" wording, confidence levels, mapping provenance + bump procedure; Tools section lists the 11 tools; Credits: CTID (Apache-2.0), Stratus Red Team (Apache-2.0), AWS TTC (MIT-0), Sysdig report.
- [ ] CHANGELOG `[Unreleased]` → `### Added` (feature, 11 tool names, "no new dependencies").
- [ ] TESTING.md: env vars, new suites, session-DB isolation rule (D27), measured runtime from Task 13.
- [ ] write tests: none (docs); re-run `test_readme_tool_counts_match_registry` and the protocol tool-list test.
- [ ] run tests - must pass; commit; then `trivy fs --skip-db-update --scanners vuln,secret,misconfig --skip-dirs .venv --skip-dirs .ruff_cache .` and fix findings.

## Post-Completion

- Plan review cycle 2 before Task 1.
- Follow-ups (separate plans):
  1. Optional live fetch (`[aws]` extra, boto3, read-only role), opt-in.
  2. OCSF import (Security Lake Parquet; new Security Hub `GetFindingsV2`).
  3. Security Hub EventBridge envelope and CloudTrail Insights records.
  4. GuardDuty attack-sequence indicators once the value format is verified.
  5. Volume-based rules (failed-login bursts → T1110 high, invocation volume → AML.T0034).
  6. FTS5 for `text` if scans are slow.
  7. Off-loop imports (`anyio.to_thread`).
  8. More scenarios and mapping rows, each sourced.
  9. Retention / size quota for the store.

## Risks and open questions

- **Mapping quality**: curated judgement with sources and confidence levels, not an official table
  (none exists at event level); low-confidence rows are hidden by default (D24).
- **ATT&CK churn**: future bumps fail the mapping test until rows are remapped (intended).
- **Prompt injection via log content** (D5, D19): reduced, not removed.
- **Unverified**: Bedrock `eventSource` per API, Lambda versioned names, MCP client timeout
  defaults; checked in Task 7 / documented as guidance.
- Owner decisions: R6, R8, R11, R15 taken as given by the owner; none outstanding.

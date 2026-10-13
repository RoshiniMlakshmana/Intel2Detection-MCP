# Intel2Detection-MCP

**Turn cited threat research into detection rule drafts for analyst review.**

Intel2Detection-MCP collects threat intelligence, reads technical reports, extracts supported behaviors, and generates **Sigma, KQL and SPL drafts**. Use it through Claude's Model Context Protocol (MCP), the Python CLI, or the local analyst dashboard. A SIEM is optional for research and local testing.

**Release 0.12.3:** automatic rule creation works for supported patterns; broad detection quality on real reports and production logs is still being evaluated. Rules begin as unverified drafts. Local approval saves a versioned rule; SIEM deployment is a separate analyst action.

## What it can do

| Capability | Current behavior |
|---|---|
| Collect intelligence | Poll CVE/advisory sources, RSS/Atom feeds and curated GitHub repositories. Show per-source failures, empty sources and stale results. |
| Collect independently | Run a Windows scheduled collector against the same database while Claude is closed. The computer must be on and the configured account logged in. |
| Research reports | Retain cited paragraphs, URLs and page hashes. Preserve blocked/unreadable pages as gaps. Route CVE-only leads to exposure/patch review. |
| Write rules automatically | Draft supported parent/child process actions, command-line behaviors, named DLL loads, process-linked destinations and specific file/hash selectors. Includes bounded Windows and Linux patterns. |
| Translate publisher KQL | Parse supported literal filters, grouped AND conditions, literal constants and bounded lookbacks. Preserve unsupported queries for manual review. |
| Review rule logic | Enforce exclusions, generate distinct Sigma IDs, deduplicate exact specs, warn about possible overlap and flag changed source content. |
| Map and test drafts | Show Defender and Sysmon/Splunk schema examples; use configured customer telemetry mappings. Replay labeled JSONL locally. Native query checks are implemented for Splunk and Defender hunting. |
| Track decisions | Keep draft/approved snapshots separate. Approved independent corroboration adds +1 to the pattern score, separate from environment risk. |

Community indexes contain **external file pointers**, not imported rule bodies, validated IOCs or deployed coverage. Environment risk requires confirmed assets and local event context; rule inventory remains Unknown until its scope is declared.

## How rule creation works

1. Collect a lead and inspect its cited technical report.
2. Extract supported behavior with values traceable to a paragraph or publisher query.
3. Compare available inventory and create a draft, return an existing draft, or explain the gap.
4. Generate Sigma, query templates and mapped examples or a configured native query.
5. Review the source, test malicious and benign examples, tune and explicitly approve.
6. Deploy the reviewed query in the target platform and monitor its results.

The automatic writer uses bounded sentence patterns and query parsing. Claude can also submit proposals through MCP; these are distinct from server-authored automatic drafts.

## Example: a report becomes two rules

The [fictional automatic lab](threat_research/lab_fixtures/automatic_reports.json) describes an RMM agent launching PowerShell to download `ClientSetup.msi`, followed by a silent MSI installation. The server creates **two independent process hunts**:

| Draft | Conditions | Meaning and false positives |
|---|---|---|
| RMM → PowerShell download | Parent ends with `RMM.Agent.exe`; child image contains `PowerShell`; command contains `Invoke-WebRequest` | Matches the reported download shape. Authorized RMM maintenance can match. |
| Silent MSI installation | Image ends with `msiexec.exe`; command contains both `/qn` and `ClientSetup.msi` | Matches the named quiet installation. Authorized deployment can match. |

These hunts do not establish that events belong to the same intrusion. The server does not invent an MSI parent, correlation key or time window.

### Generated Sigma example

The MSI draft below comes from the fictional lab, with metadata shortened for readability. It is experimental, not evidence of activity on a real host.

```yaml
title: Reported msiexec.exe /qn execution
id: 980d5e7c-4d76-5d37-8a8c-293c7ed2fa0c
status: experimental
description: Fictional lab draft; source review and real labeled tests pending.
logsource:
  category: process_creation
  product: windows
detection:
  selection_1:
    CommandLine|contains: '/qn'
  selection_2:
    CommandLine|contains: 'ClientSetup.msi'
  selection_3:
    Image|endswith: 'msiexec.exe'
  condition: selection_1 and selection_2 and selection_3
falsepositives:
  - Authorized deployment using the same package and quiet switch
level: medium
```

**Required telemetry:** process creation with executable name/path and full command line. Sysmon Event ID 1 is one possible source; the RMM draft also needs the parent image. A renamed package or missing command line may evade the selector. Substring/suffix matching requires benign testing.

### KQL: Microsoft Defender schema

This mapped event selector uses `DeviceProcessEvents`. Use it for hunting where the table and fields exist. It has not been executed against a customer tenant.

```kusto
DeviceProcessEvents
| where tolower(tostring(ProcessCommandLine)) contains '/qn'
    and tolower(tostring(ProcessCommandLine)) contains 'clientsetup.msi'
    and tolower(tostring(FileName)) endswith 'msiexec.exe'
```

### SPL: declared Sysmon lab

This equivalent example assumes index `sysmon_lab`, sourcetype `sysmon`, and extracted `EventCode`, `Image` and `CommandLine` fields. Replace them with actual ingestion settings.

```spl
index=sysmon_lab sourcetype=sysmon EventCode=1
| where like(lower(CommandLine), "%/qn%")
    AND like(lower(CommandLine), "%clientsetup.msi%")
    AND like(lower(Image), "%msiexec.exe")
```

These select events. A scheduled alert additionally needs a search window, schedule, trigger settings and review of expected benign activity.

## Where to implement the rules

Rules run in the platform that searches your logs. Installing the MCP server alone does not create endpoint or SIEM alerts.

| Destination | Output to use | Implementation |
|---|---|---|
| Splunk Enterprise / Cloud | SPL mapped to your index, sourcetype and fields | Test the search, then save it as a scheduled alert. |
| Microsoft Defender XDR | Kusto KQL mapped to Defender tables | Hunt first; check event identifiers, output fields and custom-detection settings before creating a detection. |
| Microsoft Sentinel | Kusto KQL mapped to actual workspace tables | Test in Logs, then create a scheduled analytics rule. Defender examples need adaptation if those tables are unavailable. |
| Elastic Security | Sigma converted/adapted to its backend and ECS fields | Test the converted query and create a custom detection rule. No native Elastic executor is included. |
| Other Sigma-compatible platforms | Sigma with the target backend and processing pipeline | Convert, map fields, test in the engine and configure alerts. |
| No SIEM | Normalized JSONL and the local matcher | Test selectors against labeled events; no native query execution or alert deployment. |

**Sigma is a portable format, not an alert engine.** Conversion requires a backend and field mappings: [Sigma conversion guide](https://sigmahq.io/docs/guide/getting-started.html). Microsoft's KQL is **Kusto Query Language**; Elastic's KQL is **Kibana Query Language**. They are different languages.

### Splunk implementation

1. Ingest telemetry and confirm required fields exist in real events.
2. Configure actual index, sourcetype and mappings. The [offline profile](examples/sysmon_splunk_lab_profile.json) is a declared example; the [connected lab profile](examples/splunk-sysmon-lab.profile.json) is a separate starting point for native checks.
3. Run the mapped SPL in Search & Reporting over known positive and benign samples. With credentials configured, `test_draft_in_siem` performs a bounded read-only query check.
4. After review, select **Save As → Alert** and set schedule, time range, trigger and notifications. Tune for repeated alerts and ingestion delays.

Syntax acceptance or zero results does not establish accuracy. See [Splunk's scheduled-alert instructions](https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.2/create-alerts/create-scheduled-alerts).

### Microsoft Sentinel / Defender implementation

For **Sentinel**, identify actual workspace tables and fields, test adapted KQL in Logs, and return `TimeGenerated`. Select **Analytics → Create → Scheduled query rule**; configure logic, entity mappings, scheduling and incidents. See [Microsoft's analytics-rule guide](https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules).

For **Defender**, the example uses its process-event schema. Before creating a custom detection, confirm permissions and the recommended event identifiers/output fields (such as `Timestamp`, `DeviceId` and `ReportId` for endpoint events); follow the [Defender custom-detection guide](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules). The project's Graph hunting check executes a bounded query; it does not publish a detection. Sentinel deployment is also manual.

### Elastic / other Sigma targets

Convert Sigma using the supported backend and processing pipeline. Check executable, parent and command-line mappings against real events; configure index, timestamp and alert settings. For Elastic, test the query and create a [custom query detection rule](https://www.elastic.co/docs/solutions/security/detect-and-alert/custom-query). This repository supplies neither a tested Elastic deployment package nor automatic Kusto-to-Kibana conversion.

## Start locally

Python **3.11+**. From the cloned project folder in Windows PowerShell:

```powershell
py -3 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -e .
& .\.venv\Scripts\python.exe -m threat_research.cli doctor
```

Connect Claude Desktop using that virtual environment's absolute `python.exe` path and arguments `-m`, `threat_research.server`. See [QUICKSTART.md](QUICKSTART.md). Fully quit and reopen Claude after updating the server.

Example Claude request:

> Use threat-research to run research_and_propose_detection("REPORT-ID"), then lead_workup("REPORT-ID"). Show source paragraphs, server-authored or analyst-authored drafts, Sigma conditions, mapped examples, possible overlaps, missing telemetry and test status. Do not verify, approve or deploy.

Replace `REPORT-ID` with a collected report ID. For stored research, page `propose_stored_drafts` until its cursor is null; fetch/refresh missing or outdated pages separately.

For independent collection, see [COLLECTOR_SETUP.md](COLLECTOR_SETUP.md). Check `polling_status` and `list_sources`: a fresh completion matters more than a running process between scheduled jobs. A timed-out MCP call may leave collection running; check before starting another poll.

## Test without a SIEM

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check_offline.ps1
```

Release 0.12.3 validation recorded **298 passing unit tests**, an MCP stdio check with **66 tools**, and **12 automatic drafts from 5 fictional reports**, including **7 translated queries and 26 predicate checks**. Unique IDs and repeat-pass deduplication passed. The separate template challenge includes intentional false positives and misses; passing means matching its documented baseline.

To test existing real Sysmon process logs locally:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\export_sysmon.ps1
& .\.venv\Scripts\python.exe -m threat_research.cli prepare-sysmon --file .\sysmon-export.xml --output-directory .\sysmon-review
```

Sysmon Event 1 must already be recorded. Review events, label `sysmon-review/labels.csv` using your own evidence, and reimport into a new directory with `--labels-file`. Then use `test_rule_against_samples` or CLI `test-rule`. See [the full workflow](COLLECTOR_SETUP.md#real-local-logs-without-a-siem). Importing XML does not establish authenticity; unknown labels cannot establish accuracy.

Source-linked approval requires analyst source verification and a labeled check on the current rule version using samples not marked synthetic. Arbitrary samples remain origin-unverified. Synthetic fixtures demonstrate logic and do not satisfy the approval gate. Approval saves a local snapshot; it does not deploy.

## Limitations and remaining work

- **Bounded extraction:** differently worded behaviors may be missed. Linux coverage is limited. This is not a general report-to-rule reasoning engine.
- **Partial publisher-query support:** joins, aggregates, OR branches and dynamic expressions remain gaps; clauses are not silently dropped. Local replay checks selectors, not relative publisher lookback scope.
- **Tuning is necessary:** authorized administration may match. Exact deduplication works; overlap warnings are heuristic, not proof of equivalent coverage.
- **Telemetry determines coverage:** missing process, command, hash or module fields cause misses. Generic templates retain placeholders until mapping; concrete examples are assumptions, not discovered infrastructure.
- **Upstream access varies:** feeds may be empty, blocked or rate-limited. Optional ThreatFox needs an authentication key. Collection stops while the host is off.
- **Validation is limited:** synthetic tests and an isolated public-paragraph replay demonstrate supported behavior. Broad real-report coverage, labeled real-log accuracy and customer native SIEM execution remain to be demonstrated. Windows wrappers require verification on Windows.
- **No automatic deployment or compromise claim:** a local approved rule is not a deployed alert; a match is not proof of intrusion; community pointers are not local coverage.

Next: measure extraction on representative real reports, address misses, and test resulting rules against labeled real logs and their target query engines.

## Further documentation

[Quickstart](QUICKSTART.md) · [Collector and telemetry setup](COLLECTOR_SETUP.md) · [Detection workflow](DETECTION_PLAYBOOK.md) · [Dashboard](DASHBOARD.md) · [Publishing](PUBLISHING.md)

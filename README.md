# Intel2Detection-MCP

**Collect threat intelligence → research behaviors → create Sigma, KQL and SPL drafts.**

- **Documented version:** 0.12.3 on [`fix/detection-gaps-oct06`](https://github.com/RoshiniMlakshmana/Intel2Detection-MCP/tree/fix/detection-gaps-oct06).
- **Main code:** currently 0.11.0. Switch to the development branch below to use the newer features and checks.
- **Use through:** Claude MCP, Python CLI or the local dashboard.
- **SIEM optional:** research and local testing work without one.
- **Current status:** supported patterns work; broad real-world accuracy is still unproven.

## What it does

- Collects CVEs, advisories, research feeds and GitHub leads.
- Shows failed sources, empty feeds and stale collection.
- Runs collection independently of Claude through a Windows scheduled task.
- Reads cited reports and saves paragraphs, URLs and page hashes.
- Creates drafts from supported process chains, commands, DLL loads, destinations and file/hash selectors.
- Supports Windows and a limited set of Linux behaviors.
- Translates supported publisher KQL filters into drafts.
- Enforces exclusions and creates unique Sigma IDs.
- Deduplicates exact rules and warns about possible overlap.
- Shows mapped examples for Defender and Sysmon/Splunk.
- Flags changed source content for review.
- Stores separate draft and approved rule versions.

## Research and review

- **Priority:** research high-priority leads, starting with CISA KEV.
- **Sources:** vendor advisories, CISA guidance and linked technical reports.
- **Normal budget:** up to 4 leads, 14 pages per lead and 40 fetches per pass.
- **Deeper research:** `deep_research_batch` supports up to 20 leads and 120 fetches.
- **Backfill:** each poll reviews 20 older researched leads; stored-only review does not fetch missing pages.
- **Triage:** groups leads needing source review, browser review or more detection detail.
- **Triage budget:** up to 8 researched leads, 16 fetches and 200 quick closures per run.
- **Enough detail:** propose an unverified draft for analyst review.
- **Insufficient detail:** show the gap; CVE-only leads go to exposure/patch review.
- **Unreadable page:** keep it pending; never count it as researched.
- **Blocked page:** offer browser/manual review; do not bypass access controls.
- **Captured text:** browser captures and manual quotes remain unverified.
- **Workup:** show source, behavior, draft/gap, required fields, inventory status and test results.
- **Existing rules:** compare available inventory before proposing; undeclared coverage stays Unknown.
- **Authorship:** distinguish server-written automatic drafts from Claude/analyst proposals.
- **Corroboration:** queue matching new research for review; approval adds +1 to the pattern score.

## Approval and risk

- Verify the original source paragraph.
- Test the current rule against labeled malicious and benign events.
- Review existing rules and possible overlaps.
- Explicitly approve before saving an approved local snapshot.
- Test the mapped query in its target engine before deployment.
- Synthetic tests do not satisfy source-linked approval requirements.
- Imported samples remain origin-unverified; XML alone does not prove authenticity.
- Approval saves locally; it does not deploy or push a rule.
- Environment risk needs confirmed assets and local event context.
- Risk uses the asset named in that event; it does not combine unrelated assets.
- Threat priority, corroboration score and environment risk are separate.

## Example rules created

From the [fictional RMM report](https://github.com/RoshiniMlakshmana/Intel2Detection-MCP/blob/fix/detection-gaps-oct06/threat_research/lab_fixtures/automatic_reports.json), the server creates two independent drafts:

- **PowerShell download:** `RMM.Agent.exe` parent + image containing `PowerShell` + `Invoke-WebRequest` command.
- **Silent MSI installation:** `msiexec.exe` image + `/qn` + `ClientSetup.msi`.
- **Telemetry:** process creation, image and command line; the first rule also needs parent image.
- **False positives:** authorized RMM maintenance and software deployment.
- **Limits:** renamed packages or missing fields can evade matching.
- **Scope:** separate hunts; no invented event correlation or MSI parent.

<details>
<summary>Show Sigma, KQL and SPL examples</summary>

**Sigma:** generated MSI selector, with metadata shortened. Fictional, experimental and unverified.

```yaml
title: Reported msiexec.exe /qn execution
id: 980d5e7c-4d76-5d37-8a8c-293c7ed2fa0c
status: experimental
description: Fictional lab draft; real labeled tests pending.
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
  - Authorized deployment of the same package
level: medium
```

**Kusto KQL:** Defender schema example; not executed in a customer tenant.

```kusto
DeviceProcessEvents
| where tolower(tostring(ProcessCommandLine)) contains '/qn'
    and tolower(tostring(ProcessCommandLine)) contains 'clientsetup.msi'
    and tolower(tostring(FileName)) endswith 'msiexec.exe'
```

**SPL:** assumes extracted Sysmon fields, index `sysmon_lab` and sourcetype `sysmon`. Adjust to actual ingestion.

```spl
index=sysmon_lab sourcetype=sysmon EventCode=1
| where like(lower(CommandLine), "%/qn%")
    AND like(lower(CommandLine), "%clientsetup.msi%")
    AND like(lower(Image), "%msiexec.exe")
```

</details>

## Where and how to implement

- **First:** ingest relevant logs and confirm every required field.
- **Map:** configure actual tables/indexes, sourcetypes and field names.
- **Test:** check known positive and benign events; tune exclusions.
- **Splunk:** run mapped SPL → **Save As → Alert** → set schedule, time range, trigger and notifications. [Guide](https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.2/create-alerts/create-scheduled-alerts).
- **Sentinel:** adapt KQL to workspace tables, return `TimeGenerated`, test in Logs → **Analytics → Create → Scheduled query rule** → set entities, schedule and incidents. [Guide](https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules).
- **Defender:** test KQL in Advanced hunting → check identifiers such as `Timestamp`, `DeviceId` and `ReportId` → create and configure a custom detection. [Guide](https://learn.microsoft.com/en-us/defender-xdr/custom-detection-rules).
- **Elastic:** convert Sigma with an appropriate backend and ECS mappings → test → create a custom detection rule. No native Elastic executor is included. [Guide](https://www.elastic.co/docs/solutions/security/detect-and-alert/custom-query).
- **Other platforms:** convert Sigma with the target backend and field pipeline. [Sigma guide](https://sigmahq.io/docs/guide/getting-started.html).
- **No SIEM:** replay labeled JSONL locally; this checks selectors, not native queries.
- **Native checks:** `test_draft_in_siem` supports bounded Splunk/Defender queries; it does not publish alerts.
- **Important:** Microsoft Kusto KQL and Elastic Kibana KQL are different languages.
- **Profiles:** [offline example](https://github.com/RoshiniMlakshmana/Intel2Detection-MCP/blob/fix/detection-gaps-oct06/examples/sysmon_splunk_lab_profile.json) · [connected Splunk lab](https://github.com/RoshiniMlakshmana/Intel2Detection-MCP/blob/fix/detection-gaps-oct06/examples/splunk-sysmon-lab.profile.json). Use only mappings that match actual ingestion.

## Start and test

- Requires Python **3.11+**.
- Run these commands from the cloned project folder in PowerShell:

```powershell
git fetch origin
git switch fix/detection-gaps-oct06
py -3 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -e .
& .\.venv\Scripts\python.exe -m threat_research.cli doctor
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\check_offline.ps1
```

- Connect Claude to the absolute venv `python.exe` path with arguments `-m`, `threat_research.server`.
- Fully quit and reopen Claude after updating.
- Ask Claude to run `research_and_propose_detection("REPORT-ID")`, then `lead_workup("REPORT-ID")`.
- Request cited predicates, mapped queries, overlaps, missing telemetry and test results.
- Check `polling_status` and `list_sources` for collection health.
- If a poll call times out, check whether collection is still running before retrying.
- Page `propose_stored_drafts` until its cursor is null for a complete stored backfill.
- **0.12.3 checks:** 298 passing tests; MCP smoke check with 66 tools.
- **Automatic lab:** 5 fictional reports, 12 server-written drafts, 7 query translations and 26 predicate checks.
- **Template challenge:** includes intentional false positives and misses.
- **NeedyMantis fixture:** 2 matches, 2 malicious misses and 2 benign nonmatches; synthetic only.
- **Real logs without SIEM:** export existing Sysmon Event 1, normalize, label and replay. [Instructions](https://github.com/RoshiniMlakshmana/Intel2Detection-MCP/blob/fix/detection-gaps-oct06/COLLECTOR_SETUP.md#real-local-logs-without-a-siem).

## Limitations

- Supported sentence patterns can miss differently worded behaviors.
- Linux coverage is limited.
- Complex KQL joins, aggregates, OR branches and dynamic expressions need manual review.
- Local replay does not evaluate relative publisher lookback scope.
- Generic queries keep placeholders until telemetry is mapped.
- Concrete examples are schema assumptions, not discovered infrastructure.
- Authorized activity can match; overlap warnings are heuristic.
- Community indexes are pointers, not imported rules or local coverage.
- Feeds can fail, be blocked or require credentials; ThreatFox needs its optional key.
- Collection is polling, not streaming; the Windows task needs the host on and user logged in.
- Email requires configuration; otherwise the digest is saved locally.
- Synthetic results do not establish production accuracy.
- Broad real-report coverage, real-log accuracy and customer native SIEM results remain unproven.
- A rule match does not prove compromise; approval does not deploy alerts.

## Next priorities

- Measure extraction across representative real reports.
- Fix missed behaviors and query-conversion gaps.
- Test drafts against labeled real logs and target query engines.

[Quickstart](https://github.com/RoshiniMlakshmana/Intel2Detection-MCP/blob/fix/detection-gaps-oct06/QUICKSTART.md) · [Collector setup](https://github.com/RoshiniMlakshmana/Intel2Detection-MCP/blob/fix/detection-gaps-oct06/COLLECTOR_SETUP.md) · [Detection guide](https://github.com/RoshiniMlakshmana/Intel2Detection-MCP/blob/fix/detection-gaps-oct06/DETECTION_PLAYBOOK.md) · [Dashboard](https://github.com/RoshiniMlakshmana/Intel2Detection-MCP/blob/fix/detection-gaps-oct06/DASHBOARD.md) · [Publishing](https://github.com/RoshiniMlakshmana/Intel2Detection-MCP/blob/fix/detection-gaps-oct06/PUBLISHING.md)

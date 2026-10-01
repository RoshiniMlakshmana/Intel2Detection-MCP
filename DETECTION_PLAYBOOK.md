# Detection research guide for Claude

When asked to find patterns and rules, use the `threat-research` MCP tools in this order:

1. `polling_status` and `list_sources` to show which sources were fetched and which failed. Use `poll_now` only when a fresh collection was requested.
2. `list_leads(source=...)` to select a lead. Run `research_and_propose_detection(threat_id)` to read its cited pages, including a bounded set of directly linked original reports from configured hosts. Show the actual URL, publication date, paragraph, quoted values, and the publisher's reason for calling the activity malicious.
3. Inspect `rule_proposals` and `lead_workup(threat_id)`. When a draft exists, explain each Sigma predicate, generic KQL/SPL, required fields, benign look-alikes, exact sample or behavioral scope, and current testing state. Say whether the rule identifies one file sample or a behavior. Do not describe a publisher's claim as a local sighting.
4. If no draft is supported, report the precise gap and keep it in Needs attention. Check source links and any publisher query; do not invent process relationships, hash values, fields, a numeric risk score, a local inventory match, or successful SIEM execution.
5. After onboarding, compare the client's complete rule inventory, map fields to the actual SIEM, run labeled positive and benign checks, then test natively with read-only access. Report environment risk only with the confirmed asset and recorded local event context. Source verification and local approval require the analyst's explicit decision.

## Worked examples

**Supported sample selector:** A first-party report says “the malicious loader `FictLoader.dll` (SHA-256: `<64 hex characters>`) replaced an updater.” An unverified file-event draft can match both that full hash and that file name. Explain that it identifies one reported sample, needs file-hash telemetry, and may miss renamed or rebuilt versions. Never claim the hash was seen locally.

**Supported behavioral proposal:** A first-party report says “during the intrusion `w3wp.exe` spawned `cmd.exe`.” An unverified Windows process-creation draft can match `ParentImage` ending in `w3wp.exe` and `Image` ending in `cmd.exe`. Explain attacker intent as possible post-exploitation command execution, and note that administrative activity may also spawn shells. Verify process lineage and benign events before approval.

**Insufficient claim:** “Attackers used DLL sideloading” names no parent, loaded module, hash, path, or bounded field values. Preserve it as a behavior lead and seek the original technical report or publisher hunting query. A filename alone is also insufficient for a file identity rule. A blocked page remains blocked until a browser capture or manual review records what it actually says.

For a quick review prompt: `Use threat-research research_and_propose_detection("REPORT-ID"), then lead_workup("REPORT-ID"). Show the cited behavior, why the publisher calls it malicious, proposed rule or exact gap, telemetry, source and test gates, inventory connection, and local risk availability. Do not verify, approve, or deploy.`

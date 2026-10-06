# Detection research guide for Claude

When asked to find patterns and rules, use the `threat-research` MCP tools in this order:

1. `polling_status` and `list_sources` to show which sources were fetched and which failed. Use `poll_now` only when a fresh collection was requested.
2. `list_leads(source=...)` to select a lead. Run `research_and_propose_detection(threat_id)` to read its cited pages, including a bounded set of directly linked original reports from configured hosts. Show the actual URL, publication date, paragraph, quoted values, and the publisher's reason for calling the activity malicious.
3. Inspect every `rule_proposals` entry and `lead_workup(threat_id)` pattern. When drafts exist, explain each Sigma predicate, generic KQL/SPL, required fields, benign look-alikes, exact sample or behavioral scope, and current testing state. Say whether each rule identifies one file sample or a behavior. Do not describe a publisher's claim as a local sighting.
4. If no draft is supported, report the precise gap and keep it in Needs attention. Check source links and any publisher query; do not invent process relationships, hash values, fields, a numeric risk score, a local inventory match, or successful SIEM execution.
5. After onboarding, compare the client's complete rule inventory, map fields to the actual SIEM, run labeled positive and benign checks, then test natively with read-only access. Report environment risk only with the confirmed asset and recorded local event context. Source verification and local approval require the analyst's explicit decision.

## Bulk research and proposals

If asked to process *all already researched leads*, call `propose_stored_drafts(limit=20, after_id="")`, then pass each non-null `next_cursor` back as `after_id` until it is null. This step does not fetch pages. Report the number of leads processed, new drafts, existing matches, and gaps, then list new draft IDs with their lead and paragraph. Do not print every long workup before finishing pagination. Use `lead_workup` for the resulting drafts the user selects. Polling also advances a smaller durable stored-research backfill automatically.

Use `deep_research_batch` separately to fetch due pages that have not been read or whose extractor version is old; a publisher-blocked or non-allowlisted page stays in Needs attention. The stored-only batch cannot infer paragraphs absent from the saved research. If `propose_stored_drafts` is unavailable, the Claude process has not loaded this MCP version. Report that version mismatch instead of treating two one-lead calls as a completed bulk run.

## Worked examples

**Supported sample selector:** A first-party report says “the malicious loader `FictLoader.dll` (SHA-256: `<64 hex characters>`) replaced an updater.” An unverified file-event draft can match both that full hash and that file name. Explain that it identifies one reported sample, needs file-hash telemetry, and may miss renamed or rebuilt versions. Never claim the hash was seen locally.

**Supported behavioral proposal:** A first-party report says “during the intrusion `w3wp.exe` spawned `cmd.exe`.” An unverified Windows process-creation draft can match `ParentImage` ending in `w3wp.exe` and `Image` ending in `cmd.exe`. Explain attacker intent as possible post-exploitation command execution, and note that administrative activity may also spawn shells. Verify process lineage and benign events before approval.

**Other source-grounded behaviors:** If one inspected paragraph explicitly says attacker-controlled `Poedit.exe` loaded `WinSparkle.dll` through DLL sideloading, propose an unverified `image_load` rule matching that process and module. If it explicitly says a malware process connected to a named C2 hostname, propose an unverified `network_connection` rule matching the process and destination hostname. Neither is proof of compromise: a legitimate module load or shared destination can match. Image-load logging or process-linked destination telemetry must exist, and the analyst checks benign examples.

**Reported sideload and Linux hunt:** A paragraph that says `GatherOsState.exe` sideloads the reported backdoor `slc.dll` supports an unverified `image_load` process/module draft, even when the publisher names the backdoor after the action. A Linux paragraph that explicitly connects a named pipe, `/bin/sh`, and `openssl s_client` in a reverse shell supports an unverified OpenSSL process hunt. A matching `openssl s_client` event alone does not prove the reverse shell; benign TLS diagnostics will match and missing command-line telemetry will miss it. Explain these limits beside Sigma, KQL and SPL.

**Insufficient claim:** “Attackers used DLL sideloading” names no parent, loaded module, hash, path, or bounded field values. Preserve it as a behavior lead and seek the original technical report or publisher hunting query. A filename alone is also insufficient for a file identity rule. A blocked page remains blocked until a browser capture or manual review records what it actually says.

For a quick review prompt: `Use threat-research research_and_propose_detection("REPORT-ID"), then lead_workup("REPORT-ID"). Show the cited behavior, why the publisher calls it malicious, proposed rule or exact gap, telemetry, source and test gates, inventory connection, and local risk availability. Do not verify, approve, or deploy.`

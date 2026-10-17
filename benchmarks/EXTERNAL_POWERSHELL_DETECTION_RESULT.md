# Verified external telemetry detection — Mordor PowerShell 4103

**Result: A REAL TELEMETRY MATCH WAS OBSERVED; MALICIOUS VERDICT AND DETECTION ACCURACY NOT ESTABLISHED.**

## Reproducible execution

- Source: [Mordor Empire Mimikatz LogonPasswords archive](https://github.com/thomaspatzke/mordor) at immutable upstream commit `84865f779d00bd5839301642fd0e907cfc78240c`.
- Original compressed file SHA-256: `b2f12d051b258d461df7cbd712267b5af5eb9abbff651b7cf06ddf4e2dd86ddc`.
- Successful [GitHub Actions detection execution #38994927672](https://github.com/RoshiniMlakshmana/Intel2Detection-MCP/actions/runs/38994927672), artifact `real-external-telemetry-match-report`.
- Rule implementation: `scripts/detect_external_powershell_4103.py`.
- All **4,576 source records** were scanned by the local observable matcher. **1,735 PowerShell Event ID 4103 records** showed `Host Application = ...powershell.exe ... -enc <payload>` or equivalent encoded-command argument.
- Example trace: `record_number=76918`, `@timestamp=2019-05-18T20:21:48.223Z`, `event_id=4103`, `source_name=Microsoft-Windows-PowerShell`. Command line is represented by SHA-256 `0c6b6ba0c30c6853d3b4fd22b7f47ebd2d7fae3c6dd2ce67b3f29534eac24ad3` in the published alert rather than printing encoded content.
- Source evidence: original Windows event *message* includes a `Host Application` line ending with the PowerShell encoded-command switch. This is actual externally recorded Windows PowerShell module logging, not a fabricated test fixture.

## Interpretation and limits

**Observable detection succeeded**: local code matched genuine external Windows PowerShell 4103 entries. An encoded-command parameter is suspicious and worth investigation but is not definitive proof of maliciousness. 1,735 records may repeat the *same invocation across module logging lines*; this is neither 1,735 separate attacks nor 1,735 true positives. There are **no independent event-level malicious/benign labels**, no legitimate comparison population here, and no native Splunk SPL/KQL/Sigma query execution. There is **no defensible precision, recall, false-positive rate or production accuracy metric**.

This standalone detector handles **PowerShell Event ID 4103**, a different telemetry family from the existing **Sysmon Event ID 1 / DeviceProcessEvents** `encoded_powershell` rule draft. **Do not claim the previously generated Sigma/KQL/SPL drafts matched these Event 4103 records.** The current execution proves a *specific implemented observable event matcher* works on external captured data, not that every generated rule works in every engine.

Review/approval of rules for deployment remains the installer's responsibility.

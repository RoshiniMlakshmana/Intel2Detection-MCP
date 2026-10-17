# Independent event-label dataset audit — October 16, 2026

**Status: DATASET REJECTED FOR NATIVE DETECTION-RULE TESTING; NO PERFORMANCE SCORE.**

## What was actually checked

- External source: [SILRAD Sysmon ransomware/goodware dataset](https://github.com/JamilIsp/SILRAD-dataset), pinned source commit `5085216bac1758023c672214d61b88dcc992da8b`.
- Run: [GitHub Actions research-only inspection #38992727002](https://github.com/RoshiniMlakshmana/Intel2Detection-MCP/actions/runs/38992727002), successful.
- Pinned archive URL: `https://raw.githubusercontent.com/JamilIsp/SILRAD-dataset/5085216bac1758023c672214d61b88dcc992da8b/SILRAD-dataset.zip`.
- Archive downloaded 3,807,648 bytes; SHA-256: `29a2a75117fd7f9b7c9360292f3dc22a7eef293e7db74e4cf0f97054110a3779`.
- Included `fasttext-all-nofamily.csv` (89,690,388 uncompressed bytes), `fasttext-testmodel.csv` (71,427,377 bytes), and `fasttext-trainmodel.csv` (18,263,460 bytes).
- Inspected header of the 18 MB train CSV: `event.code, CallTrace, CommandLine, Company, CurrentDirectory, Description, Details, EventType, GrantedAccess, Image, ImageLoaded, IntegrityLevel, ... ParentImage, ... task, class`.
- **Crucial finding:** the actual field values are **float feature representations**, not raw telemetry strings. In the first record, `Image` is `0.000378996` and `ParentImage` is `-0.025142908`; these cannot be matched against source-derived literals such as `powershell.exe` or `ParentImage endswith csc.exe`.

## Why this corpus was NOT scored

SILRAD's independent study describes goodware/ransomware labels, but the downloadable CSV has encoded/normalized numeric feature values. Those values do not preserve the process names and command-line tokens required by our generated Sigma/KQL/SPL predicates. Testing them directly would falsely report a collection of non-matches as missed malicious process chains, and a dataset-class label is not always a reliable per-event indicator of malicious activity.

The validation workflow therefore **did not fabricate an event-label mapping, synthesize command-line strings, or report TP/FP/FN/TN**. The source download succeeded; raw event-level validation remains blocked by incompatible representation. A different independently labeled corpus that retains the raw event fields is needed.

## What is already available

- `scripts/check_external_sysmon.py`: third-party raw Sysmon Event 1 XML schema compatibility, **unlabeled**.
- `scripts/evaluate_external_labels.py`: strict event-level external truth and SHA-256 gate; returns **UNSCORED** if no saved rule matches are available.
- Publisher report evaluations and synthetic fictional replay are separate, never combined into production accuracy.

**Open research gap:** Obtain attack/benign event-level labels with full original `Image`, `ParentImage`, `CommandLine`, `ImageLoaded` and other relevant fields, select source-linked drafts that apply to those attacker behaviors *without tuning on test data*, and score all relevant events. Native SIEM validation remains additional work.

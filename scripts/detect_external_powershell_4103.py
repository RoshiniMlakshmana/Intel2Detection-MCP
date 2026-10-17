#!/usr/bin/env python3
"""Evidence-only PowerShell 4103 encoded-command telemetry alert on Mordor capture.

Distinct from Sysmon Event 1 Sigma draft execution and not an independent
attack/benign performance benchmark.
"""
import argparse
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path

HOST = re.compile(r"(?im)^\s*Host Application\s*=\s*([^\r\n]{1,8192})")
ENCODED = re.compile(r"(?i)\s-(?:enc|encodedcommand|e)\s+\S+")
MAX_ARCHIVE = 6_000_000
MAX_MEMBER = 65_000_000
MAX_EVENT = 140_000
DATASET = "https://github.com/thomaspatzke/mordor"
EXPECTED_SHA = "b2f12d051b258d461df7cbd712267b5af5eb9abbff651b7cf06ddf4e2dd86ddc"


def inspect_record(row):
    if not isinstance(row, dict) or row.get("source_name") != "Microsoft-Windows-PowerShell":
        return None
    if str(row.get("event_id")) != "4103":
        return None
    message = row.get("message")
    if not isinstance(message, str):
        return None
    m = HOST.search(message)
    if not m or not ENCODED.search(m.group(1)):
        return None
    return {
        "event_record": row.get("record_number"),
        "timestamp": row.get("@timestamp"),
        "event_id": 4103,
        "source": row.get("source_name"),
        "behavior": "encoded_powershell_host_application",
        "evidence_type": "observed_powershell_module_log_host_application_encoded_switch",
        "command_line_sha256": hashlib.sha256(m.group(1).encode()).hexdigest(),
        "rule": "4103 PowerShell Host Application contains encoded-command switch",
        "attack_verdict": "UNKNOWN_REQUIRES_INVESTIGATION",
    }


def evaluate_archive(blob):
    if len(blob) > MAX_ARCHIVE or hashlib.sha256(blob).hexdigest() != EXPECTED_SHA:
        raise ValueError("pinned source archive hash/size mismatch")
    inspected = 0
    matches = []
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tar:
        members = tar.getmembers()
        if len(members) != 1 or not members[0].isfile() or members[0].size > MAX_MEMBER:
            raise ValueError("unexpected raw Mordor member")
        file = tar.extractfile(members[0])
        # The file is line-delimited JSON; parse each row and never print script bodies.
        for raw in file:
            if len(raw) > MAX_EVENT:
                raise ValueError("oversized raw event")
            row = json.loads(raw)
            inspected += 1
            alert = inspect_record(row)
            if alert:
                matches.append(alert)
    return {
        "dataset": DATASET,
        "archive_sha256": EXPECTED_SHA,
        "events_inspected": inspected,
        "alert_count": len(matches),
        "sample_alerts": matches[:5],
        "local_heuristic_tested": True,
        "generated_sigma_kql_spl_rule_tested": False,
        "attack_vs_benign_event_ground_truth": "UNKNOWN",
        "interpretation": "Observable encoded PowerShell command found in third-party captured Windows PowerShell 4103 telemetry; not a confirmed malicious alert, native SIEM run, or accuracy metric."
    }


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    report = evaluate_archive(args.archive.read_bytes())
    result = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(result, encoding="utf-8")
    print(result)


if __name__ == "__main__":
    main()

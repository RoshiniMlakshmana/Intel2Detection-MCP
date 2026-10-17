#!/usr/bin/env python3
"""Evaluate existing unverified local rules against independently labeled events.

A reproducible *harness*, not a pretense that arbitrary attack-corpus records
are individually labeled. Only datasets with a documented independent label
per event may be scored. No network, model inference, synthetic backfilling or
native SIEM invocation occurs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from threat_research import soc_replay

FIELDS = {"event_id", "timestamp", "event_type"}
LABELS = {True, False}


def _file_hash(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def evaluate(events_path, labels_path, rule_database):
    events_path, labels_path, rule_database = map(Path, (events_path, labels_path, rule_database))
    label_info = json.loads(labels_path.read_text(encoding="utf-8"))
    if label_info.get("schema_version") != 1 or label_info.get("provenance") != "externally_verified_event_labels":
        raise ValueError("A manifest documenting independent event-level labels is required")
    if not label_info.get("external_dataset_url") or not label_info.get("independent_label_evidence_url"):
        raise ValueError("External source and independent label-evidence URLs are both required")
    if label_info.get("events_sha256") != _file_hash(events_path):
        raise ValueError("Event file SHA-256 differs from fixed label manifest")
    cases = label_info.get("labels")
    if not isinstance(cases, list) or not cases:
        raise ValueError("Nonempty event-level labels required")
    labels = {}
    for case in cases:
        if (not isinstance(case, dict) or
                set(case) != {"event_id", "expected_malicious", "evidence"} or
                not isinstance(case["event_id"], str) or not case["event_id"] or
                type(case["expected_malicious"]) is not bool or
                not isinstance(case["evidence"], str) or not case["evidence"].strip()):
            raise ValueError("Every individual event needs independently evidenced boolean ground truth")
        if case["event_id"] in labels:
            raise ValueError("Duplicate event label")
        labels[case["event_id"]] = case
    events = list(soc_replay.read_jsonl(events_path))
    if len(events) != len(labels):
        raise ValueError("Cannot silently exclude unlabeled events or extra labels")
    for event in events:
        if not FIELDS.issubset(event):
            raise ValueError("Event ID, UTC timestamp and event family are required")
        entry = labels.pop(event["event_id"], None)
        if entry is None:
            raise ValueError(f"Unlabeled event: {event['event_id']}")
        if "expected_malicious" in event or "scenario" in event:
            raise ValueError("Input event file must not smuggle or define its own ground truth")
        event["expected_malicious"] = entry["expected_malicious"]
        event["scenario"] = "externally labeled event " + event["event_id"]
    if labels:
        raise ValueError("Labels without event records")

    rules = soc_replay.local_rules(rule_database, include_drafts=True)
    if not rules:
        return {
            "status": "UNSCORED_NO_STORED_RULES",
            "counts": None,
            "rule_count": 0,
            "event_count": len(events),
            "source": label_info["external_dataset_url"],
            "labels": label_info["independent_label_evidence_url"],
            "native_siem_executed": False
        }
    result = soc_replay.replay(events, rules)
    return {
        "status": "SCORED_LOCAL_REFERENCE_MATCHER_ONLY",
        "counts": result["counts"],
        "cases": result["cases"],
        "sample_size": result["sample_size"],
        "precision": result["precision"],
        "recall": result["recall"],
        "false_positive_rate": result["false_positive_rate"],
        "rule_count": len(rules),
        "events_sha256": _file_hash(events_path),
        "labels_sha256": _file_hash(labels_path),
        "rule_ids": [r["id"] for r in rules],
        "source": label_info["external_dataset_url"],
        "label_evidence": label_info["independent_label_evidence_url"],
        "native_siem_executed": False,
        "production_accuracy": False,
        "limitations": "External event-level truth assumed only from supplied independent evidence. Local matcher, not Sigma/KQL/SPL query execution. Dataset selected and limited; not production performance."
    }


def main(argv=None):
    p = argparse.ArgumentParser(description="Strict external labeled-event matcher; not native SIEM execution")
    p.add_argument("--events", required=True, type=Path)
    p.add_argument("--labels", required=True, type=Path)
    p.add_argument("--rule-database", required=True, type=Path)
    p.add_argument("--output", type=Path)
    a = p.parse_args(argv)
    result = evaluate(a.events, a.labels, a.rule_database)
    data = json.dumps(result, indent=2) + "\n"
    if a.output:
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(data, encoding="utf-8")
    print(data, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

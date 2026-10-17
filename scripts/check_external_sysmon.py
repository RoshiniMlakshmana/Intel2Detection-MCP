#!/usr/bin/env python3
"""Inspect *externally authored* Sysmon Event 1 XML, optionally run local draft matcher.

This is a parser-and-telemetry smoke test, NOT a confirmed benign or attack
ground-truth benchmark, and NOT a native Sigma/KQL/SPL engine.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path

from threat_research import soc_replay

ROOT = Path(__file__).resolve().parent.parent
SAMPLE = ROOT / "benchmarks" / "external_sysmon_sample.xml"
SOURCE = "https://github.com/Neo23x0/evt2sigma/blob/master/tests/sysmon-event.xml"
LIMIT = 128_000
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_event(raw: bytes):
    if not raw or len(raw) > LIMIT or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
        raise ValueError("untrusted or oversized XML")
    root = ET.fromstring(raw)
    provider = root.find("./e:System/e:Provider", NS)
    event_id = root.findtext("./e:System/e:EventID", namespaces=NS)
    if root.tag != "{http://schemas.microsoft.com/win/2004/08/events/event}Event" or (
        provider is None or provider.get("Name") != "Microsoft-Windows-Sysmon" or event_id != "1"
    ):
        raise ValueError("expected Sysmon process creation Event ID 1")
    data = {}
    for item in root.findall("./e:EventData/e:Data", NS):
        name = item.get("Name")
        if name in data or not name:
            raise ValueError("duplicate or anonymous Sysmon field")
        data[name] = item.text or ""
    if not data.get("Image") or not data.get("ParentImage"):
        raise ValueError("Sysmon process record missing Image or ParentImage")
    return {
        "event_id": root.findtext("./e:System/e:EventRecordID", namespaces=NS) or "external-sample",
        "timestamp": root.find("./e:System/e:TimeCreated", NS).get("SystemTime"),
        "event_type": "process_creation",
        **data,
    }


def inspect(xml_path: Path, rule_database: Path | None = None):
    raw = xml_path.read_bytes()
    event = parse_event(raw)
    rules = soc_replay.local_rules(rule_database, include_drafts=True) if rule_database else []
    hits = [r for r in rules if soc_replay._matches(r, event)]
    return {
        "provenance": "externally_authored_third_party_sysmon_example",
        "publisher_url": SOURCE,
        "sha256_of_exact_xml_bytes": hashlib.sha256(raw).hexdigest(),
        "record_type": "Sysmon Event 1",
        "sample_records": 1,
        "observed_field_names": sorted(event.keys()),
        "observed_image": event["Image"],
        "observed_parent_image": event["ParentImage"],
        "rules_loaded": len(rules),
        "local_reference_match_count": len(hits),
        "matched_rule_ids": [r["id"] for r in hits],
        "ground_truth_malicious_label": None,
        "outcome": "unlabeled_external_telemetry_parser_smoke_only",
        "limitations": "One third-party sample event, with NO attack/benign label; zero matching rules if --rule-database is absent. Never report detection accuracy, native SIEM execution, or that this validates generated rules."
    }


def main(argv=None):
    p = argparse.ArgumentParser(description="Unlabeled third-party Sysmon XML parser and optional draft matcher")
    p.add_argument("--xml", type=Path, default=SAMPLE)
    p.add_argument("--rule-database", type=Path, default=None)
    p.add_argument("--output", type=Path, default=None)
    a = p.parse_args(argv)
    result = inspect(a.xml, a.rule_database)
    data = json.dumps(result, indent=2) + "\n"
    if a.output:
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(data, encoding="utf-8")
    print(data, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

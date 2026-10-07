"""Local SOC event stream and labeled replay for narrow draft-rule evaluation.

This reference matcher evaluates the structured Sigma selections for supported
templates; it is not a Sigma engine or a Splunk/Defender query execution.
"""

import hashlib
import json
import re
import sys
import time
from datetime import datetime
from importlib import resources
from pathlib import Path

from . import custom_rules, store
from .core import now
from .rules import TEMPLATES

MAX_EVENT_BYTES = 64_000
EVENT_TYPES = {"process_creation", "network_connection", "file_event", "image_load", "web_access",
               "proxy", "tool_invocation"}


def local_rules(path=None, include_drafts=False):
    """Read only local inventory rules; expired hunts never run."""
    if path is not None:
        path = Path(path)
    store.initialize(path)
    statuses = ("approved", "draft") if include_drafts else ("approved",)
    with store.connection(path) as db:
        rows = db.execute("SELECT r.*,t.indicator,c.spec AS custom_spec FROM rules r JOIN threats t ON t.id=r.threat_id "
                          "LEFT JOIN custom_rule_specs c ON c.rule_id=r.id "
                          "WHERE r.status IN (" + ",".join("?" for _ in statuses) + ")", statuses).fetchall()
    return [dict(row) for row in rows if not row["expires_at"] or row["expires_at"] > now()]


def _selection_matches(selection, event):
    for key, expected in selection.items():
        field, _, operator = key.partition("|")
        value = event.get(field)
        if value is None or isinstance(value, (list, dict, bool)):
            return False
        choices = expected if isinstance(expected, list) else [expected]
        if operator == "endswith":
            matched = isinstance(value, str) and any(value.casefold().endswith(x.casefold()) for x in choices)
        elif operator == "contains":
            matched = isinstance(value, str) and any(x.casefold() in value.casefold() for x in choices)
        elif not operator:
            matched = any(value == x for x in choices)
        else:
            raise ValueError("unsupported Sigma selection operator")
        if not matched:
            return False
    return True


def _matches(rule, event):
    behavior = rule["behavior"]
    if behavior == "custom":
        if not rule.get("custom_spec"):
            return False
        spec = json.loads(rule["custom_spec"])
        kind = "tool_invocation" if spec["event_family"] == "mcp_audit" else spec["event_family"]
        if event.get("event_type") != kind:
            return False
        if "sequence" in spec:
            return False  # Single events never satisfy a correlation.
        def matches_predicate(predicate):
            raw = event.get(predicate["field"])
            if raw is None or isinstance(raw, (list, dict)) or (isinstance(raw, bool) and predicate["field"] != "Signed") \
                    or not isinstance(raw, (str, int, bool)):
                return False
            observed, expected = str(raw), predicate["value"]
            if not predicate.get("case_sensitive"):
                observed, expected = observed.casefold(), expected.casefold()
            return {"equals": observed == expected, "contains": expected in observed,
                    "endswith": observed.endswith(expected), "startswith": observed.startswith(expected),
                    "has": bool(re.search(custom_rules.term_regex(expected), observed))}[predicate["operator"]]
        return (all(matches_predicate(p) for p in spec["predicates"])
                and (not spec.get("any_of") or any(matches_predicate(p) for p in spec["any_of"]))
                and not any(matches_predicate(p) for p in spec.get("exclude", [])))
    if behavior == "ioc_network":
        if event.get("event_type") != "network_connection":
            return False
        try:
            ip, port = rule["indicator"].rsplit(":", 1)
            return event.get("DestinationIp") == ip and type(event.get("DestinationPort")) is int and event["DestinationPort"] == int(port)
        except (AttributeError, ValueError):
            return False
    required = "tool_invocation" if behavior == "mcp_unauthorized_execution" else "process_creation"
    return event.get("event_type") == required and _selection_matches(TEMPLATES[behavior]["sigma_selection"], event)


def detect(event, rules):
    """Emit only identifiers and rule metadata; keep command lines in the local log."""
    if not isinstance(event, dict) or not isinstance(event.get("event_id"), str) or not event["event_id"]:
        raise ValueError("event_id is required")
    if event.get("event_type") not in EVENT_TYPES or not isinstance(event.get("timestamp"), str):
        raise ValueError("event_type and timestamp are required")
    return [{"event_id": event["event_id"], "timestamp": event["timestamp"],
             "rule_id": rule["id"], "behavior": rule["behavior"], "rule_status": rule["status"],
             "threat_id": rule["threat_id"], "lab_or_local_match": True}
            for rule in rules if _matches(rule, event)]


def read_jsonl(file):
    """Require bounded, complete JSONL records; a broken fixture fails clearly."""
    try:
        with Path(file).open("rb") as stream:
            for line_number, raw in enumerate(stream, 1):
                if len(raw) > MAX_EVENT_BYTES or not raw.endswith(b"\n"):
                    raise ValueError(f"line {line_number} is oversized or incomplete")
                try:
                    yield json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValueError(f"line {line_number} is invalid JSON") from exc
    except OSError as exc:
        raise ValueError(f"cannot read labeled events file {str(file)!r}: {exc.strerror or exc}") from exc


def replay(events, rules):
    """Binary event-level confusion matrix with all false alerts and misses visible."""
    events = list(events)
    sequence_hits = _sequence_hits(events, rules)
    counts = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
    cases, seen = [], set()
    for event in events:
        if not isinstance(event.get("expected_malicious"), bool) or not isinstance(event.get("scenario"), str):
            raise ValueError("replay records require a scenario and a boolean expected_malicious label")
        if event.get("event_id") in seen:
            raise ValueError("duplicate event_id in replay")
        seen.add(event["event_id"])
        hits = detect(event, rules)
        hits.extend(sequence_hits.get(event["event_id"], []))
        bucket = ("tp" if hits else "fn") if event["expected_malicious"] else ("fp" if hits else "tn")
        counts[bucket] += 1
        cases.append({"event_id": event["event_id"], "scenario": event["scenario"],
                      "truth": "malicious" if event["expected_malicious"] else "benign",
                      "outcome": bucket, "rule_ids": [hit["rule_id"] for hit in hits],
                     "behaviors": [hit["behavior"] for hit in hits]})
    tp, fp, fn, tn = (counts[key] for key in ("tp", "fp", "fn", "tn"))
    return {"sample_size": len(cases), "counts": counts,
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "false_positive_rate": round(fp / (fp + tn), 3) if fp + tn else None,
            "cases": cases,
            "scope": "Synthetic labeled event fixtures; local reference matching, not production SIEM accuracy."}


def _sequence_hits(events, rules):
    """Evaluate ordered pairs by event time; emit on the second event only."""
    hits = {}
    for rule in rules:
        spec = json.loads(rule["custom_spec"]) if rule.get("custom_spec") else {}
        if "sequence" not in spec:
            continue
        seq = spec["sequence"]
        steps = []
        for predicates in seq["steps"]:
            single = {"event_family": spec["event_family"], "platform": spec["platform"], "predicates": predicates}
            steps.append({**rule, "custom_spec": json.dumps(single)})
        ordered = []
        for event in events:
            if event.get("event_type") != spec["event_family"]:
                continue
            group = event.get(seq["group_by"])
            if not isinstance(group, (str, int)) or isinstance(group, bool) or not str(group):
                continue
            try:
                timestamp = datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00"))
                if timestamp.tzinfo is None:
                    raise ValueError("sequence timestamps require a timezone")
            except (KeyError, TypeError, AttributeError, ValueError) as exc:
                raise ValueError("sequence events need valid timezone-aware timestamps") from exc
            ordered.append((timestamp, str(group), event))
        ordered.sort(key=lambda x: x[0])
        history = {}
        for timestamp, group, event in ordered:
            recent = [t for t in history.get(group, []) if (timestamp - t).total_seconds() <= seq["within_seconds"]]
            if _matches(steps[1], event) and any(t < timestamp for t in recent):
                hits.setdefault(event["event_id"], []).append({"rule_id": rule["id"], "behavior": rule["behavior"]})
            if _matches(steps[0], event):
                recent.append(timestamp)
            history[group] = recent
    return hits


def rule_content_hash(rule):
    """A hash of exactly what was tested (the generated query text), so a
    later edit to the rule is visibly untested until replayed again."""
    return hashlib.sha256(f"{rule.get('sigma','')}|{rule.get('kql','')}|{rule.get('spl','')}".encode()).hexdigest()


SYNTHETIC_MARKERS = ("synthetic", "fixture", "fictional")


def sample_provenance(events_file, events):
    """Classify known fixtures; an arbitrary file path cannot prove the events are real."""
    from importlib import resources
    try:
        fixtures = Path(str(resources.files("threat_research") / "lab_fixtures")).resolve()
        inside = fixtures in Path(events_file).resolve().parents
    except (OSError, ValueError):
        inside = False
    marked = any(event.get("synthetic") is True or any(
        word in str(event.get("scenario", "")).lower() for word in SYNTHETIC_MARKERS) for event in events)
    return "bundled_synthetic_fixture" if inside or marked else "analyst_supplied_origin_unverified"


def test_rule_against_samples(rule_id, events_file, path=None, include_drafts=True, sample_label=None):
    """Reproducible local check: replay one rule's own selection logic
    against analyst-labeled positive/benign JSONL samples (the same
    {event_id, event_type, timestamp, scenario, expected_malicious, ...}
    shape as the synthetic SOC lab), hash exactly what was tested, persist
    the run, and refresh that rule's on-disk repository snapshot.

    This is local reference matching only -- never a claim of SIEM/production
    detection accuracy. Native Splunk/Defender validation remains a separate,
    explicitly configured step (test_draft_in_siem) once a customer connects
    its own SIEM.
    """
    from . import rule_repository
    from .rules import get_rule

    rule = get_rule(rule_id, path)
    if not rule:
        raise ValueError("unknown rule")
    if rule["expires_at"] and rule["expires_at"] <= now():
        raise ValueError("this IOC hunt has expired; refresh its source before testing")
    candidates = [r for r in local_rules(path, include_drafts=include_drafts) if r["id"] == rule_id]
    if not candidates:
        raise ValueError("rule could not be loaded for replay (unsupported behavior, expired, or missing)")
    if events_file == "bundled:needymantis":
        events_file = str(resources.files("threat_research") / "lab_fixtures" /
                          "needymantis_synthetic_file_events.jsonl")
    elif str(events_file).startswith("bundled:"):
        raise ValueError("unknown bundled fixture; available: bundled:needymantis")
    events = list(read_jsonl(events_file))
    if not events:
        raise ValueError("events file has no records")
    result = replay(events, candidates)
    rule_hash = rule_content_hash(rule)
    provenance = sample_provenance(events_file, events)
    rule_repository.record_test_result(rule_id, result, rule_hash, sample_label or str(events_file), path, provenance)
    rule_repository.export_rule(rule_id, path)
    return {**result, "rule_id": rule_id, "rule_hash": rule_hash, "sample_provenance": provenance,
            "scope": "Local reference matching against analyst-labeled samples, not production SIEM accuracy; "
                     "native Splunk/Defender validation remains pending until a customer connects its SIEM."}


def screen_benign_baseline(rule_id, path=None):
    """Read-only sanity screen, never an approval check or a recall measurement."""
    candidates = [r for r in local_rules(path, include_drafts=True) if r["id"] == rule_id]
    if not candidates:
        raise ValueError("unknown or unavailable draft rule")
    file = resources.files("threat_research") / "lab_fixtures" / "benign_baseline.jsonl"
    events = list(read_jsonl(file))
    correlation = _sequence_hits(events, candidates)
    matches = [e["event_id"] for e in events if _matches(candidates[0], e) or e["event_id"] in correlation]
    return {"rule_id": rule_id, "fixture_events": len(events), "benign_matches": len(matches),
            "matching_event_ids": matches, "provenance": "bundled_synthetic_fixture",
            "approval_gate": "does not count", "native_siem_test": "not run",
            "note": "Small fictional benign examples only. Zero matches does not establish a low false-positive rate."}


def watch_jsonl(file, path=None, include_drafts=False, poll_seconds=1.0, from_end=False):
    """Tail an appended local JSONL file and print matches; Ctrl-C stops it.

    A real event shipper must supply an appropriate field mapping and durable
    cursor. This watcher handles truncation/rotation but has only in-memory dedupe.
    """
    file = Path(file)
    offset, inode, seen = 0, None, set()
    if from_end and file.exists():
        offset, inode = file.stat().st_size, file.stat().st_ino
    while True:
        try:
            stat = file.stat()
            if inode is not None and (stat.st_ino != inode or stat.st_size < offset):
                offset, seen = 0, set()
            inode = stat.st_ino
            with file.open("rb") as stream:
                stream.seek(offset)
                while True:
                    raw = stream.readline()
                    if not raw:
                        break
                    if not raw.endswith(b"\n"):
                        break  # Wait for the writer to complete this line.
                    offset = stream.tell()
                    if len(raw) > MAX_EVENT_BYTES:
                        print(json.dumps({"error": "oversized event", "offset": offset}), file=sys.stderr, flush=True)
                        continue
                    try:
                        event = json.loads(raw)
                        ident = event.get("event_id")
                        if ident in seen:
                            continue
                        hits = detect(event, local_rules(path, include_drafts))
                        seen.add(ident)
                        if len(seen) > 10000:
                            seen.clear()
                        for hit in hits:
                            print(json.dumps(hit), flush=True)
                    except (ValueError, TypeError, AttributeError) as exc:
                        print(json.dumps({"error": str(exc)[:160], "offset": offset}), file=sys.stderr, flush=True)
        except FileNotFoundError:
            pass
        time.sleep(max(0.1, poll_seconds))

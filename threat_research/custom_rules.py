"""Analyst-specified detection predicates, compiled only for declared telemetry.

Claude can help the analyst fill the constrained spec. Untrusted article text
cannot submit one on its own; source review and an explicit analyst claim are
recorded before a draft is created.
"""

import hashlib
import json
import re
import uuid
from pathlib import Path
from urllib.parse import urlsplit

from . import rule_repository, store
from .core import get_threat, now

FAMILIES = {"process_creation", "network_connection", "file_event", "image_load", "mcp_audit"}
FIELD = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,63}$")
VALUE = re.compile(r"^[A-Za-z0-9 .:/_\\-]{1,100}$")
OPERATORS = {"equals", "contains", "endswith"}
DEFENDER_FIELDS = {
    "process_creation": {"Image": "FileName", "ParentImage": "InitiatingProcessFileName",
                         "CommandLine": "ProcessCommandLine", "User": "AccountName"},
    "network_connection": {"DestinationIp": "RemoteIP", "DestinationPort": "RemotePort",
                           "DestinationHostname": "RemoteUrl", "Image": "InitiatingProcessFileName"},
    "image_load": {"Image": "InitiatingProcessFileName", "ImageLoaded": "FileName"},
    # Windows file events (Sysmon FileCreate / Defender DeviceFileEvents).
    "file_event": {"TargetFilename": "FolderPath", "Image": "InitiatingProcessFolderPath",
                   "SHA256": "SHA256", "User": "InitiatingProcessAccountName"},
    "mcp_audit": {"event_type": "event_type_s", "execution_status": "execution_status_s",
                  "authorization_decision": "authorization_decision_s", "principal_id": "principal_id_s",
                  "request_id": "request_id_s", "tool_name": "tool_name_s", "resource_scope": "resource_scope_s"},
}


def validate_spec(spec):
    """Permit a small auditable AND of literal comparisons; no query fragments."""
    if not isinstance(spec, dict) or spec.get("event_family") not in FAMILIES:
        raise ValueError("spec needs process_creation, network_connection, file_event, image_load, or mcp_audit event_family")
    if spec.get("platform") not in ("windows", "mcp"):
        raise ValueError("platform must be windows or mcp")
    if (spec["event_family"] == "mcp_audit") != (spec["platform"] == "mcp"):
        raise ValueError("MCP audit needs mcp platform; endpoint telemetry needs windows")
    predicates = spec.get("predicates")
    if not isinstance(predicates, list) or not 2 <= len(predicates) <= 8:
        raise ValueError("provide 2-8 concrete AND predicates")
    normalized, seen = [], set()
    for item in predicates:
        if not isinstance(item, dict) or set(item) != {"field", "operator", "value"}:
            raise ValueError("each predicate needs field, operator, value")
        field, op, value = item["field"], item["operator"], item["value"]
        if (not isinstance(field, str) or not FIELD.fullmatch(field) or op not in OPERATORS
                or not isinstance(value, str) or not VALUE.fullmatch(value) or value != value.strip()):
            raise ValueError("field/operator/value must be bounded literal comparisons, never query syntax")
        if op != "equals" and ("_" in value or "\\" in value):
            raise ValueError("substring values cannot contain wildcard or backslash characters")
        key = (field, op, value.casefold())
        if key in seen:
            raise ValueError("duplicate predicate")
        seen.add(key)
        normalized.append({"field": field, "operator": op, "value": value})
    normalized.sort(key=lambda x: (x["field"], x["operator"], x["value"].casefold()))
    if len({item["field"] for item in normalized}) != len(normalized):
        raise ValueError("one predicate per field is supported; repeated field needs a reviewed correlation rule")
    return {"event_family": spec["event_family"], "platform": spec["platform"], "predicates": normalized}


def fingerprint(spec):
    normalized = validate_spec(spec)
    return hashlib.sha256(("custom:" + json.dumps(normalized, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()


DEFAULT_DESCRIPTION = "Analyst-reviewed behavior hypothesis; validate in target telemetry."


def sigma_extras(sigma):
    """Description and references of a generated rule, to regenerate it for an unchanged-draft check."""
    lines = sigma.splitlines()
    description = next((json.loads(line[len("description: "):]) for line in lines
                        if line.startswith("description: \"")), DEFAULT_DESCRIPTION)
    references = []
    if "references:" in lines:
        for line in lines[lines.index("references:") + 1:]:
            if not line.startswith("  - "):
                break
            references.append(json.loads(line[4:]))
    return {"description": description, "references": tuple(references)}


def _sigma(title, spec, false_positives, description=DEFAULT_DESCRIPTION, references=()):
    # JSON strings/lists are legal YAML flow scalars.
    kind = spec["event_family"]
    category = {"process_creation": "process_creation", "network_connection": "network_connection",
                "file_event": "file_event", "image_load": "image_load", "mcp_audit": "application"}[kind]
    product = "mcp_audit" if kind == "mcp_audit" else "windows"
    lines = [f"title: {json.dumps(title)}", f"id: {uuid.uuid5(uuid.NAMESPACE_URL, fingerprint(spec))}",
             "status: experimental",
             ("description: " + json.dumps(description) if description != DEFAULT_DESCRIPTION else
              "description: " + DEFAULT_DESCRIPTION)]
    if references:
        lines.append("references:")
        lines.extend(f"  - {json.dumps(ref)}" for ref in references)
    lines += ["logsource:", f"  category: {category}", f"  product: {product}", "detection:", "  selection:"]
    suffix = {"equals": "", "contains": "|contains", "endswith": "|endswith"}
    for item in spec["predicates"]:
        lines.append(f"    {json.dumps(item['field'] + suffix[item['operator']])}: {json.dumps(item['value'])}")
    lines.extend(["  condition: selection", "falsepositives:", f"  - {json.dumps(false_positives)}",
                  "level: medium", ""])
    return "\n".join(lines)


def draft(threat_id, source_url, claim, title, rationale, false_positives, spec, path: Path | None = None):
    """Capture cited analyst input and create a review-only Sigma candidate."""
    normalized = validate_spec(spec)
    parsed = urlsplit(source_url) if isinstance(source_url, str) else None
    if (not parsed or parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or len(source_url) > 500):
        raise ValueError("a specific HTTPS research source is required")
    for label, text, minimum, maximum in (("claim", claim, 20, 1000), ("title", title, 8, 150),
                                           ("rationale", rationale, 30, 1000),
                                           ("false_positives", false_positives, 15, 500)):
        if not isinstance(text, str) or not minimum <= len(text.strip()) <= maximum:
            raise ValueError(f"{label} needs a substantive bounded explanation")
    claim, title, rationale, false_positives = (value.strip() for value in
                                                (claim, title, rationale, false_positives))
    threat = get_threat(threat_id, path)
    if not threat:
        raise ValueError("unknown threat; collect or register a sourced report first")
    if threat["kind"] == "leak_claim" and parsed.hostname in ("ransomlook.io", "www.ransomlook.io"):
        raise ValueError("leak claim alone does not document technical behavior")
    fp = fingerprint(normalized)
    rule_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "threat-research:" + fp))
    sigma = _sigma(title, normalized, false_positives)
    templates = generic_queries(normalized)
    store.initialize(path)
    with store.connection(path) as db:
        db.execute("INSERT OR IGNORE INTO evidence (threat_id,source_url,claim,kind,behavior,observed_at) VALUES (?,?,?,?,?,?)",
                   (threat_id.upper(), source_url, claim, "analyst_observation", "custom", now()))
        evidence = db.execute("SELECT id,behavior FROM evidence WHERE threat_id=? AND source_url=? AND claim=? AND kind='analyst_observation'",
                              (threat_id.upper(), source_url, claim)).fetchone()
        if evidence["behavior"] != "custom":
            raise ValueError("observation is already bound to a fixed behavior")
        previous = db.execute("SELECT fingerprint FROM custom_rule_observations WHERE evidence_id=?", (evidence["id"],)).fetchone()
        if previous and previous["fingerprint"] != fp:
            raise ValueError("this observation is already bound to a different behavior spec")
        db.execute("INSERT OR IGNORE INTO custom_rule_observations VALUES (?,?)", (evidence["id"], fp))
        existing = db.execute("SELECT id,status,pattern_score FROM rules WHERE fingerprint=?", (fp,)).fetchone()
        if existing:
            return {"status": "existing_coverage", "rule_id": existing["id"], "evidence_id": evidence["id"],
                    "pattern_score": existing["pattern_score"], "note": "Compare actual deployed logic before claiming equivalent coverage."}
        external = db.execute("SELECT id,title,source_url,pattern_score FROM external_inventory WHERE fingerprint=?", (fp,)).fetchone()
        if external:
            return {"status": "existing_external_coverage", "rule_id": external["id"], "evidence_id": evidence["id"],
                    "pattern_score": external["pattern_score"], "source": external["source_url"]}
        db.execute("INSERT INTO rules (id,threat_id,behavior,fingerprint,title,sigma,kql,spl,telemetry,rationale,status,created_at) "
                   "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                   (rule_id, threat_id.upper(), "custom", fp, title, sigma,
                    templates["kql"], templates["spl"],
                    normalized["event_family"] + " / " + normalized["platform"], rationale, "draft", now()))
        db.execute("INSERT INTO custom_rule_specs VALUES (?,?)", (rule_id, json.dumps(normalized, sort_keys=True)))
        db.execute("INSERT INTO rule_evidence VALUES (?,?)", (rule_id, evidence["id"]))
        db.execute("INSERT INTO audit(at,action,target,detail) VALUES (?,?,?,?)",
                   (now(), "custom_rule_drafted", rule_id, json.dumps({"source": source_url, "evidence_id": evidence["id"]})))
    rule_repository.export_rule(rule_id, path)
    return {"status": "draft", "rule_id": rule_id, "evidence_id": evidence["id"], "sigma": sigma,
            "required_fields": sorted({item["field"] for item in normalized["predicates"]}),
            "generic_queries": templates,
            "next_step": "Check client field mapping, inventory and benign/positive events before approval or deployment."}


def get_spec(rule_id, path=None):
    with store.connection(path) as db:
        row = db.execute("SELECT spec FROM custom_rule_specs WHERE rule_id=?", (rule_id,)).fetchone()
    return json.loads(row["spec"]) if row else None


def _query(spec, config, siem):
    mapping = config.get("field_map", {})
    if siem == "defender":
        mapping = {**DEFENDER_FIELDS[spec["event_family"]], **mapping}
    fields = config["fields"]
    resolved = []
    missing = []
    for item in spec["predicates"]:
        target = mapping.get(item["field"], item["field"])
        if not isinstance(target, str) or not FIELD.fullmatch(target) or target not in fields:
            missing.append(item["field"])
        else:
            resolved.append((target, item["operator"], item["value"].lower()))
    if missing:
        return None, sorted(set(missing))
    if siem == "splunk":
        # Backslash and wildcard are excluded for substring values by validation.
        conditions = []
        for field, op, value in resolved:
            if op == "equals":
                conditions.append(f'lower({field})={json.dumps(value)}')
            else:
                pattern = "%" + value + ("%" if op == "contains" else "")
                conditions.append(f'like(lower({field}),{json.dumps(pattern)})')
        query = f"index={config['index']} sourcetype={config['sourcetype']}\n| where " + " AND ".join(conditions)
    else:
        conditions = []
        for field, op, value in resolved:
            escaped = value.replace("'", "''")
            operator = {"equals": "==", "contains": "contains", "endswith": "endswith"}[op]
            conditions.append(f"tolower(tostring({field})) {operator} '{escaped}'")
        query = config["table"] + "\n| where " + " and ".join(conditions)
    return query, []


def generic_queries(spec):
    """Portable query templates over canonical fields, never native SIEM validation.

    The table/index and field names must be mapped to actual telemetry before
    running. Reuse the bounded predicate compiler so both dialects express the
    same rule, including escaping and case normalization.
    """
    normalized = validate_spec(spec)
    fields = [item["field"] for item in normalized["predicates"]]
    kql, _ = _query(normalized, {"table": "YOUR_EVENT_TABLE", "fields": fields, "field_map": {}}, "template")
    spl, _ = _query(normalized, {"index": "YOUR_INDEX", "sourcetype": "YOUR_SOURCETYPE",
                                  "fields": fields, "field_map": {}}, "splunk")
    return {"kql": kql, "spl": spl, "field_names": fields,
            "requires_mapping": ["Replace the event table or index/sourcetype with the actual source.",
                                 "Map each canonical field to a field present in that source.",
                                 "Check syntax and sample events in the target SIEM before use."],
            "validation": "Generic templates only; no SIEM has executed these queries."}


def fit(rule_id, path=None):
    spec = get_spec(rule_id, path)
    if not spec:
        raise ValueError("custom rule spec missing")
    with store.connection(path) as db:
        row = db.execute("SELECT profile FROM environment_config WHERE id=1").fetchone()
    if not row:
        return {"ready": False, "rule_id": rule_id, "reason": "client must configure telemetry fields; portable Sigma draft is available"}
    profile = json.loads(row["profile"])
    config = profile["telemetry"].get(spec["event_family"])
    if not config:
        return {"ready": False, "rule_id": rule_id, "reason": "required telemetry family not configured",
                "family": spec["event_family"]}
    if profile["siem"] == "generic":
        missing = sorted({item["field"] for item in spec["predicates"]} - set(config["field_map"]))
        return {"ready": not missing, "rule_id": rule_id, "siem": "generic", "missing_canonical_fields": missing,
                "field_map": config["field_map"], "source": config["source"], "mapped_query": None,
                "validation": "Sigma field mapping only; choose a backend and test against client events."}
    query, missing = _query(spec, config, profile["siem"])
    return {"ready": not missing, "rule_id": rule_id, "siem": profile["siem"],
            "missing_fields": missing, "mapped_query": query,
            "validation": "Generated from bounded literal predicates; requires native syntax and sample-event testing."}

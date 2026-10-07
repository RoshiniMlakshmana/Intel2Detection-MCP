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

FAMILIES = {"process_creation", "network_connection", "file_event", "image_load",
            "web_access", "proxy", "mcp_audit"}
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
    "web_access": {}, "proxy": {},
    "mcp_audit": {"event_type": "event_type_s", "execution_status": "execution_status_s",
                  "authorization_decision": "authorization_decision_s", "principal_id": "principal_id_s",
                  "request_id": "request_id_s", "tool_name": "tool_name_s", "resource_scope": "resource_scope_s"},
}


def _predicates(items, label, minimum, maximum):
    if not isinstance(items, list) or not minimum <= len(items) <= maximum:
        raise ValueError(f"{label} needs {minimum}-{maximum} bounded literal predicates")
    normalized, seen = [], set()
    for item in items:
        if not isinstance(item, dict) or set(item) - {"field", "operator", "value", "case_sensitive"} or not {"field", "operator", "value"} <= set(item):
            raise ValueError("each predicate needs field, operator, value")
        if "case_sensitive" in item and not isinstance(item["case_sensitive"], bool):
            raise ValueError("case_sensitive must be boolean")
        field, op, value = item["field"], item["operator"], item["value"]
        if (not isinstance(field, str) or not FIELD.fullmatch(field) or op not in OPERATORS
                or not isinstance(value, str) or not VALUE.fullmatch(value) or value != value.strip()):
            raise ValueError("field/operator/value must be bounded literal comparisons, never query syntax")
        if op != "equals" and "\\" in value:
            raise ValueError("substring values cannot contain wildcard or backslash characters")
        if field == "Signed" and (op != "equals" or value.lower() not in ("true", "false")):
            raise ValueError("Signed must be an exact true or false value")
        key = (field, op, value if item.get("case_sensitive") else value.casefold(), item.get("case_sensitive", False))
        if key in seen:
            raise ValueError("duplicate predicate")
        seen.add(key)
        normalized.append({"field": field, "operator": op, "value": value})
        if item.get("case_sensitive"):
            normalized[-1]["case_sensitive"] = True
    return sorted(normalized, key=lambda x: (x["field"], x["operator"], x["value"].casefold(),
                                            x.get("case_sensitive", False), x["value"]))


def all_predicates(spec):
    """All literal values whose field mapping and citation must be checked."""
    if "sequence" in spec:
        return [p for step in spec["sequence"]["steps"] for p in step]
    return spec["predicates"] + spec.get("any_of", []) + spec.get("exclude", [])


def required_fields(spec):
    fields = {p["field"] for p in all_predicates(spec)}
    if "sequence" in spec:
        fields.update((spec["sequence"]["group_by"], "Timestamp"))
    return sorted(fields)


def validate_spec(spec):
    """A bounded AND with optional OR and exclusions; no query fragments."""
    if not isinstance(spec, dict) or spec.get("event_family") not in FAMILIES:
        raise ValueError("unsupported event_family")
    if spec.get("platform") not in ("windows", "linux", "mcp"):
        raise ValueError("platform must be windows, linux or mcp")
    if (spec["event_family"] == "mcp_audit") != (spec["platform"] == "mcp"):
        raise ValueError("MCP audit needs mcp platform; endpoint telemetry needs windows or linux")
    if "sequence" in spec:
        if set(spec) != {"event_family", "platform", "sequence"} or spec["event_family"] == "mcp_audit":
            raise ValueError("unsupported spec key: sequence needs one endpoint event family and no other top-level filters")
        seq = spec["sequence"]
        if not isinstance(seq, dict) or set(seq) != {"group_by", "within_seconds", "steps"}:
            raise ValueError("sequence needs group_by, within_seconds and exactly two steps")
        group, seconds, steps = seq["group_by"], seq["within_seconds"], seq["steps"]
        if not isinstance(group, str) or not FIELD.fullmatch(group) or not isinstance(seconds, int) or isinstance(seconds, bool) or not 1 <= seconds <= 3600:
            raise ValueError("sequence needs a canonical group field and a 1-3600 second window")
        if not isinstance(steps, list) or len(steps) != 2:
            raise ValueError("sequence needs exactly two ordered event steps")
        normalized_steps = [_predicates(step, "sequence step", 2, 4) for step in steps]
        return {"event_family": spec["event_family"], "platform": spec["platform"],
                "sequence": {"group_by": group, "within_seconds": seconds, "steps": normalized_steps}}
    if set(spec) - {"event_family", "platform", "predicates", "any_of", "exclude"}:
        raise ValueError("unsupported spec key; event sequence correlation needs a separate reviewed rule")
    normalized = {"event_family": spec["event_family"], "platform": spec["platform"],
                  "predicates": _predicates(spec.get("predicates"), "predicates", 1, 8)}
    for key in ("any_of", "exclude"):
        if key in spec:
            normalized[key] = _predicates(spec[key], key, 1, 8)
    if not 2 <= len(all_predicates(normalized)) <= 12:
        only = normalized["predicates"]
        if not (len(all_predicates(normalized)) == 1 and spec["event_family"] == "file_event"
                and only[0]["field"] == "SHA256" and only[0]["operator"] == "equals"
                and re.fullmatch(r"[a-fA-F0-9]{64}", only[0]["value"])):
            raise ValueError("provide 2-12 bounded conditions, or one exact file SHA-256")
    return normalized


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
                "file_event": "file_event", "image_load": "image_load", "web_access": "webserver",
                "proxy": "proxy", "mcp_audit": "application"}[kind]
    product = "mcp_audit" if kind == "mcp_audit" else spec["platform"]
    if "sequence" in spec:
        # Sigma temporal_ordered correlations reference two base rules. Their
        # names and IDs are derived from the normalized spec, never source text.
        bases = []
        names = []
        for index, predicates in enumerate(spec["sequence"]["steps"], 1):
            base_spec = {"event_family": kind, "platform": spec["platform"], "predicates": predicates}
            name = f"step_{fingerprint(spec)[:12]}_{index}"
            names.append(name)
            base = _sigma(f"{title} - {name}", base_spec, false_positives, description, references)
            base = re.sub(r"^(status|level):.*\n", "", base, flags=re.M)
            bases.append(base.replace("logsource:\n", f"name: {name}\nlogsource:\n", 1).rstrip())
        group = spec["sequence"]["group_by"]
        seconds = spec["sequence"]["within_seconds"]
        correlation = [f"title: {json.dumps(title)}",
                       f"id: {uuid.uuid5(uuid.NAMESPACE_URL, fingerprint(spec))}", "status: experimental",
                       "correlation:", "  type: temporal_ordered", "  rules:",
                       *[f"    - {name}" for name in names], "  group-by:", f"    - {group}",
                       f"  timespan: {seconds}s", "  condition:", "    gte: 2",
                       "description: " + json.dumps(description),
                       *(["references:"] + [f"  - {json.dumps(ref)}" for ref in references] if references else []),
                       "falsepositives:", f"  - {json.dumps(false_positives)}",
                       "level: medium"]
        return "\n---\n".join(bases + ["\n".join(correlation)]) + "\n"
    lines = [f"title: {json.dumps(title)}", f"id: {uuid.uuid5(uuid.NAMESPACE_URL, fingerprint(spec))}",
             "status: experimental",
             ("description: " + json.dumps(description) if description != DEFAULT_DESCRIPTION else
              "description: " + DEFAULT_DESCRIPTION)]
    if references:
        lines.append("references:")
        lines.extend(f"  - {json.dumps(ref)}" for ref in references)
    lines += ["logsource:", f"  category: {category}", f"  product: {product}", "detection:"]
    suffix = {"equals": "", "contains": "|contains", "endswith": "|endswith"}
    def key(item):
        return item["field"] + suffix[item["operator"]] + ("|cased" if item.get("case_sensitive") else "")
    if not spec.get("any_of") and not spec.get("exclude") and len({key(p)
                                                                      for p in spec["predicates"]}) == len(spec["predicates"]):
        lines.append("  selection:")
        for item in spec["predicates"]:
            scalar = item["value"].lower() if item["field"] == "Signed" else json.dumps(item["value"])
            lines.append(f"    {json.dumps(key(item))}: {scalar}")
        condition = "selection"
    else:
        groups = [(f"selection_{i}", p) for i, p in enumerate(spec["predicates"], 1)]
        groups += [(f"alternative_{i}", p) for i, p in enumerate(spec.get("any_of", []), 1)]
        groups += [(f"filter_{i}", p) for i, p in enumerate(spec.get("exclude", []), 1)]
        for name, item in groups:
            scalar = item["value"].lower() if item["field"] == "Signed" else json.dumps(item["value"])
            lines += [f"  {name}:", f"    {json.dumps(key(item))}: {scalar}"]
        condition = " and ".join(n for n, _ in groups if n.startswith("selection_"))
        if spec.get("any_of"):
            condition += " and 1 of alternative_*"
        if spec.get("exclude"):
            condition += " and not 1 of filter_*"
    lines.extend([f"  condition: {condition}", "falsepositives:", f"  - {json.dumps(false_positives)}",
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
            return {"status": "existing_draft" if existing["status"] == "draft" else "existing_coverage",
                    "rule_id": existing["id"], "evidence_id": evidence["id"],
                    "pattern_score": existing["pattern_score"],
                    "note": "An existing draft is not coverage; compare approved or deployed logic separately."}
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
            "required_fields": required_fields(normalized),
            "generic_queries": templates,
            "next_step": "Check client field mapping, inventory and benign/positive events before approval or deployment."}


def get_spec(rule_id, path=None):
    with store.connection(path) as db:
        row = db.execute("SELECT spec FROM custom_rule_specs WHERE rule_id=?", (rule_id,)).fetchone()
    return json.loads(row["spec"]) if row else None


def _query(spec, config, siem):
    if "sequence" in spec:
        return _sequence_query(spec, config, siem)
    mapping = config.get("field_map", {})
    if siem == "defender":
        mapping = {**DEFENDER_FIELDS[spec["event_family"]], **mapping}
    fields = config["fields"]
    resolved = []
    missing = []
    for item in all_predicates(spec):
        target = mapping.get(item["field"], item["field"])
        if not isinstance(target, str) or not FIELD.fullmatch(target) or target not in fields:
            missing.append(item["field"])
        else:
            cased = item.get("case_sensitive", False)
            resolved.append((target, item["operator"], item["value"] if cased else item["value"].lower(), cased))
    if missing:
        return None, sorted(set(missing))
    if siem == "splunk":
        # LIKE treats underscore as a one-character wildcard. A literal
        # underscore instead uses match() with an escaped regex.
        conditions = []
        for field, op, value, cased in resolved:
            field = field if cased else f"lower({field})"
            if op == "equals":
                conditions.append(f'{field}={json.dumps(value)}')
            elif "_" in value:
                regex = re.escape(value) + ("$" if op == "endswith" else "")
                conditions.append(f'match({field},{json.dumps(regex)})')
            else:
                pattern = "%" + value + ("%" if op == "contains" else "")
                conditions.append(f'like({field},{json.dumps(pattern)})')
        prefix = f"index={config['index']} sourcetype={config['sourcetype']}\n| where "
    else:
        conditions = []
        for field, op, value, cased in resolved:
            escaped = value.replace("'", "''")
            operator = {"equals": "==", "contains": "contains", "endswith": "endswith"}[op]
            if cased and op != "equals":
                operator += "_cs"
            expr = f"tostring({field})" if cased else f"tolower(tostring({field}))"
            conditions.append(f"{expr} {operator} '{escaped}'")
        prefix = config["table"] + "\n| where "
    required = conditions[:len(spec["predicates"])]
    alternatives = conditions[len(required):len(required) + len(spec.get("any_of", []))]
    exclusions = conditions[len(required) + len(alternatives):]
    join = " AND " if siem == "splunk" else " and "
    condition = join.join(f"({c})" for c in required)
    if alternatives:
        condition += join + "(" + (" OR " if siem == "splunk" else " or ").join(f"({c})" for c in alternatives) + ")"
    if exclusions:
        condition += join + "not (" + (" OR " if siem == "splunk" else " or ").join(f"({c})" for c in exclusions) + ")"
    query = prefix + condition
    return query, []


def _sequence_query(spec, config, siem):
    seq = spec["sequence"]
    mapping = config.get("field_map", {})
    group = mapping.get(seq["group_by"], seq["group_by"])
    timestamp = mapping.get("Timestamp", "_time" if siem == "splunk" else "Timestamp")
    missing = [canonical for canonical, field in ((seq["group_by"], group), ("Timestamp", timestamp))
               if not FIELD.fullmatch(field) or field not in config["fields"]]
    queries = []
    for predicates in seq["steps"]:
        query, absent = _query({"event_family": spec["event_family"], "platform": spec["platform"],
                               "predicates": predicates}, config, siem)
        queries.append(query)
        missing.extend(absent)
    if missing:
        return None, sorted(set(missing))
    seconds = seq["within_seconds"]
    if siem == "splunk":
        first = queries[0] + f'\n| where isnotnull({group}) AND len(tostring({group}))>0\n| eval correlation_key=tostring({group}), first_time={timestamp}\n| fields correlation_key first_time'
        second = queries[1] + f'\n| where isnotnull({group}) AND len(tostring({group}))>0\n| eval correlation_key=tostring({group}), second_time={timestamp}\n| fields correlation_key second_time'
        return (first + '\n| join type=inner max=0 correlation_key [ search ' + second + ' ]' +
                f'\n| where second_time>first_time AND second_time-first_time<={seconds}', [])
    def stage(query, alias):
        return query + f'\n| where isnotempty(tostring({group}))\n| project correlation_key=tostring({group}), {alias}=todatetime({timestamp})'
    return ('let first = ' + stage(queries[0], 'first_time') + ';\nlet second = ' +
            stage(queries[1], 'second_time') + ';\nfirst\n| join kind=inner (second) on correlation_key' +
            f'\n| where second_time > first_time and second_time <= first_time + {seconds}s', [])


def generic_queries(spec):
    """Portable query templates over canonical fields, never native SIEM validation.

    The table/index and field names must be mapped to actual telemetry before
    running. Reuse the bounded predicate compiler so both dialects express the
    same rule, including escaping and case normalization.
    """
    normalized = validate_spec(spec)
    fields = required_fields(normalized)
    kql, _ = _query(normalized, {"table": "YOUR_EVENT_TABLE", "fields": fields, "field_map": {}}, "template")
    spl, _ = _query(normalized, {"index": "YOUR_INDEX", "sourcetype": "YOUR_SOURCETYPE",
                                  "fields": fields, "field_map": {"Timestamp": "Timestamp"}}, "splunk")
    return {"kql": kql, "spl": spl, "field_names": fields,
            "requires_mapping": ["Replace the event table or index/sourcetype with the actual source.",
                                 "Map each canonical field to a field present in that source.",
                                 "Check syntax and sample events in the target SIEM before use."],
            "validation": "Generic templates only; no SIEM has executed these queries.",
            "limitations": (["Splunk join subsearch limits can truncate correlation results; configure limits and validate native behavior.",
                              "Exactly two strictly ordered events in one family with the same nonempty grouping value."]
                             if "sequence" in normalized else [])}


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
        missing = sorted(set(required_fields(spec)) - set(config["field_map"]))
        return {"ready": not missing, "rule_id": rule_id, "siem": "generic", "missing_canonical_fields": missing,
                "field_map": config["field_map"], "source": config["source"], "mapped_query": None,
                "validation": "Sigma field mapping only; choose a backend and test against client events."}
    query, missing = _query(spec, config, profile["siem"])
    return {"ready": not missing, "rule_id": rule_id, "siem": profile["siem"],
            "missing_fields": missing, "mapped_query": query,
            "validation": "Generated from bounded literal predicates; requires native syntax and sample-event testing.",
            "limitations": generic_queries(spec)["limitations"]}

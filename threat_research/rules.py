"""Two narrow, reviewable behavior templates. CVE text alone cannot select one."""

import hashlib
import ipaddress
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import rule_repository, store
from .core import get_threat, now

# How long an analyst's "this is our complete rule inventory" declaration
# stays usable for a 'no' answer before it must be treated as unknown again.
INVENTORY_DECLARATION_TTL_DAYS = 30


TEMPLATES = {
    "web_server_shell": {
        "title": "Web Service Spawns a Shell",
        "telemetry": "Sysmon Event ID 1 / DeviceProcessEvents / Splunk Sysmon process creation; Sigma/SPL Windows only",
        "rationale": "A web server process launching a command shell can indicate post-exploitation; deployments and maintenance can also cause this. Investigate parent lineage, account, command line, and change window.",
        "sigma_selection": {
            "ParentImage|endswith": ["\\w3wp.exe", "\\httpd.exe", "\\nginx.exe"],
            "Image|endswith": ["\\cmd.exe", "\\powershell.exe"],
        },
        "kql": "DeviceProcessEvents\n| where InitiatingProcessFileName in~ ('w3wp.exe','httpd.exe','nginx.exe','apache2')\n| where FileName in~ ('cmd.exe','powershell.exe','sh','bash')\n| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine",
        "spl": "index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1\n| eval parent=lower(ParentImage), child=lower(Image)\n| where match(parent, \"(?i)(w3wp|httpd|nginx|apache2)(\\\\.exe)?$\") AND match(child, \"(?i)(cmd|powershell|sh|bash)(\\\\.exe)?$\")\n| table _time host User ParentImage Image CommandLine ParentCommandLine",
    },
    "encoded_powershell": {
        "title": "PowerShell Encoded Command Execution",
        "telemetry": "Sysmon Event ID 1 / DeviceProcessEvents / Splunk Sysmon process creation with command line",
        "rationale": "Encoded PowerShell commands can hide script content. Legitimate administration may also use encoding; review decoded content, signer, ancestry, and user context.",
        "sigma_selection": {
            "Image|endswith": ["\\powershell.exe", "\\pwsh.exe"],
            "CommandLine|contains": [" -enc ", " -encodedcommand ", " -e "],
        },
        "kql": "DeviceProcessEvents\n| where FileName in~ ('powershell.exe','pwsh.exe')\n| where ProcessCommandLine matches regex @'(?i)\\s-(enc|encodedcommand|e)\\s+'\n| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine",
        "spl": "index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=1\n| where match(lower(Image), \"(?i)(powershell|pwsh)\\\\.exe$\") AND match(lower(CommandLine), \"(?i)\\\\s-(enc|encodedcommand|e)\\\\s+\")\n| table _time host User ParentImage Image CommandLine ParentCommandLine",
    },
    "mcp_unauthorized_execution": {
        "title": "MCP Tool Executed Without Allow Decision",
        "telemetry": "Custom MCP audit contract: event_type, execution_status, authorization_decision, principal_id, request_id, tool_name, resource_scope, timestamp",
        "rationale": "A tool marked executed despite a non-allow authorization decision is a policy-state mismatch. Investigate request binding, delayed decisions, log completeness, and idempotent retries; this alert alone does not prove compromise.",
        "sigma_selection": {
            "event_type": "tool_invocation",
            "execution_status": "executed",
            "authorization_decision": ["deny", "missing", "expired"],
        },
        "kql": "MCPAudit_CL\n| where event_type_s == 'tool_invocation' and execution_status_s == 'executed'\n| where authorization_decision_s in ('deny','missing','expired')\n| project TimeGenerated, principal_id_s, request_id_s, tool_name_s, resource_scope_s, authorization_decision_s, execution_status_s",
        "spl": "index=ai_security sourcetype=mcp:audit event_type=tool_invocation execution_status=executed authorization_decision IN (deny,missing,expired)\n| table _time principal_id request_id tool_name resource_scope authorization_decision execution_status",
    },
}


def fingerprint_for(behavior):
    if behavior not in TEMPLATES:
        raise ValueError("unsupported behavior")
    return hashlib.sha256(f"{behavior}:{TEMPLATES[behavior]['telemetry']}".encode()).hexdigest()


def ioc_fingerprint(indicator):
    try:
        ip, port_raw = indicator.rsplit(":", 1)
        address, port = ipaddress.ip_address(ip), int(port_raw)
        if not address.is_global or not 1 <= port <= 65535:
            raise ValueError("not a public IP:port")
    except (AttributeError, TypeError) as exc:
        raise ValueError("invalid IP:port") from exc
    return hashlib.sha256(f"ioc_network:{address}:{port}:destination".encode()).hexdigest()


def validate_inventory(items):
    """Validate the full inventory before any environment state is changed."""
    if not isinstance(items, list) or len(items) > 1000:
        raise ValueError("inventory must be a list of at most 1000 mapped rules")
    normalized = []
    ids, fingerprints = set(), set()
    for item in items:
        if not isinstance(item, dict) or item.get("behavior") not in (*TEMPLATES, "ioc_network", "custom"):
            raise ValueError("each rule needs a supported analyst-mapped behavior")
        if not all(isinstance(item.get(k), str) and item[k].strip() and len(item[k]) <= 500 for k in ("id", "title", "source_url")):
            raise ValueError("id, title, and source_url are required")
        if not item["source_url"].startswith("https://"):
            raise ValueError("inventory source must be HTTPS")
        if item["behavior"] == "custom":
            from . import custom_rules
            fingerprint = custom_rules.fingerprint(item.get("spec"))
        else:
            fingerprint = (ioc_fingerprint(item.get("indicator")) if item["behavior"] == "ioc_network"
                           else fingerprint_for(item["behavior"]))
        if item["id"] in ids or fingerprint in fingerprints:
            raise ValueError("inventory has duplicate IDs or mapped behavior fingerprints")
        ids.add(item["id"])
        fingerprints.add(fingerprint)
        normalized.append((item["id"], item["title"], item["behavior"], fingerprint, item["source_url"]))
    return normalized


def import_inventory(items, path: Path | None = None):
    """Import analyst-mapped rule metadata; do not claim arbitrary query equivalence."""
    normalized = validate_inventory(items)
    store.initialize(path)
    with store.connection(path) as db:
        for item in normalized:
            db.execute("INSERT INTO external_inventory (id,title,behavior,fingerprint,source_url) VALUES (?,?,?,?,?) "
                       "ON CONFLICT(id) DO UPDATE SET title=excluded.title,behavior=excluded.behavior,"
                       "fingerprint=excluded.fingerprint,source_url=excluded.source_url,"
                       "pattern_score=CASE WHEN external_inventory.fingerprint=excluded.fingerprint "
                       "THEN external_inventory.pattern_score ELSE 0 END,"
                       "evidence_ids=CASE WHEN external_inventory.fingerprint=excluded.fingerprint "
                       "THEN external_inventory.evidence_ids ELSE '[]' END",
                       item)
    return {"imported": len(normalized), "note": "Behavior mapping is analyst supplied; syntax and semantic equivalence were not inferred."}


def _sigma(title, behavior):
    selection = TEMPLATES[behavior]["sigma_selection"]
    # JSON scalars/arrays are legal YAML flow values and escape titles safely.
    lines = [
        f"title: {json.dumps(title)}", f"id: {uuid.uuid5(uuid.NAMESPACE_URL, 'threat-research:' + behavior)}",
        "status: experimental", "description: Behavior hypothesis; investigate correlated evidence before alerting.",
        "logsource:",
        "  category: application" if behavior == "mcp_unauthorized_execution" else "  category: process_creation",
        "  product: mcp_audit" if behavior == "mcp_unauthorized_execution" else "  product: windows",
        "detection:", "  selection:",
    ]
    for key, value in selection.items():
        lines.append(f"    {json.dumps(key)}: {json.dumps(value)}")
    lines.extend(["  condition: selection", "falsepositives:", "  - Authorized administration or application maintenance", "level: medium"])
    return "\n".join(lines) + "\n"


def propose_ioc_detection(ident, path: Path | None = None):
    """Short-lived C2 endpoint hunt from a fresh, high-confidence source assertion."""
    ident = ident.upper()
    threat = get_threat(ident, path)
    if not threat or threat["kind"] != "ioc" or threat["indicator_type"] != "ip:port":
        raise ValueError("a sourced IP:port IOC is required")
    if (threat["confidence"] or 0) < 75 or not threat["expires_at"] or threat["expires_at"] <= now():
        raise ValueError("IOC is low confidence or expired; refresh the source before drafting")
    try:
        ip, port_raw = threat["indicator"].rsplit(":", 1)
        address = ipaddress.ip_address(ip)
        port = int(port_raw)
        if not address.is_global or not 1 <= port <= 65535:
            raise ValueError("not a public IP:port")
    except (AttributeError, TypeError) as exc:
        raise ValueError("invalid IP:port") from exc
    evidence = next((e for e in threat["evidence"] if e["kind"] == "source_fact" and e["source_url"].startswith("https://threatfox.abuse.ch/")), None)
    if evidence is None:
        raise ValueError("current ThreatFox source evidence is required")
    fp = ioc_fingerprint(threat["indicator"])
    rule_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"threat-research:{fp}"))
    title = f"Recent ThreatFox C2 Connection to {address}:{port}"
    sigma = "\n".join([
        f"title: {json.dumps(title)}", f"id: {rule_id}", "status: experimental",
        f"description: {json.dumps('Expiring IOC hunt. Revalidate after ' + threat['expires_at'] + '.')}",
        "logsource:", "  category: network_connection", "  product: windows",
        "detection:", "  selection:", f"    DestinationIp: {json.dumps(str(address))}",
        f"    DestinationPort: {port}", "  condition: selection",
        "falsepositives:", "  - Shared or reassigned hosting; verify current destination ownership and process context",
        "level: medium", "",
    ])
    kql = ("DeviceNetworkEvents\n"
           f"| where RemoteIP == '{address}' and RemotePort == {port}\n"
           "| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, ActionType")
    spl = ("index=endpoint sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=3 "
           f"DestinationIp={address} DestinationPort={port}\n"
           "| table _time host Image User DestinationIp DestinationPort Initiated")
    telemetry = "Sysmon Event ID 3 / Defender DeviceNetworkEvents / Splunk Sysmon network events; Windows endpoint"
    rationale = (f"A recent ThreatFox botnet C2 listing links this endpoint to {threat['summary'][:180]} "
                 "Investigate the initiating process and asset; IPs can be reassigned. This is an IOC hunt, not proof of compromise.")
    with store.connection(path) as db:
        existing = db.execute("SELECT id,status FROM rules WHERE fingerprint=?", (fp,)).fetchone()
        if existing:
            return {"status": "existing_coverage", "rule_id": existing["id"], "message": "Existing IOC hunt; no duplicate drafted."}
        external = db.execute("SELECT id,title,source_url,pattern_score FROM external_inventory WHERE fingerprint=?", (fp,)).fetchone()
        if external:
            return {"status": "existing_external_coverage", "rule_id": external["id"],
                    "title": external["title"], "source": external["source_url"],
                    "pattern_score": external["pattern_score"]}
        db.execute("""INSERT INTO rules
            (id,threat_id,behavior,fingerprint,title,sigma,kql,spl,telemetry,rationale,status,created_at,expires_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (rule_id, ident, "ioc_network", fp, title, sigma, kql, spl, telemetry, rationale, "draft", now(), threat["expires_at"]))
        db.execute("INSERT INTO rule_evidence(rule_id,evidence_id) VALUES (?,?)", (rule_id, evidence["id"]))
        db.execute("INSERT INTO audit(at,action,target,detail) VALUES (?,?,?,?)",
                   (now(), "ioc_rule_drafted", rule_id, json.dumps({"source": evidence["source_url"]})))
    rule_repository.export_rule(rule_id, path)
    return {"status": "draft", "rule_id": rule_id, "expires_at": threat["expires_at"], "source": evidence["source_url"]}


def propose_rule(ident, evidence_id, path: Path | None = None):
    threat = get_threat(ident, path)
    if not threat:
        raise ValueError("unknown threat")
    evidence = next((e for e in threat["evidence"] if e["id"] == evidence_id and e["kind"] == "analyst_observation"), None)
    if evidence is None or evidence["behavior"] not in TEMPLATES:
        raise ValueError("a cited analyst observation with a supported behavior is required")
    behavior = evidence["behavior"]
    fingerprint = fingerprint_for(behavior)
    rule_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"threat-research:{ident.upper()}:{behavior}"))
    title = TEMPLATES[behavior]["title"]
    with store.connection(path) as db:
        # Matching behavior and log source is already covered, even for another CVE.
        existing = db.execute("SELECT id,status,pattern_score FROM rules WHERE fingerprint=?", (fingerprint,)).fetchone()
        if existing:
            return {"status": "existing_coverage", "rule_id": existing["id"], "pattern_score": existing["pattern_score"], "message": "Review coverage and attach new evidence; no duplicate rule drafted."}
        external = db.execute("SELECT id,title,source_url,pattern_score FROM external_inventory WHERE fingerprint=?", (fingerprint,)).fetchone()
        if external:
            return {"status": "existing_external_coverage", "rule_id": external["id"],
                    "title": external["title"], "source": external["source_url"],
                    "pattern_score": external["pattern_score"],
                    "message": "Mapped inventory coverage exists; inspect the actual query before deciding it is equivalent."}
        body = TEMPLATES[behavior]
        db.execute("""INSERT INTO rules
            (id,threat_id,behavior,fingerprint,title,sigma,kql,spl,telemetry,rationale,status,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (rule_id, ident.upper(), behavior, fingerprint, title, _sigma(title, behavior),
             body["kql"], body["spl"], body["telemetry"], body["rationale"], "draft", now()))
        db.execute("INSERT INTO rule_evidence(rule_id,evidence_id) VALUES (?,?)", (rule_id, evidence_id))
        db.execute("INSERT INTO audit (at,action,target,detail) VALUES (?,?,?,?)",
                   (now(), "rule_drafted", rule_id, json.dumps({"evidence_id": evidence_id})))
    rule_repository.export_rule(rule_id, path)
    return {"status": "draft", "rule_id": rule_id, "title": title, "telemetry": body["telemetry"], "source": evidence["source_url"]}


def declare_inventory_scope(scope, complete, path: Path | None = None):
    """Analyst explicitly asserts what was checked and whether it is their
    complete existing-rule inventory as of now. Only this declaration, while
    it stays recent, allows inventory_status to ever answer 'no' instead of
    'unknown'. Importing rows with import_inventory does not by itself imply
    completeness -- a partial import must not silently unlock a 'no' answer.
    """
    if not isinstance(scope, str) or not 10 <= len(scope.strip()) <= 500:
        raise ValueError("scope needs a specific description of what was checked (10-500 characters)")
    if not isinstance(complete, bool):
        raise ValueError("complete must be true or false")
    stamp = now()
    with store.connection(path) as db:
        db.execute("INSERT INTO inventory_declaration(id,scope,complete,declared_at) VALUES (1,?,?,?) "
                   "ON CONFLICT(id) DO UPDATE SET scope=excluded.scope,complete=excluded.complete,declared_at=excluded.declared_at",
                   (scope.strip(), int(complete), stamp))
        db.execute("INSERT INTO audit(at,action,target,detail) VALUES (?,?,?,?)",
                   (stamp, "inventory_scope_declared", "inventory", json.dumps({"complete": complete, "scope": scope.strip()[:200]})))
    return {"scope": scope.strip(), "complete": complete, "declared_at": stamp}


def inventory_declaration_status(path: Path | None = None):
    """Read-only: is there a usable 'complete inventory' declaration right now?"""
    with store.connection(path) as db:
        row = db.execute("SELECT scope,complete,declared_at FROM inventory_declaration WHERE id=1").fetchone()
    if not row:
        return {"declared": False, "complete": False, "recent": False,
                "reason": "No inventory scope has been declared yet; call declare_inventory_scope with complete=true first."}
    declared_at = datetime.fromisoformat(row["declared_at"].replace("Z", "+00:00"))
    age = datetime.now(timezone.utc) - declared_at
    recent = age <= timedelta(days=INVENTORY_DECLARATION_TTL_DAYS)
    return {"declared": True, "scope": row["scope"], "complete": bool(row["complete"]),
            "declared_at": row["declared_at"], "recent": recent,
            "reason": None if (bool(row["complete"]) and recent) else
                     (f"Declaration is older than {INVENTORY_DECLARATION_TTL_DAYS} days; treat as stale until redeclared."
                      if not recent else
                      "The declared inventory is not marked complete; a non-match here could mean missing coverage, not confirmed absence.")}


def _coverage_targets(threat, path):
    """Every distinct behavior fingerprint an analyst has actually recorded
    evidence for on this threat -- one per fixed template behavior, plus one
    per distinct custom-spec fingerprint bound through custom_rule_observations.
    A 'custom' observation is not skipped just because it isn't one of the
    three templates; its fingerprint comes from what it was actually bound to
    when drafted (custom_rules.draft), never guessed.
    """
    observations = [e for e in threat["evidence"] if e["kind"] == "analyst_observation"]
    targets, seen_fps = [], set()
    for behavior in sorted({e["behavior"] for e in observations if e["behavior"] in TEMPLATES}):
        fp = fingerprint_for(behavior)
        if fp in seen_fps:
            continue
        seen_fps.add(fp)
        evidence = [e for e in observations if e["behavior"] == behavior]
        targets.append({"behavior": behavior, "fingerprint": fp, "evidence": evidence})
    custom_ids = [e["id"] for e in observations if e["behavior"] == "custom"]
    if custom_ids:
        with store.connection(path) as db:
            bindings = db.execute("SELECT evidence_id,fingerprint FROM custom_rule_observations WHERE evidence_id IN (" +
                                  ",".join("?" for _ in custom_ids) + ")", custom_ids).fetchall()
        by_fp = {}
        for row in bindings:
            by_fp.setdefault(row["fingerprint"], []).append(row["evidence_id"])
        for fp, evidence_ids in by_fp.items():
            if fp in seen_fps:
                continue
            seen_fps.add(fp)
            evidence = [e for e in observations if e["id"] in evidence_ids]
            targets.append({"behavior": "custom", "fingerprint": fp, "evidence": evidence})
    return targets


def inventory_status(threat_id, path: Path | None = None):
    """Read-only coverage lookup; never creates or changes anything.

    Evaluates every distinct behavior fingerprint an analyst has actually
    recorded evidence for -- the three fixed templates *and* any recorded
    custom behavior, each by its own bound fingerprint. 'yes' only for a
    target with an approved local rule or analyst-imported external rule at
    the exact matching fingerprint. 'no' only when that fingerprint
    comparison ran against an inventory the analyst has explicitly declared
    complete and recent (declare_inventory_scope) -- an inventory that is
    merely empty, or was imported without that declaration, still yields
    'unknown'. 'unknown' whenever no verified behavior exists yet to compare,
    or the declared scope is missing/incomplete/stale.
    """
    threat = get_threat(threat_id, path)
    if not threat:
        raise ValueError("unknown threat")
    declaration = inventory_declaration_status(path)
    targets = _coverage_targets(threat, path)
    if not targets:
        return {"threat_id": threat_id.upper(), "status": "unknown",
                "reason": "No analyst-verified behavior is recorded for this threat yet.", "behaviors": [],
                "inventory_scope": declaration}
    can_assert_no = declaration["declared"] and declaration["complete"] and declaration["recent"]
    scope_note = (f"Checked against the declared complete inventory (\"{declaration['scope']}\"), "
                  f"declared {declaration['declared_at']}." if can_assert_no else
                  declaration["reason"])
    results = []
    with store.connection(path) as db:
        for target in targets:
            behavior, fp = target["behavior"], target["fingerprint"]
            evidence_summary = [{"evidence_id": e["id"], "source_url": e["source_url"], "claim": e["claim"]}
                                for e in target["evidence"]]
            local = db.execute("SELECT id,title,status,pattern_score FROM rules WHERE fingerprint=?", (fp,)).fetchone()
            external = db.execute("SELECT id,title,source_url,pattern_score FROM external_inventory WHERE fingerprint=?", (fp,)).fetchone()
            if local and local["status"] == "approved":
                results.append({"behavior": behavior, "status": "yes", "rule_id": local["id"],
                                "title": local["title"], "pattern_score": local["pattern_score"],
                                "evidence": evidence_summary,
                                "scope": "Matched an approved local rule at this exact behavior fingerprint."})
            elif external:
                results.append({"behavior": behavior, "status": "yes", "rule_id": external["id"],
                                "title": external["title"], "source": external["source_url"],
                                "pattern_score": external["pattern_score"], "evidence": evidence_summary,
                                "note": "Analyst-imported inventory; inspect actual deployed logic.",
                                "scope": "Matched an analyst-imported external rule at this exact fingerprint."})
            elif can_assert_no:
                note = ("A draft exists but is not approved; not counted as covered." if local else
                        "No local draft/approved rule and no imported external rule at this exact fingerprint.")
                results.append({"behavior": behavior, "status": "no",
                                **({"rule_id": local["id"], "title": local["title"]} if local else {}),
                                "evidence": evidence_summary, "note": note, "scope": scope_note})
            else:
                note = ("A draft exists but is not approved; not counted as covered." if local else
                        "No match at this exact fingerprint, but the inventory scope checked is not declared complete/recent, so absence is not confirmed.")
                results.append({"behavior": behavior, "status": "unknown",
                                **({"rule_id": local["id"], "title": local["title"]} if local else {}),
                                "evidence": evidence_summary, "note": note, "scope": scope_note})
    overall = ("yes" if any(r["status"] == "yes" for r in results) else
              "no" if all(r["status"] == "no" for r in results) else "unknown")
    return {"threat_id": threat_id.upper(), "status": overall, "behaviors": results,
            "inventory_scope": declaration,
            "scope": "Exact recorded-behavior fingerprint comparison (fixed templates and custom specs alike), same scope review_for_client uses."}


def reject_rule(rule_id, reason, path: Path | None = None):
    """Record an analyst rejection; the draft stays in the repository for later review, never deleted."""
    if not isinstance(reason, str) or not 5 <= len(reason.strip()) <= 500:
        raise ValueError("a short reason (5-500 characters) is required")
    with store.connection(path) as db:
        row = db.execute("SELECT status FROM rules WHERE id=?", (rule_id,)).fetchone()
        if row is None:
            raise ValueError("unknown rule")
        if row["status"] == "approved":
            raise ValueError("an approved rule cannot be rejected here; review it directly")
        db.execute("UPDATE rules SET status='rejected',rejected_reason=?,rejected_at=? WHERE id=?",
                   (reason.strip(), now(), rule_id))
        db.execute("INSERT INTO audit (at,action,target,detail) VALUES (?,?,?,?)",
                   (now(), "rule_rejected", rule_id, json.dumps({"reason": reason.strip()[:200]})))
    rule_repository.export_rule(rule_id, path)
    return {"status": "rejected", "rule_id": rule_id, "note": "Draft remains stored and can be revisited; it was not deleted."}


def reopen_rule(rule_id, path: Path | None = None):
    """Move a rejected draft back to draft status for a later review pass."""
    with store.connection(path) as db:
        row = db.execute("SELECT status FROM rules WHERE id=?", (rule_id,)).fetchone()
        if row is None:
            raise ValueError("unknown rule")
        if row["status"] != "rejected":
            raise ValueError("only a rejected draft can be reopened")
        db.execute("UPDATE rules SET status='draft',rejected_reason=NULL,rejected_at=NULL WHERE id=?", (rule_id,))
        db.execute("INSERT INTO audit (at,action,target,detail) VALUES (?,?,?,?)",
                   (now(), "rule_reopened", rule_id, "{}"))
    rule_repository.export_rule(rule_id, path)
    return {"status": "draft", "rule_id": rule_id}


def get_rule(rule_id, path: Path | None = None):
    store.initialize(path)
    with store.connection(path) as db:
        row = db.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
        if row is None:
            return None
        sources = [dict(x) for x in db.execute("""SELECT e.id,e.source_url,e.claim,e.behavior
            FROM evidence e JOIN rule_evidence re ON re.evidence_id=e.id WHERE re.rule_id=?""", (rule_id,))]
    from . import custom_rules
    return {**dict(row), "supporting_evidence": sources,
            "custom_spec": custom_rules.get_spec(rule_id, path) if row["behavior"] == "custom" else None,
            "expired": bool(row["expires_at"] and row["expires_at"] <= now()),
            "validation": "syntax and sample telemetry require target-SIEM validation before deployment"}


def implement_rule(rule_id, approval_phrase, evidence_id=None, path: Path | None = None):
    """Explicit request approves a local inventory entry; never deploys to a SIEM."""
    if approval_phrase.strip().lower() != "implement this rule":
        raise ValueError("explicit approval phrase 'implement this rule' is required")
    with store.connection(path) as db:
        row = db.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
        if row is None:
            raise ValueError("unknown rule")
        if row["expires_at"] and row["expires_at"] <= now():
            raise ValueError("IOC hunt has expired; refresh source before approval")
        source_link = db.execute("SELECT status FROM rule_source_links WHERE rule_id=?", (rule_id,)).fetchone()
        if source_link and source_link["status"] != "verified":
            raise ValueError("this draft was proposed from a cited paragraph that the analyst has not verified; "
                             "run verify_draft_source(rule_id, 'I verified this source paragraph') before approval")
        if source_link:
            from .soc_replay import rule_content_hash
            check = db.execute("SELECT rule_hash,sample_provenance FROM rule_tests WHERE rule_id=? "
                               "ORDER BY id DESC LIMIT 1", (rule_id,)).fetchone()
            if not check or check["rule_hash"] != rule_content_hash(dict(row)):
                raise ValueError("no labeled-event check covers this exact rule version; run "
                                 "test_rule_against_samples(rule_id, <your labeled JSONL>) before approval")
        external = db.execute("SELECT id,title,source_url,pattern_score FROM external_inventory WHERE fingerprint=?",
                              (row["fingerprint"],)).fetchone()
        if external:
            return {"status": "existing_external_coverage", "rule_id": external["id"],
                    "title": external["title"], "source": external["source_url"],
                    "pattern_score": external["pattern_score"], "deployment": "unchanged",
                    "note": "Imported mapping was added after this draft; inspect its actual deployed logic."}
        existing = db.execute("SELECT id FROM rules WHERE fingerprint=? AND status='approved'", (row["fingerprint"],)).fetchone()
        if existing and existing["id"] != rule_id:
            return {"status": "existing_coverage", "rule_id": existing["id"]}
        if evidence_id is not None:
            evidence = db.execute("SELECT * FROM evidence WHERE id=? AND kind='analyst_observation'", (evidence_id,)).fetchone()
            if not evidence or evidence["behavior"] != row["behavior"]:
                raise ValueError("evidence must independently support this behavior")
            if row["behavior"] == "custom":
                binding = db.execute("SELECT fingerprint FROM custom_rule_observations WHERE evidence_id=?", (evidence_id,)).fetchone()
                if not binding or binding["fingerprint"] != row["fingerprint"]:
                    raise ValueError("custom observation must match this exact behavior spec")
            existing_link = db.execute("SELECT 1 FROM rule_evidence WHERE rule_id=? AND evidence_id=?", (rule_id, evidence_id)).fetchone()
            if not existing_link:
                if row["behavior"] == "custom" and db.execute(
                    "SELECT 1 FROM rule_evidence re JOIN evidence e ON e.id=re.evidence_id "
                    "WHERE re.rule_id=? AND e.source_url=?", (rule_id, evidence["source_url"])).fetchone():
                    raise ValueError("custom corroboration needs a distinct independent source URL")
                db.execute("INSERT INTO rule_evidence(rule_id,evidence_id) VALUES (?,?)", (rule_id, evidence_id))
                db.execute("UPDATE rules SET pattern_score=pattern_score+1 WHERE id=?", (rule_id,))
        db.execute("UPDATE rules SET status='approved' WHERE id=?", (rule_id,))
        validation_scope = ("fixture_only" if source_link and check["sample_provenance"] == "bundled_synthetic_fixture"
                            else "sample_origin_unverified" if source_link else "not_required_for_legacy_rule")
        db.execute("INSERT INTO audit (at,action,target,detail) VALUES (?,?,?,?)",
                   (now(), "rule_approved", rule_id,
                    json.dumps({"evidence_id": evidence_id, "validation_scope": validation_scope})))
        score = db.execute("SELECT pattern_score FROM rules WHERE id=?", (rule_id,)).fetchone()[0]
    rule_repository.export_rule(rule_id, path)
    return {"status": "approved_in_local_inventory", "rule_id": rule_id, "pattern_score": score,
            "suspicion": "higher_corroboration" if score >= 2 else "investigate_context",
            "deployment": "not_deployed", "validation_scope": validation_scope,
            "validation_note": "Local sample logic check only; native SIEM and production accuracy remain unverified."}


def acknowledge_existing(rule_id, evidence_id, approval_phrase, path: Path | None = None):
    """Attach new independent evidence to an imported inventory rule (+1 once)."""
    if approval_phrase.strip().lower() != "implement this rule":
        raise ValueError("explicit approval phrase 'implement this rule' is required")
    with store.connection(path) as db:
        rule = db.execute("SELECT * FROM external_inventory WHERE id=?", (rule_id,)).fetchone()
        evidence = db.execute("SELECT * FROM evidence WHERE id=?", (evidence_id,)).fetchone()
        if not rule or not evidence:
            raise ValueError("existing rule and matching independent evidence are required")
        if rule["behavior"] == "ioc_network":
            linked_threat = db.execute("SELECT indicator,kind FROM threats WHERE id=?", (evidence["threat_id"],)).fetchone()
            if (evidence["kind"] != "source_fact" or not linked_threat or linked_threat["kind"] != "ioc"
                    or ioc_fingerprint(linked_threat["indicator"]) != rule["fingerprint"]):
                raise ValueError("matching sourced IOC evidence is required")
        elif evidence["kind"] != "analyst_observation" or evidence["behavior"] != rule["behavior"]:
            raise ValueError("matching observed behavior is required")
        if rule["behavior"] == "custom":
            binding = db.execute("SELECT fingerprint FROM custom_rule_observations WHERE evidence_id=?", (evidence_id,)).fetchone()
            if not binding or binding["fingerprint"] != rule["fingerprint"]:
                raise ValueError("custom observation must match exact spec")
        ids = json.loads(rule["evidence_ids"])
        if evidence_id not in ids:
            if rule["behavior"] == "custom" and ids:
                rows = db.execute("SELECT source_url FROM evidence WHERE id IN (" + ",".join("?" for _ in ids) + ")", ids).fetchall()
                if any(row["source_url"] == evidence["source_url"] for row in rows):
                    raise ValueError("custom corroboration needs a distinct independent source URL")
            ids.append(evidence_id)
            db.execute("UPDATE external_inventory SET evidence_ids=?,pattern_score=pattern_score+1 WHERE id=?", (json.dumps(ids), rule_id))
            db.execute("INSERT INTO audit(at,action,target,detail) VALUES (?,?,?,?)",
                       (now(), "external_coverage_corroborated", rule_id, json.dumps({"evidence_id": evidence_id})))
        score = db.execute("SELECT pattern_score FROM external_inventory WHERE id=?", (rule_id,)).fetchone()[0]
    return {"status": "existing_inventory_updated", "rule_id": rule_id, "pattern_score": score,
            "suspicion": "higher_corroboration" if score >= 2 else "investigate_context", "deployment": "unchanged"}


def corroborate_local_rule(rule_id, evidence_id, path: Path | None = None):
    """Attach a distinct, independently-recorded observation to an existing
    local rule and add exactly +1 to its pattern_score. Unlike implement_rule,
    this never changes draft/approved status -- corroborating a draft's
    evidence is a separate action from an analyst's decision to approve it.
    It also never touches environment/asset risk scoring. Used by the
    automatic corroboration-review workflow's explicit approval step, and
    safe to reuse anywhere a rule already has evidence and a fresh,
    independently-cited observation needs to be linked.
    """
    with store.connection(path) as db:
        row = db.execute("SELECT * FROM rules WHERE id=?", (rule_id,)).fetchone()
        if row is None:
            raise ValueError("unknown rule")
        evidence = db.execute("SELECT * FROM evidence WHERE id=? AND kind='analyst_observation'", (evidence_id,)).fetchone()
        if not evidence or evidence["behavior"] != row["behavior"]:
            raise ValueError("evidence must independently support this behavior")
        if row["behavior"] == "custom":
            binding = db.execute("SELECT fingerprint FROM custom_rule_observations WHERE evidence_id=?", (evidence_id,)).fetchone()
            if not binding or binding["fingerprint"] != row["fingerprint"]:
                raise ValueError("custom observation must match this exact behavior spec")
        if db.execute("SELECT 1 FROM rule_evidence WHERE rule_id=? AND evidence_id=?", (rule_id, evidence_id)).fetchone():
            return {"status": "already_linked", "rule_id": rule_id, "pattern_score": row["pattern_score"], "deployment": "unchanged"}
        if db.execute("SELECT 1 FROM rule_evidence re JOIN evidence e ON e.id=re.evidence_id "
                      "WHERE re.rule_id=? AND e.source_url=?", (rule_id, evidence["source_url"])).fetchone():
            raise ValueError("corroboration needs a distinct independent source URL; this source already corroborated this rule")
        db.execute("INSERT INTO rule_evidence(rule_id,evidence_id) VALUES (?,?)", (rule_id, evidence_id))
        db.execute("UPDATE rules SET pattern_score=pattern_score+1 WHERE id=?", (rule_id,))
        db.execute("INSERT INTO audit (at,action,target,detail) VALUES (?,?,?,?)",
                   (now(), "rule_corroborated", rule_id, json.dumps({"evidence_id": evidence_id})))
        score = db.execute("SELECT pattern_score,status FROM rules WHERE id=?", (rule_id,)).fetchone()
    rule_repository.export_rule(rule_id, path)
    return {"status": "corroborated", "rule_id": rule_id, "pattern_score": score["pattern_score"],
            "rule_status": score["status"], "deployment": "not_deployed"}


def implement_or_corroborate(rule_id, approval_phrase, evidence_id=None, path: Path | None = None):
    """One approval entry point for a local draft or an imported inventory match."""
    if get_rule(rule_id, path):
        result = implement_rule(rule_id, approval_phrase, evidence_id, path)
        if result["status"] == "existing_external_coverage" and evidence_id is not None:
            return acknowledge_existing(result["rule_id"], evidence_id, approval_phrase, path)
        return result
    if evidence_id is None:
        raise ValueError("an independent evidence_id is required for an imported existing rule")
    return acknowledge_existing(rule_id, evidence_id, approval_phrase, path)


def review_for_client(rule_id, path: Path | None = None, update_frameworks=True):
    """One cited, environment-aware review payload for the MCP host's analysis."""
    import os
    from . import environment, frameworks, live_validation
    from .core import research_view

    rule = get_rule(rule_id, path)
    if not rule:
        raise ValueError("unknown local rule; collect and verify behavior before drafting")
    threat = get_threat(rule["threat_id"], path)
    with store.connection(path) as db:
        other_local = [dict(row) for row in db.execute(
            "SELECT id,title,status,pattern_score FROM rules WHERE fingerprint=? AND id<>?", (rule["fingerprint"], rule_id))]
        imported = [dict(row) for row in db.execute(
            "SELECT id,title,source_url,pattern_score FROM external_inventory WHERE fingerprint=?", (rule["fingerprint"],))]
    setup = environment.status(path)
    risk = None
    if threat and threat["kind"] == "advisory" and setup.get("configured"):
        risk = environment.risk_from_assets(rule["threat_id"], path)
    elif threat:
        risk = {"priority": "verify_environment_relevance", "score": None,
                "reason": "No verified matching asset and local event context were supplied; a client risk score cannot be asserted."}
    live_inventory = {"status": "not_connected", "reason": "No authorized native inventory read is configured."}
    if setup.get("siem") == "splunk" and setup.get("splunk_probe_configured") and os.environ.get("SPLUNK_TOKEN"):
        try:
            live_inventory = live_validation.compare_splunk_inventory(rule_id, path)
        except (OSError, ValueError) as exc:
            live_inventory = {"status": "unavailable", "reason": str(exc)[:200]}
    context = frameworks.retrieve(rule["behavior"], path, update=update_frameworks)
    if rule["behavior"] == "custom":
        context["unverified_candidates"] = frameworks.search((rule["title"] + " " + rule["rationale"])[:300], path, update=False)["candidates"]
    return {"as_of": now(), "rule": rule, "threat_sources": threat["sources"] if threat else [],
            "why_helpful": rule["rationale"], "behavior_and_future_hypotheses": research_view(rule["threat_id"], path),
            "inventory_comparison": {
                "exact_local_behavior_and_telemetry": other_local,
                "analyst_mapped_external_coverage": imported,
                "live_splunk_candidate_review": live_inventory,
                "scope": "Exact supported-behavior fingerprints only. Arbitrary deployed queries require SIEM access or a curated inventory; inspect actual logic before calling them equivalent."},
            "environment": setup, "environment_risk": risk,
            "detection_fit": environment.check_rule_fit(rule_id, path),
            "framework_context": context,
            "analyst_next_steps": ["Verify the cited report and observed behavior.",
                                   "Compare real deployed inventory and representative benign/positive telemetry.",
                                   "Tune and test target query in the client SIEM before deployment."],
            "deployment": "review_only_not_deployed"}

"""Conservative, repeatable draft proposals from already inspected research.

This is a bounded rule writer, not an analyst: a paragraph must contain a
SHA-256 paired with a named malicious file, an explicit process/child action,
an encoded PowerShell command, a named DLL loaded by a named process, or a
named process contacting a quoted C2 host. Both values for behavioral rules
must be in the same inspected paragraph and tied by an explicit action.
The draft remains unverified and cannot be approved without source verification
and real labeled checks. Behavioral descriptions without measurable predicates
stay visible as research gaps rather than invented detections.
"""

import re
from pathlib import Path

from . import behavior_leads, drafting, research_pass, store, workup
from .core import now

SYSTEM32_EXCLUSION = {"field": "ImageLoaded", "operator": "startswith", "value": "C:\\Windows\\System32\\"}


ENCODED_FLAG = re.compile(r"(?<!\w)-(?:EncodedCommand|enc)\b", re.I)
EXECUTION_ACTOR = re.compile(r"\b(?:attackers?|adversar(?:y|ies)|threat actors?|intruders?|"
                             r"malware|malicious|payload|backdoor|implant)\b", re.I)
WINDOWS_EXE = re.compile(r"\b[A-Za-z0-9_.-]+\.exe\b", re.I)
PROCESS_TOKEN = re.compile(r"\b[A-Za-z0-9_.-]+\.exe\b|\b(?:PowerShell|pwsh|bash|sh|nginx|httpd|apache2|python3?|curl|wget|perl|openssl)\b", re.I)
PROCESS_ACTION = re.compile(r"\b(?:spawn(?:s|ed)?|launch(?:es|ed)?|start(?:s|ed)?|execut(?:es|ed)|"
                            r"invok(?:es|ed)|used|run(?:s|ning)?)\b", re.I)
COMMAND_TOKEN = re.compile(r"\b(?:Invoke-WebRequest|Invoke-RestMethod|curl|wget|mshta|certutil|bitsadmin)\b|(?<!\w)/qn\b", re.I)
WINDOWS_DLL = re.compile(r"\b[A-Za-z0-9_.-]+\.dll\b", re.I)
HOSTNAME = re.compile(r"(?<![\w.-])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b")
DLL_LOAD = re.compile(r"\b(?:load(?:s|ed|ing)?|side[ -]?load(?:s|ed|ing)?)\b", re.I)
C2_ACTION = re.compile(r"\b(?:connect(?:s|ed|ing)?|contact(?:s|ed|ing)?|"
                       r"communicat(?:es|ed|ing)|beacon(?:s|ed|ing)?)\b", re.I)
REVERSE_SHELL = re.compile(r"\breverse shell\b", re.I)
OPENSSL_CLIENT = re.compile(r"\bopenssl\s+s_client\b", re.I)


def _actor_before(quote, process):
    """An attacker/malware cue must modify this action, not another sentence."""
    prefix = quote[max(0, process.start() - 140):process.start()]
    actors = list(EXECUTION_ACTOR.finditer(prefix))
    return bool(actors and not re.search(r"[!?;]|\.(?:\s|$)", prefix[actors[-1].end():]))


def _process_spec(pattern):
    """Use exactly the process names in an explicit parent-spawns-child claim."""
    quote = pattern["quoted_paragraph"]
    for parent in PROCESS_TOKEN.finditer(quote):
        for child in PROCESS_TOKEN.finditer(quote, parent.end(), min(len(quote), parent.end() + 160)):
            between = quote[parent.end():child.start()]
            if (not PROCESS_ACTION.search(between) or re.search(r"[!?;]|\.(?:\s|$)", between)
                    or re.search(r"\b(?:was|were)\s+(?:used|launched|spawned|executed)\s+by\b", between, re.I)):
                continue
            if not (behavior_leads.execution_chain(quote[parent.start():], anchored=True) or _actor_before(quote, parent) or EXECUTION_ACTOR.search(
                    re.split(r"[!?;]|\.(?:\s|$)", quote[child.end():child.end()+100], maxsplit=1)[0])):
                continue
            child_op = "endswith" if child.group().lower().endswith(".exe") else "contains"
            predicates = [{"field": "ParentImage", "operator": "endswith", "value": parent.group()},
                          {"field": "Image", "operator": child_op, "value": child.group()}]
            command = COMMAND_TOKEN.search(quote, child.end(), min(len(quote), child.end() + 100))
            if command and not re.search(r"[!?;]|\.(?:\s|$)", quote[child.end():command.start()]):
                predicates.append({"field": "CommandLine", "operator": "contains", "value": command.group()})
            return {"event_family": "process_creation",
                    "platform": "windows" if parent.group().lower().endswith(".exe") or child.group().lower() in ("powershell", "pwsh") else "linux",
                    "predicates": predicates}
    if (pattern.get("observable") or {}).get("lexical_behavior") != "web_server_shell":
        return None
    parent, child = behavior_leads.WEB_PARENT.search(quote), behavior_leads.SHELL.search(quote)
    if not (parent and child and parent.end() < child.start() <= parent.end() + 180
            and behavior_leads.CHILD_ACTION.search(quote[parent.end():child.start()])):
        return None
    # The portable Windows process event fields cannot represent Linux sh/bash.
    if not parent.group().lower().endswith(".exe") or not child.group().lower().endswith(".exe"):
        return None
    return {"event_family": "process_creation", "platform": "windows", "predicates": [
        {"field": "ParentImage", "operator": "endswith", "value": parent.group()},
        {"field": "Image", "operator": "endswith", "value": child.group()}]}


def _encoded_powershell_spec(pattern):
    """Only a source's explicit process and switch; a general mention is insufficient."""
    if (pattern.get("observable") or {}).get("lexical_behavior") != "encoded_powershell":
        return None
    quote = pattern["quoted_paragraph"]
    for process in behavior_leads.POWERSHELL.finditer(quote):
        # A generic mention of PowerShell does not assert powershell.exe ran.
        if not process.group().lower().endswith(".exe"):
            continue
        for flag in ENCODED_FLAG.finditer(quote, process.end(), min(len(quote), process.end() + 100)):
            prefix = re.split(r"[!?;]|\.(?:\s|$)", quote[max(0, process.start() - 120):process.start()])[-1]
            if (not EXECUTION_ACTOR.search(prefix) or not behavior_leads.EXECUTE.search(prefix)
                    or any(mark in quote[process.end():flag.start()] for mark in ".!?;")):
                continue
            return {"event_family": "process_creation", "platform": "windows", "predicates": [
                {"field": "Image", "operator": "endswith", "value": process.group()},
                {"field": "CommandLine", "operator": "contains", "value": flag.group()}]}
    return None


def _process_command_spec(pattern):
    """An explicitly executed command under a named process, never a list of tools."""
    quote = pattern["quoted_paragraph"]
    for process in PROCESS_TOKEN.finditer(quote):
        if not _actor_before(quote, process):
            continue
        command = COMMAND_TOKEN.search(quote, process.end(), min(len(quote), process.end() + 140))
        if not command:
            continue
        between = quote[process.end():command.start()]
        if re.search(r"[!?;]|\.(?:\s|$)", between) or not re.search(r"(?:\b(?:command(?:\s+line)?|with|to\s+(?:execute|run|invoke))\b|(?<!\w)-l?c\b)", between, re.I):
            continue
        return {"event_family": "process_creation", "platform": "windows" if process.group().lower().endswith(".exe") else "linux", "predicates": [
            {"field": "Image", "operator": "endswith", "value": process.group()},
            {"field": "CommandLine", "operator": "contains", "value": command.group()}]}
    return None


def _image_load_spec(pattern):
    """Require a literal process loading a literal DLL, not a generic sideloading claim."""
    if (pattern.get("observable") or {}).get("lexical_behavior") != "dll_sideloading":
        return None
    quote = pattern["quoted_paragraph"]
    for process in WINDOWS_EXE.finditer(quote):
        for module in WINDOWS_DLL.finditer(quote, process.end(), min(len(quote), process.end() + 180)):
            between = quote[process.end():module.start()]
            # Talos describes a signed executable which "sideloads slc.dll,
            # the Antino backdoor"; the actor cue follows the module. A cue
            # in a previous sentence does not justify an unrelated DLL load.
            suffix = re.split(r"[!?;]|\.(?:\s|$)", quote[module.end():module.end() + 120], maxsplit=1)[0]
            if (DLL_LOAD.search(between) and not re.search(r"[!?;]|\.(?:\s|$)", between)
                    and (_actor_before(quote, process) or EXECUTION_ACTOR.search(suffix))):
                spec = {"event_family": "image_load", "platform": "windows", "predicates": [
                    {"field": "Image", "operator": "endswith", "value": process.group()},
                    {"field": "ImageLoaded", "operator": "endswith", "value": module.group()}]}
                spec["exclude"] = [dict(SYSTEM32_EXCLUSION)]
                return spec
    return None


def _c2_process_spec(pattern):
    """Require the reported process and its C2 domain in one short action clause."""
    if (pattern.get("observable") or {}).get("lexical_behavior") != "c2_communication":
        return None
    quote = pattern["quoted_paragraph"]
    for process in WINDOWS_EXE.finditer(quote):
        if not _actor_before(quote, process):
            continue
        for host in HOSTNAME.finditer(quote, process.end(), min(len(quote), process.end() + 200)):
            between = quote[process.end():host.start()]
            if (C2_ACTION.search(between) and behavior_leads.C2.search(between)
                    and not re.search(r"[!?;]|\.(?:\s|$)", between)):
                return {"event_family": "network_connection", "platform": "windows", "predicates": [
                    {"field": "Image", "operator": "endswith", "value": process.group()},
                    {"field": "DestinationHostname", "operator": "equals", "value": host.group()}]}
    return None


def _linux_reverse_shell_spec(pattern):
    """A narrow, review-only Linux hunt for an explicit OpenSSL reverse shell."""
    quote = pattern["quoted_paragraph"]
    if (REVERSE_SHELL.search(quote) and "/bin/sh" in quote and "/tmp/" in quote
            and OPENSSL_CLIENT.search(quote) and behavior_leads.ACTOR.search(quote)):
        # This selector catches s_client usage, not the pipe correlation or a
        # confirmed reverse shell. Its breadth must be visible to reviewers.
        return {"event_family": "process_creation", "platform": "linux", "predicates": [
            {"field": "Image", "operator": "endswith", "value": "openssl"},
            {"field": "CommandLine", "operator": "contains", "value": "s_client"}]}
    return None


def behavior_spec(pattern):
    """A bounded behavioral selection from one paragraph; no source verification implied."""
    return (_process_spec(pattern) or _encoded_powershell_spec(pattern) or _process_command_spec(pattern)
            or _image_load_spec(pattern) or _c2_process_spec(pattern)
            or _linux_reverse_shell_spec(pattern))


def propose_from_stored(threat_id: str, path: Path | None = None):
    from . import sources
    if sources.CVE.fullmatch(threat_id.upper()):
        return {"threat_id": threat_id.upper(), "research_status": "exposure_patch_review",
                "patterns_reviewed": 0, "proposals": [], "gaps": [],
                "note": "CVE-only leads go to exposure and patch review. Draft behavior from the original report lead."}
    analysis = workup.pattern_analysis(threat_id, path)
    proposals, gaps = [], []
    if not analysis["patterns"]:
        gaps.append({"source_url": None, "paragraph": None,
                     "reason": ("No full cited page is readable in stored research. Browser or source review is "
                                "needed before drafting." if analysis["status"] == "no_readable_source" else
                                "Stored research contains no bounded cited pattern for a draft.")})
    for pattern in analysis["patterns"]:
        spec = ((pattern.get("draftable") or {}).get("suggested_spec") or
                (None if pattern.get("publisher_query") else behavior_spec(pattern)))
        quote = pattern["quoted_paragraph"]
        if not spec:
            gaps.append({"source_url": pattern["source_url"], "paragraph": pattern["paragraph"],
                         "reason": (pattern.get("draftable") or {}).get("reason", "No bounded rule predicates.")})
            continue
        # A secondary news story can quote research, but the identity and
        # malicious context must be checked at the original publication.
        if research_pass._host(pattern["source_url"]) in research_pass.NEWS_HOSTS:
            gaps.append({"source_url": pattern["source_url"], "paragraph": pattern["paragraph"],
                         "reason": "Secondary news source: inspect its original technical publication first."})
            continue
        if (not pattern["quote_is_full_text"] or behavior_leads.NEGATION.search(quote)
                or (not pattern.get("publisher_query") and not behavior_leads.has_behavior_context(quote))):
            gaps.append({"source_url": pattern["source_url"], "paragraph": pattern["paragraph"],
                         "reason": "The inspected paragraph does not tie the file to attacker activity."})
            continue
        if pattern.get("publisher_query"):
            title = f"Publisher KQL event selector ({analysis['threat_id']}, query {pattern['paragraph']})"[:150]
            rationale = ("The publisher's inspected KQL query contains exactly these bounded comparisons. "
                         "This draft translates only the supported event selector; check its scope, intent, "
                         "false positives and event fields against the original query before approval. "
                         "The publisher query itself was not executed.")
            false_positives = ("A publisher hunting query can match normal administration or benign software. "
                               "Replay labeled benign and malicious events in your own telemetry before approval.")
        elif any(p["field"] == "ParentImage" for p in spec["predicates"]):
            parent = next(p["value"] for p in spec["predicates"] if p["field"] == "ParentImage")
            child = next(p["value"] for p in spec["predicates"] if p["field"] == "Image")
            title = f"Reported {parent} spawning {child} ({analysis['threat_id']})"[:150]
            rationale = (f"Paragraph {pattern['paragraph']} reports {parent} spawning {child} in the cited "
                         "process chain. This is a behavior hypothesis from the publisher; check the process fields "
                         "and local context before approval.")
            false_positives = ("Web administration and application maintenance can launch a shell. "
                               "Review account, command line, host and change window against benign events.")
        elif spec["platform"] == "linux" and spec["event_family"] == "process_creation":
            title = f"Reported OpenSSL reverse-shell client activity ({analysis['threat_id']})"[:150]
            rationale = (f"Paragraph {pattern['paragraph']} reports a named pipe connecting /bin/sh to "
                         "openssl s_client in a reverse shell. The selector detects OpenSSL client process "
                         "execution only; it cannot establish the pipe, destination or intent. Review "
                         "process lineage and command line before approval.")
            false_positives = ("Legitimate TLS diagnostics use openssl s_client. A match alone does not prove "
                               "a reverse shell; confirm the pipe and shell lineage with local events.")
        elif any(p["field"] == "CommandLine" for p in spec["predicates"]):
            process = next(p["value"] for p in spec["predicates"] if p["field"] == "Image")
            flag = next(p["value"] for p in spec["predicates"] if p["field"] == "CommandLine")
            title = f"Reported {process} {flag} execution ({analysis['threat_id']})"[:150]
            rationale = (f"Paragraph {pattern['paragraph']} reports attacker execution of {process} with the "
                         f"{flag} command term. This detects a command-line pattern, not the payload or a local sighting; "
                         "verify the publisher's description and event fields before approval.")
            false_positives = ("Administrative scripts can use the same command terms. Review process ancestry, "
                               "script content and account against benign events before approval.")
        elif spec["event_family"] == "image_load":
            process = next(p["value"] for p in spec["predicates"] if p["field"] == "Image")
            module = next(p["value"] for p in spec["predicates"] if p["field"] == "ImageLoaded")
            title = f"Reported {process} loading {module} ({analysis['threat_id']})"[:150]
            rationale = (f"Paragraph {pattern['paragraph']} describes {process} loading {module} in a DLL "
                         "sideloading report. This is a publisher claim, not proof the module was malicious on "
                         "your systems; check the module's path and signature before approval.")
            false_positives = (f"Normal installations of {process} may load {module}. Check path, hash, signature "
                               "and benign events before interpreting a match as malicious.")
        elif spec["event_family"] == "network_connection":
            process = next(p["value"] for p in spec["predicates"] if p["field"] == "Image")
            host = next(p["value"] for p in spec["predicates"] if p["field"] == "DestinationHostname")
            title = f"Reported {process} C2 connection to {host} ({analysis['threat_id']})"[:150]
            rationale = (f"Paragraph {pattern['paragraph']} connects {process} to the C2 host {host}. This "
                         "is a reported process-and-destination hypothesis; the host may change and no "
                         "local connection has been observed.")
            false_positives = ("Hostname attribution and process names can be incomplete or shared. Check DNS, "
                               "connection context and benign events before approval.")
        else:
            name = next((p["value"] for p in spec["predicates"] if p["field"] == "TargetFilename"), None)
            title = (f"Reported {name or 'file'} SHA-256 ({analysis['threat_id']})")[:150]
            rationale = (f"Paragraph {pattern['paragraph']} of the cited publisher report identifies a file by "
                         "SHA-256 in malicious activity. This is an exact sample hunt, not a behavioral detection "
                         "or evidence of activity in the local environment.")
            false_positives = ("Check file-hash telemetry and benign context before approval; "
                               "a hash match identifies the reported sample only.")
        try:
            result = drafting.propose(analysis["threat_id"], pattern["source_url"], pattern["paragraph"], spec,
                                      title, rationale, false_positives, path, proposed_by="bounded_research_pass",
                                      publisher_query=pattern.get("publisher_query", False),
                                      browser_capture_id=pattern.get("browser_capture_id"))
        except ValueError as exc:
            gaps.append({"source_url": pattern["source_url"], "paragraph": pattern["paragraph"],
                         "reason": f"Candidate refused: {exc}"})
            continue
        if any(p["rule_id"] == result["rule_id"] and p["source_url"] == pattern["source_url"]
               and p["paragraph"] == pattern["paragraph"] for p in proposals):
            continue
        proposals.append({"source_url": pattern["source_url"], "paragraph": pattern["paragraph"],
                          "status": result["status"], "rule_id": result["rule_id"],
                          "source_verification": ("unverified" if result["status"] == "draft_unverified" else
                                                  "see existing rule"), "reason": rationale})
    with store.connection(path) as db:
        existing = db.execute("SELECT l.source_url,l.paragraph,l.rule_id,r.status FROM rule_source_links l JOIN rules r ON r.id=l.rule_id WHERE l.threat_id=?", (analysis["threat_id"],)).fetchall()
    covered = {(p["source_url"], p["paragraph"]) for p in proposals}
    for row in existing:
        citation = (row["source_url"], row["paragraph"])
        if citation not in covered:
            proposals.append({"source_url": row["source_url"], "paragraph": row["paragraph"], "rule_id": row["rule_id"],
                              "status": "existing_draft" if row["status"] == "draft" else "existing_coverage",
                              "source_verification": "see existing rule", "reason": "This citation already has a source-linked rule."})
            covered.add(citation)
    # The artifact extractor can list a filename from the same paragraph as
    # an explicit behavior. Do not report "filename alone" as a second gap
    # when the process/module or process/destination rule used that paragraph.
    gaps = [gap for gap in gaps if (gap["source_url"], gap["paragraph"]) not in covered]
    return {"threat_id": analysis["threat_id"], "research_status": analysis["status"],
            "patterns_reviewed": len(analysis["patterns"]), "proposals": proposals, "gaps": gaps,
            "note": "No source was analyst-verified, no rule was approved or deployed, and no local risk was scored."}


def proposal_gaps(threat_id: str, path: Path | None = None, offset: int = 0, limit: int = 20):
    """Page all gaps on one lead; also deduplicate any source-linked candidates."""
    if offset < 0 or limit < 1:
        raise ValueError("offset must be non-negative and limit positive")
    result = propose_from_stored(threat_id, path)
    gaps = result["gaps"]
    limit = min(limit, 40)
    end = offset + limit
    return {"threat_id": result["threat_id"], "total": len(gaps), "offset": offset,
            "gaps": gaps[offset:end], "next_offset": end if end < len(gaps) else None,
            "proposals": [{"rule_id": p["rule_id"], "status": p["status"]} for p in result["proposals"]],
            "note": "Draft proposals may be created from stored cited text; no source was verified or rule approved."}


def propose_stored_batch(path: Path | None = None, limit: int = 20, after_id: str = ""):
    """Backfill citations already researched, page by page without fetching or approving.

    A stable threat-id cursor lets an MCP client resume after each bounded batch.
    Repeating the same cursor is safe: exact predicate fingerprints deduplicate
    drafts, including drafts already written during the original research pass.
    """
    store.initialize(path)
    if not isinstance(after_id, str) or len(after_id) > 100:
        raise ValueError("after_id must be the next_cursor from the previous batch (or empty)")
    count = max(1, min(int(limit), 40))
    with store.connection(path) as db:
        ids = [row["threat_id"] for row in db.execute(
            "SELECT threat_id FROM research_outcomes WHERE threat_id>? ORDER BY threat_id LIMIT ?",
            (after_id.upper(), count)).fetchall()]
    results = []
    for ident in ids:
        try:
            outcome = propose_from_stored(ident, path)
            proposals = outcome["proposals"]
            results.append({"threat_id": ident, "research_status": outcome["research_status"],
                            "patterns_reviewed": outcome["patterns_reviewed"],
                            "drafts_created": sum(p["status"] == "draft_unverified" for p in proposals),
                            "existing_drafts": sum(p["status"] == "existing_draft" for p in proposals),
                            "existing_rule_matches": sum(p["status"] == "existing_coverage" for p in proposals),
                            "proposals": [{"rule_id": p["rule_id"], "status": p["status"],
                                           "source_url": p["source_url"], "paragraph": p["paragraph"]}
                                          for p in proposals],
                            "gap_count": len(outcome["gaps"]), "gaps": outcome["gaps"][:5],
                            "gaps_remaining": max(0, len(outcome["gaps"]) - 5),
                            "gaps_next_offset": 5 if len(outcome["gaps"]) > 5 else None})
        except ValueError as exc:
            results.append({"threat_id": ident, "status": "error", "reason": str(exc)[:300],
                            "patterns_reviewed": 0, "drafts_created": 0, "existing_drafts": 0,
                            "existing_rule_matches": 0,
                            "proposals": [], "gap_count": 0, "gaps": []})
    cursor = ids[-1] if ids else after_id.upper()
    with store.connection(path) as db:
        remaining = db.execute("SELECT COUNT(*) FROM research_outcomes WHERE threat_id>?", (cursor,)).fetchone()[0]
    return {"leads_processed": len(results), "patterns_reviewed": sum(r["patterns_reviewed"] for r in results),
            "drafts_created": sum(r["drafts_created"] for r in results),
            "existing_drafts": sum(r["existing_drafts"] for r in results),
            "existing_rule_matches": sum(r["existing_rule_matches"] for r in results),
            "gaps_total": sum(r["gap_count"] for r in results), "results": results,
            "next_cursor": cursor if remaining else None, "remaining_researched_leads": remaining,
            "note": ("Stored research only: no source fetch, analyst verification, approval, deployment, local "
                     "telemetry claim or environment risk score. Each draft cites an inspected paragraph; "
                     "unreadable sources need a cited browser capture before they can yield a source-linked draft. "
                     "Use propose_stored_draft_gaps for every gap beyond this batch preview.")}


def advance_stored_backfill(path: Path | None = None, limit: int = 20):
    """Advance one durable batch per poll; a failed batch is safe to retry.

    A completed sweep resets the cursor so later polls can revisit research
    refreshed after its ID was passed. Existing draft fingerprints deduplicate.
    The collector's poll lease prevents concurrent automatic workers.
    """
    store.initialize(path)
    with store.connection(path) as db:
        db.execute("INSERT OR IGNORE INTO proposal_backfill_state(id) VALUES (1)")
        start = db.execute("SELECT cursor FROM proposal_backfill_state WHERE id=1").fetchone()[0]
    result = propose_stored_batch(path, limit=limit, after_id=start)
    next_cursor = result["next_cursor"] or ""
    with store.connection(path) as db:
        db.execute("UPDATE proposal_backfill_state SET cursor=?,last_run_at=? WHERE id=1",
                   (next_cursor, now()))
    return {"leads_processed": result["leads_processed"], "patterns_reviewed": result["patterns_reviewed"],
            "drafts_created": result["drafts_created"], "existing_drafts": result["existing_drafts"],
            "existing_rule_matches": result["existing_rule_matches"],
            "gaps_total": result["gaps_total"],
            "errors": sum(r.get("status") == "error" for r in result["results"]),
            "remaining_researched_leads": result["remaining_researched_leads"],
            "cycle_completed": not bool(next_cursor), "cursor": next_cursor,
            "note": "Stored-only analysis; unverified drafts and cited gaps, no source fetch or approvals."}

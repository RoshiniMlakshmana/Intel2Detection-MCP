"""Conservative, repeatable draft proposals from already inspected research.

This is a bounded rule writer, not an analyst: a paragraph must contain either
a SHA-256 paired with a named malicious file, or explicit Windows web-server
parent and shell child process names and a spawning action.
The draft remains unverified and cannot be approved without source verification
and real labeled checks. Behavioral descriptions without measurable predicates
stay visible as research gaps rather than invented detections.
"""

from pathlib import Path

from . import behavior_leads, drafting, research_pass, workup


def _process_spec(pattern):
    """Use exactly the process names in an explicit parent-spawns-child claim."""
    if (pattern.get("observable") or {}).get("lexical_behavior") != "web_server_shell":
        return None
    quote = pattern["quoted_paragraph"]
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


def propose_from_stored(threat_id: str, path: Path | None = None):
    analysis = workup.pattern_analysis(threat_id, path)
    proposals, gaps = [], []
    for pattern in analysis["patterns"]:
        spec = (pattern.get("draftable") or {}).get("suggested_spec") or _process_spec(pattern)
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
                or not behavior_leads.ACTOR.search(quote)):
            gaps.append({"source_url": pattern["source_url"], "paragraph": pattern["paragraph"],
                         "reason": "The inspected paragraph does not tie the file to attacker activity."})
            continue
        if spec["event_family"] == "process_creation":
            parent, child = (p["value"] for p in spec["predicates"])
            title = f"Reported {parent} spawning {child} ({analysis['threat_id']})"[:150]
            rationale = (f"Paragraph {pattern['paragraph']} reports {parent} spawning {child} during attacker "
                         "activity. This is a behavior hypothesis from the publisher; check the process fields "
                         "and local context before approval.")
            false_positives = ("Web administration and application maintenance can launch a shell. "
                               "Review account, command line, host and change window against benign events.")
        else:
            name = next(p["value"] for p in spec["predicates"] if p["field"] == "TargetFilename")
            title = (f"Reported {name} SHA-256 ({analysis['threat_id']})")[:150]
            rationale = (f"Paragraph {pattern['paragraph']} of the cited publisher report names {name} with an exact "
                         "SHA-256 in malicious activity. This proposal identifies only that reported sample, "
                         "not every variant or an event observed in the local environment.")
            false_positives = (f"A legitimate {name} may exist; require the reported SHA-256. "
                               "Check file-hash telemetry and benign look-alikes before approval.")
        result = drafting.propose(analysis["threat_id"], pattern["source_url"], pattern["paragraph"], spec,
                                  title, rationale, false_positives, path, proposed_by="bounded_research_pass")
        proposals.append({"source_url": pattern["source_url"], "paragraph": pattern["paragraph"],
                          "status": result["status"], "rule_id": result["rule_id"],
                          "source_verification": ("unverified" if result["status"] == "draft_unverified" else
                                                  "see existing rule"), "reason": rationale})
    return {"threat_id": analysis["threat_id"], "proposals": proposals, "gaps": gaps,
            "note": "No source was analyst-verified, no rule was approved or deployed, and no local risk was scored."}

"""Automatic corroboration review.

When a newly collected, cited article-behavior lead lexically matches a
behavior that already has a rule in the local inventory (a drafted or
approved local rule, or an analyst-imported external rule), this queues a
durable *pending review* -- never an automatic evidence link, never a score
change, and never a claim that coverage is confirmed. Only an analyst's
explicit approval attaches evidence and adds exactly +1 to that rule's
pattern_score; rejection leaves the rule untouched. Environment/asset risk
scoring is a separate concern this module never touches.

A lead is inherently a lexical read of one paragraph in one article --
`behavior_leads.py` says so itself ("Lexical lead only; verify actor
action, negation, telemetry, and benign context in the full report"). That
caveat is carried through into every pending review and never dropped just
because the lead happens to line up with an existing rule's fingerprint.
"""

import json
from pathlib import Path

from . import core, rule_repository, rules, store
from .core import now
from .rules import TEMPLATES, fingerprint_for

LEAD_CAVEAT = ("Lexical lead only, cited to a specific source and paragraph. The analyst must confirm the "
               "behavior, check for negation, and rule out benign context in the full article before approving.")


def _find_match(fingerprint, path):
    """At most one local rule and one external rule can ever hold a given
    fixed-template fingerprint (both fingerprint columns are UNIQUE), so this
    is a single deterministic lookup, not a fuzzy or ranked match."""
    with store.connection(path) as db:
        local = db.execute("SELECT id,status FROM rules WHERE fingerprint=?", (fingerprint,)).fetchone()
        if local:
            return "local", local["id"], local["status"]
        external = db.execute("SELECT id FROM external_inventory WHERE fingerprint=?", (fingerprint,)).fetchone()
        if external:
            return "external", external["id"], "external_imported"
    return None, None, None


def queue_from_lead(threat_id, source_url, paragraph, behavior, excerpt, path: Path | None = None):
    """Call this once per genuinely new article_behavior_leads row (i.e. only
    when its INSERT OR IGNORE actually inserted). Idempotent: a repeat of the
    exact same lead -- from a re-poll, a retry, or re-inspecting the same
    article -- can never create a second pending review or change any score,
    because the row is keyed on (rule, threat, source, paragraph, behavior)
    with INSERT OR IGNORE. Returns the review id, or None if the behavior
    isn't one of the fixed templates or doesn't match anything in inventory.
    """
    if behavior not in TEMPLATES:
        return None
    fp = fingerprint_for(behavior)
    kind, rule_id, matched_status = _find_match(fp, path)
    if kind is None:
        return None
    with store.connection(path) as db:
        db.execute("""INSERT OR IGNORE INTO corroboration_reviews
            (rule_kind,rule_id,threat_id,source_url,paragraph,behavior,excerpt,fingerprint,matched_rule_status,status,created_at)
            VALUES (?,?,?,?,?,?,?,?,?,'pending',?)""",
            (kind, rule_id, threat_id.upper(), source_url, paragraph, behavior, excerpt[:420], fp, matched_status, now()))
        row = db.execute("""SELECT id FROM corroboration_reviews WHERE rule_kind=? AND rule_id=? AND threat_id=?
            AND source_url=? AND paragraph=? AND behavior=?""",
            (kind, rule_id, threat_id.upper(), source_url, paragraph, behavior)).fetchone()
    return row["id"] if row else None


def queue_custom_matches(threat_id, source_url, page, path: Path | None = None):
    """Queue a pending review when a fresh inspected paragraph contains every literal
    predicate value of an existing custom rule (draft or approved).

    The match is exact on the rule's own literals (e.g. the same SHA-256 and
    file name), never similarity. The rule's own cited source, or any source
    that already corroborated it, is skipped, so a re-read can never queue a
    self-corroboration. Nothing is attached or scored here.
    """
    texts = page.get("paragraph_text") or {}
    if not texts:
        return []
    with store.connection(path) as db:
        candidates = db.execute("SELECT r.id,r.status,r.fingerprint,c.spec FROM rules r "
                                "JOIN custom_rule_specs c ON c.rule_id=r.id "
                                "WHERE r.status IN ('draft','approved')").fetchall()
    queued = []
    for row in candidates:
        values = [p["value"].casefold() for p in json.loads(row["spec"])["predicates"]]
        if source_url in _existing_source_urls("local", row["id"], path):
            continue
        for number, text in sorted(texts.items(), key=lambda item: int(item[0])):
            if all(value in text.casefold() for value in values):
                with store.connection(path) as db:
                    inserted = db.execute("""INSERT OR IGNORE INTO corroboration_reviews
                        (rule_kind,rule_id,threat_id,source_url,paragraph,behavior,excerpt,fingerprint,
                         matched_rule_status,status,created_at)
                        VALUES ('local',?,?,?,?,'custom',?,?,?,'pending',?)""",
                                          (row["id"], threat_id.upper(), source_url, int(number), text[:420],
                                           row["fingerprint"], row["status"], now())).rowcount
                if inserted:
                    queued.append(row["id"])
                break
    return queued


def _custom_observation(review, path):
    """Approving a custom review is the analyst confirming that exact paragraph."""
    claim = f"Corroboration review approved (paragraph {review['paragraph']}): {review['excerpt']}"[:1000]
    with store.connection(path) as db:
        db.execute("INSERT OR IGNORE INTO evidence (threat_id,source_url,claim,kind,behavior,observed_at) "
                   "VALUES (?,?,?,?,?,?)", (review["threat_id"], review["source_url"], claim,
                                            "analyst_observation", "custom", now()))
        evidence_id = db.execute("SELECT id FROM evidence WHERE threat_id=? AND source_url=? AND claim=? "
                                 "AND kind='analyst_observation'",
                                 (review["threat_id"], review["source_url"], claim)).fetchone()[0]
        db.execute("INSERT OR IGNORE INTO custom_rule_observations VALUES (?,?)", (evidence_id, review["fingerprint"]))
    return evidence_id


def _rule_context(rule_kind, rule_id, path):
    """Live title/status/pattern_score -- never the stale value captured at
    queue time, so a rule already approved (or corroborated) since the lead
    was queued is always shown accurately."""
    if rule_kind == "local":
        rule = rules.get_rule(rule_id, path)
        if not rule:
            return None, None, None
        return rule["title"], rule["status"], rule["pattern_score"]
    with store.connection(path) as db:
        row = db.execute("SELECT title,pattern_score FROM external_inventory WHERE id=?", (rule_id,)).fetchone()
    return (row["title"], "external_imported", row["pattern_score"]) if row else (None, None, None)


def _enrich(row, path=None):
    title, live_status, score = _rule_context(row["rule_kind"], row["rule_id"], path)
    return {**row, "rule_title": title, "rule_current_status": live_status,
            "current_pattern_score": score, "proposed_pattern_score": (score + 1) if score is not None else None,
            "note": LEAD_CAVEAT,
            "match_confidence": ("This lead lexically matches an existing rule for the same fixed behavior; the "
                                 "match itself is exact by fingerprint, but the lead's accuracy is not verified. "
                                 f"The matched rule's current state is: {row['matched_rule_status']} as of when this "
                                 "review was queued.")}


def pending_count(path: Path | None = None):
    store.initialize(path)
    with store.connection(path) as db:
        return db.execute("SELECT COUNT(*) FROM corroboration_reviews WHERE status='pending'").fetchone()[0]


def list_pending(path: Path | None = None, limit=20):
    store.initialize(path)
    with store.connection(path) as db:
        rows = db.execute("SELECT * FROM corroboration_reviews WHERE status='pending' ORDER BY created_at DESC LIMIT ?",
                          (max(1, min(int(limit), 100)),)).fetchall()
    return [_enrich(dict(row), path) for row in rows]


def get_review(review_id, path: Path | None = None):
    with store.connection(path) as db:
        row = db.execute("SELECT * FROM corroboration_reviews WHERE id=?", (review_id,)).fetchone()
    return _enrich(dict(row), path) if row else None


def _existing_source_urls(rule_kind, rule_id, path):
    if rule_kind == "local":
        with store.connection(path) as db:
            rows = db.execute("SELECT e.source_url FROM evidence e JOIN rule_evidence re ON re.evidence_id=e.id "
                              "WHERE re.rule_id=?", (rule_id,)).fetchall()
        return {row["source_url"] for row in rows}
    with store.connection(path) as db:
        row = db.execute("SELECT evidence_ids FROM external_inventory WHERE id=?", (rule_id,)).fetchone()
        if not row:
            return set()
        ids = json.loads(row["evidence_ids"])
        if not ids:
            return set()
        rows = db.execute("SELECT source_url FROM evidence WHERE id IN (" + ",".join("?" for _ in ids) + ")", ids).fetchall()
    return {r["source_url"] for r in rows}


def approve(review_id, approval_phrase, path: Path | None = None):
    """Explicit analyst approval only. Records the lead's own excerpt as the
    evidence claim (the analyst is confirming it by approving, not rewriting
    it), links it to the matched rule, and adds exactly +1. A review that is
    no longer 'pending' -- already approved or rejected, including by a
    second, mirrored review citing the same source -- refuses instead of
    incrementing again.
    """
    if approval_phrase.strip().lower() != "implement this rule":
        raise ValueError("explicit approval phrase 'implement this rule' is required")
    with store.connection(path) as db:
        review = db.execute("SELECT * FROM corroboration_reviews WHERE id=?", (review_id,)).fetchone()
    if not review:
        raise ValueError("unknown corroboration review")
    if review["status"] != "pending":
        raise ValueError(f"review is already {review['status']}; repeated approval does not increment the score again")
    if review["source_url"] in _existing_source_urls(review["rule_kind"], review["rule_id"], path):
        raise ValueError("this source already corroborated this rule (directly or via an earlier review); "
                         "a mirrored or repeated source must not increment the score again")
    claim = f"Corroboration review approved: {review['excerpt']}"[:1000]
    evidence_id = (_custom_observation(review, path) if review["behavior"] == "custom" else
                   core.add_behavior_evidence(review["threat_id"], review["source_url"], claim, review["behavior"], path))
    if review["rule_kind"] == "local":
        result = rules.corroborate_local_rule(review["rule_id"], evidence_id, path)
    else:
        result = rules.acknowledge_existing(review["rule_id"], evidence_id, "implement this rule", path)
    with store.connection(path) as db:
        db.execute("UPDATE corroboration_reviews SET status='approved',decided_at=?,evidence_id=? WHERE id=?",
                   (now(), evidence_id, review_id))
        db.execute("INSERT INTO audit (at,action,target,detail) VALUES (?,?,?,?)",
                   (now(), "corroboration_review_approved", str(review_id),
                    json.dumps({"rule_kind": review["rule_kind"], "rule_id": review["rule_id"],
                               "evidence_id": evidence_id, "pattern_score": result.get("pattern_score")})))
    return {"review_id": review_id, "evidence_id": evidence_id, **result}


def reject(review_id, reason, path: Path | None = None):
    """Leaves the rule, its evidence, and its pattern_score entirely unchanged."""
    if not isinstance(reason, str) or not 5 <= len(reason.strip()) <= 500:
        raise ValueError("a short reason (5-500 characters) is required")
    with store.connection(path) as db:
        review = db.execute("SELECT status FROM corroboration_reviews WHERE id=?", (review_id,)).fetchone()
        if not review:
            raise ValueError("unknown corroboration review")
        if review["status"] != "pending":
            raise ValueError(f"review is already {review['status']}")
        db.execute("UPDATE corroboration_reviews SET status='rejected',decided_at=?,decided_reason=? WHERE id=?",
                   (now(), reason.strip(), review_id))
        db.execute("INSERT INTO audit (at,action,target,detail) VALUES (?,?,?,?)",
                   (now(), "corroboration_review_rejected", str(review_id), json.dumps({"reason": reason.strip()[:200]})))
    return {"review_id": review_id, "status": "rejected", "note": "Rule, evidence, and pattern_score are unchanged."}

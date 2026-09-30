"""A local, Git-ready rule repository on disk.

This writes deterministic JSON snapshots into two folders — `draft/` for
unapproved (draft or rejected) work and `approved/` for explicitly approved
rules — so an analyst can `git init`/`git add`/`git commit` the directory
themselves for review history. Nothing here runs `git` or touches a network;
this module never pushes anywhere and never deploys anything to a SIEM. It
only serializes what core/rules/frameworks/environment already computed and
validated elsewhere.
"""

import hashlib
import json
import os
import re
from pathlib import Path

import yaml

from . import store
from .core import get_threat, now


def repo_dir(path=None, override=None):
    """Default: <database directory>/rule-repository, so every enterprise
    pack (its own database directory) gets its own isolated repository for
    free. RULE_REPOSITORY_DIR overrides this for every database unless a
    caller passes an explicit override."""
    if override:
        return Path(override).expanduser().resolve()
    env = os.environ.get("RULE_REPOSITORY_DIR")
    if env:
        return Path(env).expanduser().resolve()
    return (path or store.db_path()).parent / "rule-repository"


README = """# Local detection rule repository

Generated and updated by ThreatResearch-MCP. This directory is designed to
be committed with `git init` / `git add` / `git commit` by the analyst — no
command in this project runs `git` or pushes anything on your behalf.

- `draft/<rule_id>.json` — unapproved work (draft or rejected). Rejected
  drafts are kept here, not deleted, so they remain available for later
  review.
- `approved/<rule_id>.json` — the snapshot as of explicit analyst approval
  ("Approve and add to rule repository" / `implement_rule`), including its
  full approval history. A file appearing here means it was added to this
  **local** repository only. It was never deployed to a SIEM and never
  pushed to any remote (including GitHub).

Each rule file embeds: its Sigma/KQL/SPL text where generated, source
evidence with publication dates, analyst observations, an inventory
comparison, risk analysis, false positives, current MITRE ATT&CK/ATLAS/OWASP
framework mappings (with each framework's retrieved version and date), any
recorded reproducible test results (`evaluate_synthetic_soc_lab`-style local
reference matching against labeled samples), and its approval history.
"""


def _ensure_dirs(root):
    (root / "draft").mkdir(parents=True, exist_ok=True)
    (root / "approved").mkdir(parents=True, exist_ok=True)
    readme = root / "README.md"
    if not readme.exists():
        readme.write_text(README, encoding="utf-8")
    gitignore = root / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text("# Nothing to ignore by default; this repository is meant to be committed.\n", encoding="utf-8")


def _false_positives(sigma_text):
    if not sigma_text:
        return []
    try:
        parsed = yaml.safe_load(sigma_text)
    except yaml.YAMLError:
        return []
    if isinstance(parsed, dict) and isinstance(parsed.get("falsepositives"), list):
        return [str(x) for x in parsed["falsepositives"]]
    return []


def _approval_history(rule_id, path):
    with store.connection(path) as db:
        rows = db.execute(
            "SELECT at,action,detail FROM audit WHERE target=? AND action IN "
            "('rule_drafted','rule_approved','rule_rejected','rule_reopened',"
            "'external_coverage_corroborated','ioc_rule_drafted','custom_rule_drafted') "
            "ORDER BY at", (rule_id,)).fetchall()
    history = []
    for row in rows:
        try:
            detail = json.loads(row["detail"])
        except (ValueError, TypeError):
            detail = {}
        history.append({"at": row["at"], "action": row["action"], "detail": detail})
    return history


def _test_results(rule_id, path):
    with store.connection(path) as db:
        rows = db.execute("SELECT rule_hash,tested_at,sample_size,counts,cases,sample_source FROM rule_tests "
                          "WHERE rule_id=? ORDER BY tested_at DESC", (rule_id,)).fetchall()
    return [{"rule_hash": r["rule_hash"], "tested_at": r["tested_at"], "sample_size": r["sample_size"],
            "counts": json.loads(r["counts"]), "cases": json.loads(r["cases"]), "sample_source": r["sample_source"],
            "scope": "Local reference matching against labeled samples, not production SIEM accuracy; "
                     "native Splunk/Defender validation remains pending until a customer connects its SIEM."}
            for r in rows]


def snapshot(rule_id, path=None):
    """Build the full JSON-serializable snapshot for one rule. Read-only;
    raises ValueError for an unknown rule, same as the other rule tools."""
    from . import rules as rules_module  # local import: rules imports this module too

    rule = rules_module.get_rule(rule_id, path)
    if not rule:
        raise ValueError("unknown rule")
    threat = get_threat(rule["threat_id"], path)
    try:
        review = rules_module.review_for_client(rule_id, path, update_frameworks=False)
    except ValueError:
        review = None
    behavior_evidence = [e for e in (threat["evidence"] if threat else []) if e["kind"] == "analyst_observation"]
    return {
        "rule_id": rule["id"], "status": rule["status"], "behavior": rule["behavior"],
        "title": rule["title"], "fingerprint": rule["fingerprint"], "created_at": rule["created_at"],
        "expires_at": rule["expires_at"], "pattern_score": rule["pattern_score"],
        "rejected_reason": rule.get("rejected_reason"), "rejected_at": rule.get("rejected_at"),
        "telemetry_required": rule["telemetry"], "rationale": rule["rationale"],
        "detections": {"sigma": rule["sigma"], "kql": rule["kql"], "spl": rule["spl"]},
        "false_positives": _false_positives(rule["sigma"]),
        "source_evidence": [{"evidence_id": e["id"], "source_url": e["source_url"], "claim": e["claim"],
                             "behavior": e.get("behavior")} for e in rule["supporting_evidence"]],
        "threat": {"id": threat["id"], "kind": threat["kind"], "title": threat["title"],
                   "published": threat.get("published"), "first_seen": threat.get("first_seen"),
                   "sources": threat["sources"]} if threat else None,
        "analyst_observations": [{"evidence_id": e["id"], "source_url": e["source_url"], "claim": e["claim"],
                                  "behavior": e["behavior"], "observed_at": e["observed_at"]}
                                 for e in behavior_evidence],
        "inventory_comparison": review["inventory_comparison"] if review else None,
        "risk_analysis": review["environment_risk"] if review else None,
        "framework_mappings": review["framework_context"] if review else None,
        "detection_fit": review["detection_fit"] if review else None,
        "test_results": _test_results(rule_id, path),
        "approval_history": _approval_history(rule_id, path),
        "custom_spec": rule.get("custom_spec"),
        "exported_at": now(),
        "deployment": "not_deployed_to_any_siem; local repository only; never pushed to a remote",
    }


def export_rule(rule_id, path=None, repo_dir_override=None):
    """Write the current snapshot to draft/ (unapproved) or approved/
    (approved), creating the repository layout on first use. Idempotent and
    side-effect-free beyond writing this one file."""
    data = snapshot(rule_id, path)
    root = repo_dir(path, repo_dir_override)
    _ensure_dirs(root)
    folder = "approved" if data["status"] == "approved" else "draft"
    target = root / folder / f"{rule_id}.json"
    target.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"path": str(target), "status": data["status"], "folder": folder}


def list_repository(path=None, repo_dir_override=None):
    """Offline inventory of what's currently on disk; never inspects git."""
    root = repo_dir(path, repo_dir_override)
    result = {"repository": str(root), "draft": [], "approved": []}
    for folder in ("draft", "approved"):
        directory = root / folder
        if directory.is_dir():
            for file in sorted(directory.glob("*.json")):
                try:
                    payload = json.loads(file.read_text(encoding="utf-8"))
                    result[folder].append({"rule_id": payload.get("rule_id", file.stem), "title": payload.get("title"),
                                           "behavior": payload.get("behavior"), "status": payload.get("status")})
                except (ValueError, OSError):
                    result[folder].append({"rule_id": file.stem, "title": None, "behavior": None, "status": "unreadable"})
    return result


def record_test_result(rule_id, replay_result, rule_hash, sample_source, path=None, provenance=None):
    """Persist one reproducible-check run; called by rules.test_rule_against_samples."""
    with store.connection(path) as db:
        row = db.execute("SELECT 1 FROM rules WHERE id=?", (rule_id,)).fetchone()
        if not row:
            raise ValueError("unknown rule")
        db.execute("INSERT INTO rule_tests (rule_id,rule_hash,tested_at,sample_size,counts,cases,sample_source,"
                   "sample_provenance) VALUES (?,?,?,?,?,?,?,?)",
                   (rule_id, rule_hash, now(), replay_result["sample_size"],
                    json.dumps(replay_result["counts"]), json.dumps(replay_result["cases"]), sample_source,
                    provenance))

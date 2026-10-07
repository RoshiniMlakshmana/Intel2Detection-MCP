"""Public GitHub repository updates as attributed research/coverage pointers."""

import hashlib
import os
import re
import urllib.parse
from datetime import datetime, timezone

from .sources import fetch_json
from . import store

# No rule body, third-party detection logic, or IOC file is copied into our store.
REPOSITORIES = (
    ("Unit 42 supporting intel", "PaloAltoNetworks/Unit42-Threat-Intelligence-Article-Information", "", "research_update"),
    ("Volexity public intel", "volexity/threat-intel", "", "research_update"),
    ("Meta threat indicators", "facebook/threat-research", "indicators", "research_update"),
    ("SigmaHQ community rules", "SigmaHQ/sigma", "rules", "community_rule"),
    ("Microsoft Sentinel detections", "Azure/Azure-Sentinel", "Detections", "community_rule"),
)
CVE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
SHA = re.compile(r"^[0-9a-f]{40}$")


def collect_repo(repo, path, kind, since, until=None, fetch=fetch_json, max_pages=2):
    """Collect time-bounded commit subjects, not unreviewed rule contents."""
    if (repo, path, kind) not in ({(r, p, k) for _, r, p, k in REPOSITORIES} | {("Azure/Azure-Sentinel", "Solutions", "community_rule")}):
        raise ValueError("repository is not in the curated catalog")
    until = until or datetime.now(timezone.utc)
    base = f"https://api.github.com/repos/{repo}/commits"
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    output = []
    for page in range(1, max_pages + 1):
        params = {"since": since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "until": until.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "per_page": 100, "page": page}
        if path:
            params["path"] = path
        data = fetch(base + "?" + urllib.parse.urlencode(params), headers=headers)
        if not isinstance(data, list):
            raise ValueError("unexpected GitHub commit response")
        for item in data:
            if not isinstance(item, dict):
                continue
            sha = item.get("sha", "")
            commit = item.get("commit") or {}
            if not isinstance(commit, dict) or not isinstance(sha, str):
                continue
            message = commit.get("message") or ""
            subject = message.splitlines()[0].strip()[:220] if isinstance(message, str) else ""
            stamp = ((commit.get("committer") or {}).get("date") or
                     (commit.get("author") or {}).get("date"))
            if not SHA.fullmatch(sha) or not subject or not isinstance(stamp, str):
                continue
            try:
                published = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
                if published.tzinfo is None:
                    continue
                published = published.astimezone(timezone.utc)
            except ValueError:
                continue
            if not since <= published <= until:
                continue
            ident = "REPO-" + hashlib.sha256(f"{repo}:{sha}".encode()).hexdigest()[:16].upper()
            url = f"https://github.com/{repo}/commit/{sha}"
            output.append({"id": ident, "kind": kind, "title": f"{repo}: {subject}",
                           "summary": ("GitHub commit subject in a curated detection repository. Inspect the linked diff, original report,"
                                       " field mapping and license before considering it as coverage." if kind == "community_rule" else
                                       "GitHub commit subject in a curated threat-research repository. Inspect the linked diff"
                                       " and original report before extracting any IOC or behavior."),
                           "published": published.isoformat().replace("+00:00", "Z"),
                           "updated": published.isoformat().replace("+00:00", "Z"),
                           "affected": [], "source": url,
                           "mentioned_cves": sorted(set(x.upper() for x in CVE.findall(subject)))[:20],
                           "claim": f"{repo} published a commit with this subject. Contents were not analyzed; external rules are not proof of local coverage."})
        if len(data) < 100:
            break
    else:
        raise RuntimeError(f"{repo} exceeded the commit page cap; narrow the collection window")
    return output


def collect_catalog(repo, path, kind, since, until=None, database=None, source_name=None, fetch=fetch_json):
    """Bootstrap community file pointers once, then resume time-bounded commits.

    The tree is pinned to a commit; truncated responses never get checkpointed.
    External pointers are research leads, not imported/deployed coverage.
    """
    store.initialize(database)
    with store.connection(database) as db:
        state = db.execute("SELECT 1 FROM repo_bootstraps WHERE repo=?", (repo,)).fetchone()
    if kind != "community_rule" or state:
        records = collect_repo(repo, path, kind, since, until, fetch=fetch)
        if repo == "Azure/Azure-Sentinel":
            # Modern Sentinel analytic rules live under Solutions as well.
            more = collect_repo(repo, "Solutions", kind, since, until, fetch=fetch)
            records = list({r["id"]: r for r in records + more}.values())
        return records
    if (repo, path, kind) not in {(r, p, k) for _, r, p, k in REPOSITORIES}:
        raise ValueError("repository is not in the curated catalog")
    headers = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["GITHUB_TOKEN"]
    api = "https://api.github.com/repos/" + repo
    info = fetch(api, headers=headers)
    branch = info.get("default_branch") if isinstance(info, dict) else None
    if not isinstance(branch, str) or not branch:
        raise ValueError("GitHub repository response has no default branch")
    commit = fetch(api + "/commits/" + urllib.parse.quote(branch, safe=""), headers=headers)
    sha = commit.get("sha") if isinstance(commit, dict) else None
    if not isinstance(sha, str) or not SHA.fullmatch(sha):
        raise ValueError("invalid GitHub snapshot commit")
    tree_options = {"max_bytes": 32_000_000} if fetch is fetch_json else {}
    tree = fetch(api + "/git/trees/" + sha + "?recursive=1", headers=headers, **tree_options)
    if not isinstance(tree, dict) or tree.get("truncated") is not False or not isinstance(tree.get("tree"), list):
        raise ValueError("GitHub tree missing or truncated; bootstrap was not checkpointed")
    at = (until or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z")
    records = []
    for item in tree["tree"]:
        file = item.get("path", "")
        in_scope = file.startswith(path + "/") or (repo == "Azure/Azure-Sentinel" and
                    file.startswith("Solutions/") and "/Analytic Rules/" in file)
        if item.get("type") != "blob" or not in_scope or not file.lower().endswith((".yml", ".yaml")):
            continue
        ident = "RULEPTR-" + hashlib.sha256((repo + ":" + file + ":" + item["sha"]).encode()).hexdigest()[:16].upper()
        records.append({"id": ident, "kind": kind, "title": (repo + ": " + file)[:300],
                        "summary": "Initial pinned community-rule file index. Fetch and inspect this external rule before comparing predicates; local coverage is unknown.",
                        "published": at, "updated": at, "affected": [],
                        "source": "https://github.com/" + repo + "/blob/" + sha + "/" + urllib.parse.quote(file, safe="/"),
                        "claim": "Community file pointer collected at snapshot time, not its publication date. No rule body was imported or validated.",
                        "reported_by": source_name or ("GitHub: " + repo),
                        "bootstrap_repo": repo, "bootstrap_sha": sha})
    if not records:
        raise ValueError("community repository initial tree has no rules in configured folders")
    # collect_daily checkpoints only after it durably ingests this whole list.
    return records

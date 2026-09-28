"""Public GitHub repository updates as attributed research/coverage pointers."""

import hashlib
import os
import re
import urllib.parse
from datetime import datetime, timezone

from .sources import fetch_json

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
    if (repo, path, kind) not in {(r, p, k) for _, r, p, k in REPOSITORIES}:
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

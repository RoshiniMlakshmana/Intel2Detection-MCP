"""Conservative technical-behavior leads from report paragraphs, never observations."""

import re

NEGATION = re.compile(r"\b(?:no evidence|no signs|did not|was not|not observed|not detected|false positive)\b", re.I)
WEB_PARENT = re.compile(r"\b(?:w3wp|httpd|nginx|apache2)(?:\.exe)?\b", re.I)
SHELL = re.compile(r"\b(?:cmd|powershell|pwsh|sh|bash)(?:\.exe)?\b", re.I)
CHILD_ACTION = re.compile(r"\b(?:spawned|launched|created a child process|started a shell|executed)\b", re.I)
POWERSHELL = re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b", re.I)
ENCODED = re.compile(r"(?:-encodedcommand\b|-enc\b|encoded command)", re.I)
EXECUTE = re.compile(r"\b(?:executed|ran|launched|started)\b", re.I)
DENY = re.compile(r"\b(?:deny|denied|missing|expired)\b", re.I)
TOOL = re.compile(r"\b(?:tool invocation|tool execution|mcp tool)\b", re.I)
SIDELOAD = re.compile(r"\b(?:DLL[ -]?)?side[ -]?load(?:ed|ing|s)?\b", re.I)
LOADER = re.compile(r"\b(?:malware|malicious|loader|downloader|backdoor|implant|threat actor|attacker)\b", re.I)
C2 = re.compile(r"\b(?:C2|command[- ]and[- ]control)\b", re.I)
BEACON = re.compile(r"\b(?:beacon|connect(?:ion|ivity|s|ed)?|communicat(?:ion|es)|request)\b", re.I)
NETWORK = re.compile(r"\b(?:HTTPS?|WebSockets?|domain|host|URL|URI)\b", re.I)


def from_paragraphs(paragraphs, limit=30):
    """Return explicit leads and exact short snippets; analyst must check full context."""
    output = []
    for index, paragraph in enumerate(paragraphs):
        if NEGATION.search(paragraph):
            continue
        found = []
        if WEB_PARENT.search(paragraph) and SHELL.search(paragraph) and CHILD_ACTION.search(paragraph):
            found.append("web_server_shell")
        if POWERSHELL.search(paragraph) and ENCODED.search(paragraph) and EXECUTE.search(paragraph):
            found.append("encoded_powershell")
        if ("authorization" in paragraph.lower() and DENY.search(paragraph) and TOOL.search(paragraph)
                and EXECUTE.search(paragraph)):
            found.append("mcp_unauthorized_execution")
        for behavior in found:
            output.append({"behavior": behavior, "paragraph": index + 1,
                           "excerpt": paragraph[:420], "status": "analyst_review_required",
                           "note": "Lexical lead only; verify actor action, negation, telemetry, and benign context in the full report."})
            if len(output) >= limit:
                return output
    return output


def behavior_patterns(paragraphs, limit=30):
    """Cited behaviors beyond the three rule templates; untrusted research only.

    A behavioral description alone cannot supply the bounded field predicates
    or telemetry needed for a draft. Keep it visible for analyst review without
    putting an unsupported behavior into the rule/corroboration pipeline.
    """
    output = []
    for index, paragraph in enumerate(paragraphs):
        if NEGATION.search(paragraph):
            continue
        kinds = []
        if SIDELOAD.search(paragraph) and LOADER.search(paragraph):
            kinds.append("dll_sideloading")
        if C2.search(paragraph) and BEACON.search(paragraph) and NETWORK.search(paragraph):
            kinds.append("c2_communication")
        for kind in kinds:
            output.append({"behavior": kind, "paragraph": index + 1,
                           "excerpt": paragraph[:700], "status": "unverified_behavior_description",
                           "note": "Publisher's description only. Confirm the full source and measurable fields "
                                   "before proposing a custom detection; no template rule is implied."})
            if len(output) >= limit:
                return output
    return output


# Actor or malicious-artifact context. Malware write-ups describe "the loader"
# or "the sample" rather than an attacker (observed: Microsoft's NeedyMantis
# analysis, whose loader name and SHA-256 were missed with actor words only).
ACTOR = re.compile(r"\b(?:attacker|adversar(?:y|ies)|threat actors?|actors?|MCA|intruders?|operators?|"
                   r"exploit(?:ed|ing|ation)?|malware|malicious|loader|sample|payload|backdoor|implant|"
                   r"dropper|stealer|ransomware|beacon|shellcode|web ?shell|C2|command[- ]and[- ]control)\b", re.I)
HASH = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b", re.I)
# SHA-256/SHA-1 lengths are specific on their own. A 32-hex value is also the
# shape of reporter handles and IDs (observed: Chrome release notes' "Reported
# by c6eed09f..."), so it counts only when labeled as a hash or in context.
STRONG_HASH = re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40})\b", re.I)
HASH_LABEL = re.compile(r"\b(?:md5|sha-?1|sha-?256|hash(?:es)?)\b", re.I)
ARTIFACT = re.compile(
    r"(?:(?<![\w/])/(?:bin|sbin|tmp|var|etc|usr|netscaler|flash|home|opt|dev/shm)/[\w./-]+"
    r"|\b[A-Za-z]:\\[\w\\.-]+"
    r"|[\"'“‘]\.[\w.-]{2,}[\"'”’]"
    r"|\b[\w-]+(?:\.[\w-]+)*\.(?:php|pl|sh|jsp|jspx|aspx?|exe|dll|ps1|py|elf|so|bat|vbs|lnk)\b"
    r"|\b(?:\d{1,3}\.){3}\d{1,3}\b"
    r"|\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b)", re.I)


def specific_details(paragraphs, limit=30):
    """Paragraphs that pair actor activity with a concrete artifact (path, file, IP, hash).

    These are quoted claims to verify against their original publication,
    never indicators: the tokens are returned exactly as written, only so the
    analyst can see why the paragraph was flagged.
    """
    output = []
    for index, paragraph in enumerate(paragraphs):
        # A file hash in a threat report is itself a specific artifact; other
        # tokens (paths, file names, IPs) need actor or malware context.
        labeled = HASH.search(paragraph) and HASH_LABEL.search(paragraph)
        if NEGATION.search(paragraph) or not (ACTOR.search(paragraph) or STRONG_HASH.search(paragraph) or labeled):
            continue
        tokens = list(dict.fromkeys(m.group(0) for m in ARTIFACT.finditer(paragraph)))
        if tokens:
            output.append({"paragraph": index + 1, "excerpt": paragraph[:700], "artifacts_as_written": tokens[:8],
                           "status": "unverified_quoted_claim"})
        if len(output) >= limit:
            break
    return output

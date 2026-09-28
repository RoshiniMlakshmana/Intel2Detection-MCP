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


def from_paragraphs(paragraphs):
    """Return explicit leads and exact short snippets; analyst must check full context."""
    output, seen = [], set()
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
            if behavior not in seen:
                output.append({"behavior": behavior, "paragraph": index + 1,
                               "excerpt": paragraph[:420], "status": "analyst_review_required",
                               "note": "Lexical lead only; verify actor action, negation, telemetry, and benign context in the full report."})
                seen.add(behavior)
    return output

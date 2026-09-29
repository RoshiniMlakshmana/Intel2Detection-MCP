"""Regression test for a real CI failure: every f-string expression part
must be free of backslashes.

PEP 701 (Python 3.12) lifted the restriction that an f-string's `{...}`
expression cannot contain a backslash; on 3.11 and earlier it is a hard
SyntaxError raised at import time -- before any test can even run. This
project declares `requires-python = ">=3.11"` and CI's matrix includes 3.11,
so this must never regress, independent of which interpreter a developer
happens to run locally (this repository's own CI failed on exactly this in
threat_research/dashboard.py, undetected locally because the development
environment used here is Python 3.13).

The scan below is a purely lexical scanner over the raw source text (quote/
escape scanning for the f-string's own delimiter, then brace-depth counting
for `{`/`}`), not an ast-position-based one. That is deliberate: an earlier
version of this test used `ast.get_source_segment()` on each `FormattedValue`
node, and running it in CI under Python 3.11 (not 3.12+) produced false
positives -- on 3.11, the `ast` module reports source spans for expressions
inside f-strings far less precisely than 3.12+ does (PEP 701 rewrote the
f-string parser and gave it exact positions), so the "expression part"
segment it returned sometimes included surrounding literal text with its own,
entirely legal, backslash escapes (e.g. `f"...{x}\\n"` or `f"...(\\"{x}\\"), "`,
where the backslash sits in the literal text, not inside `{}`). That failure
is reproduced and pinned in test_legitimate_backslash_in_literal_text_is_not_flagged
below, so it is never silently reintroduced.
"""

import ast
import re
import sys
import unittest
from pathlib import Path

import threat_research

FSTRING_OPEN = re.compile(r"(?i)\b[rbu]{0,2}f[rbu]{0,2}('''|\"\"\"|'|\")")


def _fstring_spans(src):
    """Yield the raw text of each f-string literal in src (opening prefix
    through its matching closing quote), scanning only for the *outer*
    quote/escape boundary -- nothing inside is interpreted."""
    i, n = 0, len(src)
    while i < n:
        match = FSTRING_OPEN.search(src, i)
        if not match:
            return
        quote = match.group(1)
        j = match.end()
        while j < n:
            if src[j] == "\\":
                j += 2
                continue
            if src.startswith(quote, j):
                j += len(quote)
                yield match.start(), src[match.start():j]
                break
            j += 1
        else:
            return
        i = j


def _backslash_in_expression_part(literal):
    """True if a raw backslash appears at brace-depth > 0 -- i.e. strictly
    inside a `{...}` expression, not the literal text around it. `{{`/`}}`
    are literal-brace escapes and never open/close an expression."""
    depth = 0
    k, n = 0, len(literal)
    while k < n:
        ch = literal[k]
        if ch == "{":
            if depth == 0 and k + 1 < n and literal[k + 1] == "{":
                k += 2
                continue
            depth += 1
        elif ch == "}":
            if depth == 0 and k + 1 < n and literal[k + 1] == "}":
                k += 2
                continue
            depth = max(0, depth - 1)
        elif ch == "\\" and depth > 0:
            return True
        k += 1
    return False


def _violations(path):
    src = path.read_text(encoding="utf-8")
    ast.parse(src, filename=str(path))  # still a real syntax check, on whatever interpreter runs this
    found = []
    for start, literal in _fstring_spans(src):
        if _backslash_in_expression_part(literal):
            line = src.count("\n", 0, start) + 1
            found.append((path.name, line, literal[:160]))
    return found


class Python311CompatTest(unittest.TestCase):
    def test_no_backslash_inside_any_fstring_expression(self):
        package_dir = Path(threat_research.__file__).parent
        modules = sorted(package_dir.glob("*.py"))
        self.assertGreater(len(modules), 10)  # sanity: the scan actually covered the package
        violations = []
        for module in modules:
            violations.extend(_violations(module))
        self.assertEqual(violations, [],
                         "Backslash inside an f-string expression part is a SyntaxError on Python < 3.12 "
                         "(PEP 701 only relaxed this in 3.12); this project supports 3.11+. "
                         f"Found: {violations}")

    def test_detector_flags_the_exact_shape_that_broke_ci(self):
        broken = 'x = f\'<a href="{href}"{" style=\\"color:red\\"" if href == active else ""}>{label}</a>\''
        spans = list(_fstring_spans(broken))
        self.assertEqual(len(spans), 1)
        self.assertTrue(_backslash_in_expression_part(spans[0][1]),
                        "detector must flag the exact pattern that broke Python 3.11 CI")
        if sys.version_info < (3, 12):
            with self.assertRaises(SyntaxError):
                compile(broken, "<broken-fixture>", "exec")

    def test_legitimate_backslash_in_literal_text_is_not_flagged(self):
        """The false positives actually seen in CI under Python 3.11 with the
        prior ast-based detector: a backslash in the f-string's literal text
        (outside {}), which is legal on every Python version. Guards against
        reintroducing that specific regression in the detector itself."""
        legit_samples = [
            'f"| where RemoteIP == \'{address}\' and RemotePort == {port}\\n"',
            'f"index={config[\'index\']} sourcetype={config[\'sourcetype\']}\\n| where "',
            'f"Checked against the declared complete inventory (\\"{declaration[\'scope\']}\\"), "',
        ]
        for sample in legit_samples:
            spans = list(_fstring_spans(sample))
            self.assertEqual(len(spans), 1, sample)
            self.assertFalse(_backslash_in_expression_part(spans[0][1]), sample)
            ast.parse(sample)  # also confirm it is simply valid Python


if __name__ == "__main__":
    unittest.main()

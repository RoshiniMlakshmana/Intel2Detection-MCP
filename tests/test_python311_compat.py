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

This check does not need a 3.11 interpreter: it walks the AST of every
shipped module and inspects each JoinedStr's FormattedValue source segments
directly, which is exactly what the 3.11 parser itself would reject.
"""

import ast
import sys
import unittest
from pathlib import Path

import threat_research


def _fstring_backslash_violations(path):
    src = path.read_text(encoding="utf-8")
    tree = ast.parse(src, filename=str(path))
    violations = []
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr):
            for value in node.values:
                if isinstance(value, ast.FormattedValue):
                    segment = ast.get_source_segment(src, value)
                    if segment and "\\" in segment:
                        violations.append((path.name, value.lineno, segment[:160]))
    return violations


class Python311CompatTest(unittest.TestCase):
    def test_no_backslash_inside_any_fstring_expression(self):
        package_dir = Path(threat_research.__file__).parent
        modules = sorted(package_dir.glob("*.py"))
        self.assertGreater(len(modules), 10)  # sanity: the scan actually covered the package
        violations = []
        for module in modules:
            violations.extend(_fstring_backslash_violations(module))
        self.assertEqual(violations, [],
                         "Backslash inside an f-string expression part is a SyntaxError on Python < 3.12 "
                         "(PEP 701 only relaxed this in 3.12); this project supports 3.11+. "
                         f"Found: {violations}")

    def test_regression_fixture_the_exact_shape_that_broke_ci(self):
        """The literal pattern that failed CI on Python 3.11/dashboard.py:110
        (an inline conditional style attribute built with escaped quotes
        inside the {...} of an f-string). Confirms the detector used above
        actually flags this shape, not just that today's source is clean."""
        broken = 'f\'<a href="{href}"{" style=\\"color:red\\"" if href == active else ""}>{label}</a>\''
        tree = ast.parse(broken)
        joined = tree.body[0].value
        self.assertIsInstance(joined, ast.JoinedStr)
        found = any("\\" in (ast.get_source_segment(broken, v) or "")
                    for v in joined.values if isinstance(v, ast.FormattedValue))
        self.assertTrue(found, "detector must flag the exact pattern that broke Python 3.11 CI")
        if sys.version_info < (3, 12):
            with self.assertRaises(SyntaxError):
                compile(broken, "<broken-fixture>", "eval")


if __name__ == "__main__":
    unittest.main()

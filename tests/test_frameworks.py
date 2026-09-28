import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import yaml

from threat_research import core, frameworks, rules, store


class FrameworkTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "test.sqlite3"
        store.initialize(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_owasp_2026_table_of_contents_extraction(self):
        titles = ["Prompt Injection", "Sensitive Information Disclosure", "Excessive Agency", "Supply Chain",
                  "Data and Model Poisoning", "Unbounded Consumption", "Misinformation", "Hidden Context Exposure",
                  "Vector and Embedding Weaknesses", "Improper Output Handling"]
        class Page:
            def extract_text(self):
                return "\n".join(f"LLM{i:02d}:2026 {title} {i + 9}" for i, title in enumerate(titles, 1))
        with patch.object(frameworks, "PdfReader", return_value=type("Reader", (), {"pages": [Page()]})()):
            version, entries = frameworks._parse_owasp(b"fixture", 2026)
        self.assertEqual(version, "2026")
        self.assertEqual(entries["LLM03"]["name"], "Excessive Agency")
        self.assertEqual(len(entries), 10)

    def test_refresh_cites_validated_ids_and_never_claims_unavailable_map(self):
        attack = {"objects": [{"type": "attack-pattern", "name": "PowerShell", "description": "Run scripts.",
                               "external_references": [{"source_name": "mitre-attack", "external_id": f"T{i:04d}",
                                                        "url": "https://attack.mitre.org/techniques/"}]}
                              for i in range(1000, 1101)]}
        attack["objects"].append({"type": "attack-pattern", "name": "PowerShell", "description": "Run scripts.",
                                  "external_references": [{"source_name": "mitre-attack", "external_id": "T1059.001",
                                                           "url": "https://attack.mitre.org/techniques/T1059/001/"}]})
        atlas = {"collection": {"version": "2026.08"}, "techniques": {
            f"AML.T{i:04d}": {"name": "Synthetic technique", "description": "Fixture"} for i in range(1, 24)}}
        atlas["techniques"]["AML.T0053"] = {"name": "AI Agent Tool Invocation", "description": "Tool execution"}
        home = b'<a href="/resource/owasp-genai-llm-top-10-2026/">2026 release</a>'
        release = b'<a href="https://genai.owasp.org/download/123/">Download</a>'
        fetches = []

        def fetch(url, limit):
            fetches.append(url)
            if url == frameworks.ATTACK_INDEX:
                return b"Enterprise ATT&CK v19.2 enterprise-attack-19.2.json"
            if url == frameworks.ATTACK_PREFIX + "19.2.json":
                return json.dumps(attack).encode()
            if url == frameworks.ATLAS_URL:
                return yaml.safe_dump(atlas).encode()
            if url == frameworks.OWASP_HOME:
                return home
            if url.endswith("/resource/owasp-genai-llm-top-10-2026/"):
                return release
            return b"fixture-pdf"

        with patch.object(frameworks, "_parse_owasp", return_value=("2026", {
            f"LLM{i:02d}": {"id": f"LLM{i:02d}:2026", "name": "Excessive Agency" if i == 3 else "Fixture",
                           "url": "https://genai.owasp.org/"} for i in range(1, 11)})):
            first = frameworks.refresh(self.path, fetch=fetch)
            self.assertEqual(first["errors"], {})
            self.assertEqual(frameworks.refresh(self.path, fetch=fetch)["sources"]["atlas"]["status"], "cached")
        self.assertEqual(len(fetches), 6)
        self.assertEqual(frameworks.status(self.path)["attack"]["version"], "19.2")
        reference = frameworks.retrieve("mcp_unauthorized_execution", self.path, update=False)
        self.assertEqual(reference["mappings"]["atlas"][0]["id"], "AML.T0053")
        self.assertEqual(reference["mappings"]["owasp"][0]["id"], "LLM03:2026")
        self.assertEqual(reference["frameworks"]["owasp"]["version"], "2026")
        candidates = frameworks.search("AI Agent Tool Invocation", self.path, update=False)
        self.assertEqual(candidates["candidates"]["atlas"][0]["id"], "AML.T0053")

        with store.connection(self.path) as db:
            db.execute("UPDATE framework_snapshots SET fetched_at=? WHERE name='atlas'",
                       ((datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),))
        self.assertEqual(frameworks.status(self.path)["atlas"]["status"], "stale")
        failed = frameworks.refresh(self.path, fetch=lambda url, limit: (_ for _ in ()).throw(OSError("offline")))
        self.assertEqual(failed["sources"]["atlas"]["status"], "stale")
        self.assertEqual(frameworks.status(self.path)["atlas"]["status"], "stale")

    def test_client_review_joins_rule_inventory_risk_and_framework_state(self):
        core.ingest([{"id": "CVE-2099-55555", "title": "Fictional CVE", "summary": "Fixture",
                      "source": "https://example.org/cve", "claim": "A fictional vulnerability."}], self.path)
        observed = core.add_behavior_evidence("CVE-2099-55555", "https://example.org/report",
                                              "Observed PowerShell encoded command", "encoded_powershell", self.path)
        proposal = rules.propose_rule("CVE-2099-55555", observed, self.path)
        review = rules.review_for_client(proposal["rule_id"], self.path, update_frameworks=False)
        self.assertEqual(review["environment_risk"]["score"], None)
        self.assertEqual(review["framework_context"]["frameworks"]["attack"]["status"], "unavailable")
        self.assertEqual(review["deployment"], "review_only_not_deployed")
        self.assertEqual(review["inventory_comparison"]["analyst_mapped_external_coverage"], [])


if __name__ == "__main__":
    unittest.main()

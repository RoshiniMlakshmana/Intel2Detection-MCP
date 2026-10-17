"""Intelligence-first branch validates exact observed IOCs and preserves research queue."""
import tempfile
import unittest
from unittest.mock import patch
from scripts import intelligence_first
from pathlib import Path

from threat_research import core, intelligence_router as route

class IntelligenceRouterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "iocs.sqlite3"
        self.src = "https://threatfox.abuse.ch/browse/"
        core.ingest([
            {"id":"IOC-EXAMPLE-IP","title":"Known IP","source":self.src,"kind":"ioc",
             "indicator":"8.8.4.4","indicator_type":"ip","confidence":95},
            {"id":"IOC-EXAMPLE-SHA","title":"Known hash","source":self.src,"kind":"ioc",
             "indicator":"a"*64,"indicator_type":"sha256","confidence":95},
            {"id":"IOC-EXAMPLE-PORT","title":"Known socket","source":self.src,"kind":"ioc",
             "indicator":"203.0.113.4:443","indicator_type":"ip:port","confidence":90},
            {"id":"CVE-2099-9999","title":"Research required","source":self.src,
             "kind":"advisory"}], self.db)
    def test_exact_ip_match_has_provenance_but_not_compromise_claim(self):
        r=route.classify_event({"DestinationIp":"8.8.4.4"}, self.db)
        self.assertEqual(r["status"], "known_intelligence_match")
        self.assertEqual(len(r["matches"]),1)
        self.assertEqual(r["matches"][0]["threat_id"],"IOC-EXAMPLE-IP")
        self.assertEqual(r["matches"][0]["sources"],[self.src])
        self.assertFalse(r["compromise_confirmed"])
        self.assertFalse(r["rules_auto_approved"])
    def test_hash_needs_exact_full_value(self):
        r=route.classify_event({"SHA256":"A"*64},self.db)
        self.assertEqual(len(r["matches"]),1)
        self.assertEqual(r["matches"][0]["threat_id"],"IOC-EXAMPLE-SHA")
        self.assertEqual(route.classify_event({"SHA256":"A"*63},self.db)["matches"],[])
    def test_port_must_match_both_values(self):
        self.assertEqual(route.classify_event(
            {"DestinationIp":"203.0.113.4","DestinationPort":80},self.db)["matches"],[])
        self.assertEqual(len(route.classify_event(
            {"DestinationIp":"203.0.113.4","DestinationPort":443},self.db)["matches"]),1)
    def test_no_match_routes_to_source_backed_research(self):
        self.assertEqual(route.classify_event({"Image":"powershell.exe"},self.db)["status"],
                         "no_known_indicator_match")
        p=route.route("CVE-2099-9999",self.db)
        self.assertEqual(p["path"],"behavior_research")
        self.assertFalse(p["automatic_approval"])
    def test_cli_dispatches_real_research_pipeline_when_requested(self):
        with patch('threat_research.research_pass.run_pass',return_value={\"drafts_created\":1,\"results\":[]}) as mock:
            self.assertEqual(intelligence_first.main([\"--database\",str(self.db),\"--threat-id\",\"CVE-2099-9999\",\"--run-research\"]),0)
            self.assertEqual(mock.call_args.kwargs['threat_ids'],[\"CVE-2099-9999\"])
    def test_ioc_routes_to_matching(self):
        self.assertEqual(route.route("IOC-EXAMPLE-IP",self.db)["path"],"known_indicator")

if __name__=="__main__":
    unittest.main()

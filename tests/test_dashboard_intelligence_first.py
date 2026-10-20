"""Dashboard known-IOC lookup only, using fictional source data."""
import tempfile
import unittest
from pathlib import Path
from threat_research import core, dashboard

class KnownIOCPageTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/"ioc.sqlite3"
        core.ingest([
            {"id":"IOC-C2-FICTIONAL","title":"Example C2 IOC","kind":"ioc","indicator":"198.51.100.23:443",
             "indicator_type":"ip:port","confidence":91,"source":"https://example.test/intel/1"},
            {"id":"REPORT-FICTIONAL","title":"Reported threat needing research","kind":"campaign",
             "source":"https://example.test/report"}
        ],self.db)
    def test_matching_ip_and_port_is_visible_with_source(self):
        page=dashboard.render_indicator_check(self.db,{"DestinationIp":["198.51.100.23"],"DestinationPort":["443"]})
        self.assertIn("Known intelligence indicator match",page)
        self.assertIn("IOC-C2-FICTIONAL",page)
        self.assertIn("https://example.test/intel/1",page)
        self.assertIn("not confirmation of an incident",page)
    def test_wrong_port_shows_no_match(self):
        page=dashboard.render_indicator_check(self.db,{"DestinationIp":["198.51.100.23"],"DestinationPort":["22"]})
        self.assertIn("No known indicator match",page)
    def test_invalid_input_rejected(self):
        with self.assertRaises(ValueError):
            dashboard.render_indicator_check(self.db,{"DestinationIp":["x"*513]})
        with self.assertRaises(ValueError):
            dashboard.render_indicator_check(self.db,{"DestinationPort":["443"]})
        with self.assertRaises(ValueError):
            dashboard.render_indicator_check(self.db,{"Url":["abc"],"SHA256":["b"*64]})
    def test_reflective_html_is_escaped(self):
        page=dashboard.render_indicator_check(self.db,{"DestinationHostname":["<script>bad()</script>"]})
        self.assertNotIn("<script>",page)
        self.assertIn("&lt;script&gt;",page)
    def test_threat_page_shows_research_route(self):
        page=dashboard.render_threat("REPORT-FICTIONAL",self.db)
        self.assertIn("behavior_research",page)
        self.assertIn("/indicator-check",page)

if __name__=="__main__":
    unittest.main()

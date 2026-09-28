import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from threat_research import doctor, enterprise


class InstallationTest(unittest.TestCase):
    def test_research_only_install_and_unmapped_team_pack(self):
        with tempfile.TemporaryDirectory() as folder:
            database = Path(folder) / "research.sqlite3"
            pack = Path(folder) / "team"
            enterprise.create_pack(pack, "Research Team", "generic")
            with patch.dict(os.environ, {"THREAT_RESEARCH_DB": str(database)}, clear=False), \
                 patch("threat_research.doctor.importlib.util.find_spec", return_value=object()):
                standalone = doctor.check()
                team = doctor.check(pack)
            self.assertEqual(standalone["status"], "ready_for_research")
            self.assertEqual(standalone["database_check"], "ok")
            self.assertEqual(team["status"], "ready_for_research")
            self.assertFalse(team["environment_pack"]["ready_to_onboard"])
            self.assertFalse(team["environment_loaded"]["configured"])
            self.assertTrue(team["warnings"])

    def test_bad_schedule_is_visible_before_running_worker(self):
        with tempfile.TemporaryDirectory() as folder:
            with patch.dict(os.environ, {"THREAT_RESEARCH_DB": str(Path(folder) / "db.sqlite3"),
                                      "DIGEST_TZ": "Invalid/Timezone", "DIGEST_TIME": "27:81",
                                      "POLL_INTERVAL_MINUTES": "2"}, clear=False), \
                 patch("threat_research.doctor.importlib.util.find_spec", return_value=object()):
                result = doctor.check()
            self.assertEqual(result["status"], "fix_setup_errors")
            self.assertTrue(any("DIGEST_TZ" in error for error in result["errors"]))
            self.assertTrue(any("POLL_INTERVAL_MINUTES" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()

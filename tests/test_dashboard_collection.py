"""Collect now responds immediately and reports a finished poll in the browser."""

import http.client
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from threat_research import dashboard, poller, sources, store, workflow


class DashboardCollectionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "intel.sqlite3"
        self.server, self.stop_event = dashboard.serve(host="127.0.0.1", port=0, path=self.path,
                                                        auto_refresh=False, block=False)
        self.port = self.server.server_address[1]
        self.release = threading.Event()

    def tearDown(self):
        self.release.set()
        dashboard.stop(self.server, self.stop_event)
        self.tmp.cleanup()

    def request(self, method, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request(method, path)
        response = conn.getresponse()
        payload = response.read().decode("utf-8")
        result = response.status, response.getheader("Location"), payload
        conn.close()
        return result

    def wait_for_finish(self):
        for _ in range(100):
            status, _, body = self.request("GET", "/api/collection")
            self.assertEqual(status, 200)
            result = json.loads(body)
            if not result["running"]:
                return result
            time.sleep(0.02)
        self.fail("collection did not finish")

    def test_click_is_fast_shows_status_and_does_not_start_twice(self):
        calls = []

        def slow_poll(path):
            calls.append(path)
            self.assertTrue(self.release.wait(5))
            return {"status": "degraded", "new_records": 120}

        with patch.object(dashboard.poller, "run_poll", side_effect=slow_poll):
            start = time.monotonic()
            status, location, _ = self.request("POST", "/collect-now")
            self.assertLess(time.monotonic() - start, 1.0)
            self.assertEqual(status, 303)
            self.assertIn("collecting=1", location)
            _, _, page = self.request("GET", "/?collecting=1")
            self.assertIn("this page will update when finished", page)
            self.assertIn("/api/collection", page)
            self.assertTrue(json.loads(self.request("GET", "/api/collection")[2])["running"])
            _, second_location, _ = self.request("POST", "/collect-now")
            self.assertIn("already%20running", second_location)
            self.assertEqual(len(calls), 1)
            self.release.set()
            result = self.wait_for_finish()

        self.assertEqual((result["status"], result["new_records"]), ("degraded", 120))

    def test_background_exception_is_visible(self):
        def failed_poll(path):
            self.release.wait(5)
            raise RuntimeError("fictional feed error")

        with patch.object(dashboard.poller, "run_poll", side_effect=failed_poll):
            self.assertEqual(self.request("POST", "/collect-now")[0], 303)
            self.release.set()
            result = self.wait_for_finish()
        self.assertEqual(result["status"], "failed")
        self.assertIn("fictional feed error", result["error"])

    def test_another_worker_is_not_started_twice(self):
        with store.connection(self.path) as db:
            db.execute("INSERT INTO poll_state(id,lease_until,last_started) VALUES (1,?,?)",
                       ("2099-01-01T00:00:00Z", "2026-10-01T04:00:00Z"))
        with patch.object(dashboard.poller, "run_poll") as run:
            status, location, _ = self.request("POST", "/collect-now")
            self.assertEqual(status, 303)
            self.assertIn("already%20running", location)
            self.assertTrue(json.loads(self.request("GET", "/api/collection")[2])["running"])
            run.assert_not_called()
        with store.connection(self.path) as db:
            db.execute("UPDATE poll_state SET lease_until=NULL,last_completed=?,last_result=? WHERE id=1",
                       ("2026-10-01T04:02:00Z", json.dumps({"status": "collected", "new_records": 3})))
        result = json.loads(self.request("GET", "/api/collection")[2])
        self.assertEqual((result["running"], result["new_records"]), (False, 3))

    def test_real_poll_updates_database_after_fast_redirect(self):
        real_poll = poller.run_poll
        record = {"id": "CVE-2099-70001", "title": "Fictional advisory", "summary": "Synthetic fixture.",
                  "source": "https://example.test/advisory", "claim": "Fictional feed entry.",
                  "published": "2099-01-01"}
        with patch.object(sources, "enrich_epss", return_value={}), patch.object(
                dashboard.poller, "run_poll", side_effect=lambda path: real_poll(
                    path, adapters={"CISA KEV": lambda: [record]})):
            self.assertEqual(self.request("POST", "/collect-now")[0], 303)
            result = self.wait_for_finish()
        self.assertEqual((result["status"], result["new_records"]), ("collected", 1))
        self.assertEqual(workflow.list_leads(self.path, source="CISA KEV")["total"], 1)


if __name__ == "__main__":
    unittest.main()

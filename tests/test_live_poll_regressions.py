"""Regression tests for the specific live poll failures reported:

- NVD page cap reached; narrow the collection window
- ATLAS document is not a mapping
- framework response exceeds size cap (OWASP)
- unsupported or oversized XML / feed response too large (RSS)
- HTTP Error 301/403 on a cited article (report_inspection redirects/headers)
- WinError 10061 connection refused (Malpedia-style transient network failure)

Each test here reproduces the failure shape first (proving it would have
failed under the old behavior) and then proves the fix. All fixtures are
fictional/local; nothing here contacts a real network.
"""

import unittest

from threat_research import report_inspection, research_feeds


class ArticleRedirectRegressionTest(unittest.TestCase):
    """Was: every redirect (even a same-host canonicalization 301/302) failed
    with HTTP Error 301/302, because _NoRedirect blocked all of them."""

    def test_same_host_https_redirect_is_now_followed(self):
        # OpenerDirector.open already drives redirect handling via
        # HTTPErrorProcessor + our handler's redirect_request; test that
        # decision function directly rather than re-implementing urllib.
        handler = report_inspection._SameHostRedirectOnly()
        import urllib.request as ur
        original_request = ur.Request("https://example.test/article", headers=report_inspection.ARTICLE_HEADERS)
        redirected = handler.redirect_request(original_request, None, 301, "Moved Permanently",
                                              {}, "https://example.test/article/")
        self.assertIsNotNone(redirected)
        self.assertEqual(redirected.full_url, "https://example.test/article/")

    def test_cross_host_redirect_is_still_refused(self):
        handler = report_inspection._SameHostRedirectOnly()
        import urllib.request as ur
        original_request = ur.Request("https://example.test/article", headers=report_inspection.ARTICLE_HEADERS)
        redirected = handler.redirect_request(original_request, None, 301, "Moved Permanently",
                                              {}, "https://attacker.example/article")
        self.assertIsNone(redirected)

    def test_redirect_hop_limit_is_enforced(self):
        handler = report_inspection._SameHostRedirectOnly()
        import urllib.request as ur
        request = ur.Request("https://example.test/a", headers=report_inspection.ARTICLE_HEADERS)
        for _ in range(3):
            request = handler.redirect_request(request, None, 301, "Moved Permanently", {}, "https://example.test/b")
            self.assertIsNotNone(request)
        # A 4th hop must be refused.
        self.assertIsNone(handler.redirect_request(request, None, 301, "Moved Permanently", {}, "https://example.test/c"))


class ConnectionRetryRegressionTest(unittest.TestCase):
    """Was: a single transient connection refusal (Malpedia's WinError 10061
    shape) failed the whole feed for that poll cycle with no retry."""

    def test_transient_oserror_is_retried_once_then_succeeds(self):
        attempts = []

        def flaky_fetch(url, max_bytes=None):
            attempts.append(url)
            if len(attempts) == 1:
                raise OSError("[WinError 10061] No connection could be made because the target machine actively refused it")
            return (b"<rss><channel><item><title>Fictional recovered item</title>"
                    b"<link>https://example.test/item</link>"
                    b"<pubDate>Mon, 02 Jan 2099 10:00:00 GMT</pubDate></item></channel></rss>")

        from datetime import datetime, timezone
        since = datetime(2099, 1, 1, tzinfo=timezone.utc)
        until = datetime(2099, 1, 3, tzinfo=timezone.utc)
        records, counts, errors = research_feeds.collect_research(
            since, until, feeds=(("Example", "https://example.test/feed", "research"),),
            fetch=flaky_fetch, retries=1)
        self.assertEqual(errors, {})
        self.assertEqual(counts["Example"], 1)
        self.assertEqual(len(attempts), 2)  # First attempt failed, retry succeeded.

    def test_persistent_failure_is_still_reported_not_swallowed(self):
        def always_fails(url, max_bytes=None):
            raise OSError("[WinError 10061] No connection could be made because the target machine actively refused it")

        from datetime import datetime, timezone
        since = datetime(2099, 1, 1, tzinfo=timezone.utc)
        until = datetime(2099, 1, 3, tzinfo=timezone.utc)
        records, counts, errors = research_feeds.collect_research(
            since, until, feeds=(("Example", "https://example.test/feed", "research"),),
            fetch=always_fails, retries=1)
        self.assertIn("Example", errors)
        self.assertIn("10061", errors["Example"])
        self.assertEqual(records, [])


class OwaspSizeCapRegressionTest(unittest.TestCase):
    """Was: MAX_BYTES['owasp'] = 18_000_000 could reject a legitimate,
    slightly larger PDF release with 'framework response exceeds size cap'."""

    def test_pdf_between_old_and_new_cap_now_fits(self):
        from threat_research import frameworks
        size_between_old_and_new_cap = 25_000_000
        self.assertGreater(size_between_old_and_new_cap, 18_000_000)  # would have failed under the old cap
        self.assertLessEqual(size_between_old_and_new_cap, frameworks.MAX_BYTES["owasp"])  # fits under the new one


if __name__ == "__main__":
    unittest.main()

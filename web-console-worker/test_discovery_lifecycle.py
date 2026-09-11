"""Discovery pending work belongs to the document that started it."""
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import browser_worker as w


class Request:
    def __init__(self, frame, url, navigation=False):
        self.frame, self.url, self.navigation = frame, url, navigation

    def is_navigation_request(self):
        return self.navigation


class DiscoveryLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.probe = w.Discovery("https://console.test/start")
        self.main = SimpleNamespace(url="https://console.test/start", parent_frame=None)
        self.probe.page = SimpleNamespace(main_frame=self.main)

    def test_navigation_releases_abandoned_fetch_but_keeps_new_document_pending(self):
        bootstrap = Request(self.main, "https://console.test/bootstrap?private=test")
        self.probe.request_started(bootstrap)
        navigation = Request(self.main, "https://sso.test/login", True)
        self.probe.request_started(navigation)
        self.main.url = navigation.url
        self.probe.frame_navigated(self.main)
        self.assertNotIn(bootstrap, self.probe.pending_requests)
        self.assertIn(navigation, self.probe.pending_requests)
        self.probe.request_finished(navigation)
        self.assertFalse(self.probe.pending_requests)
        with patch.object(w.time, "monotonic", return_value=self.probe.settled + 30):
            previous = self.probe.settled
            self.probe.request_finished(bootstrap)
            self.assertEqual(self.probe.settled, previous)
        self.assertNotIn("private", str(self.probe.result()))

    def test_frame_navigation_does_not_discard_work_in_other_documents(self):
        child = SimpleNamespace(url="https://frame.test/start", parent_frame=self.main)
        grandchild = SimpleNamespace(url="https://nested.test/start", parent_frame=child)
        sibling = SimpleNamespace(url="https://sibling.test/start", parent_frame=self.main)
        old = Request(child, "https://frame.test/bootstrap")
        nested = Request(grandchild, "https://nested.test/pending")
        parent = Request(self.main, "https://console.test/pending")
        other = Request(sibling, "https://sibling.test/pending")
        navigation = Request(child, "https://frame.test/login", True)
        for request in (old, nested, parent, other, navigation):
            self.probe.request_started(request)
        child.url = navigation.url
        self.probe.frame_navigated(child)
        self.assertEqual(set(self.probe.pending_requests), {parent, other, navigation})

    def test_main_navigation_releases_replaced_iframe_work(self):
        child = SimpleNamespace(url="https://frame.test/start", parent_frame=self.main)
        pending = Request(child, "https://frame.test/long-fetch")
        self.probe.request_started(pending)
        self.main.url = "https://console.test/final"
        navigation = Request(self.main, self.main.url, True)
        self.probe.request_started(navigation)
        self.probe.frame_navigated(self.main)
        self.assertEqual(set(self.probe.pending_requests), {navigation})

    def test_live_document_slow_fetch_remains_pending(self):
        pending = Request(self.main, "https://console.test/slow-bootstrap")
        self.probe.request_started(pending)
        with patch.object(w.time, "monotonic", return_value=self.probe.settled + 30):
            self.assertIn(pending, self.probe.pending_requests)
        self.probe.request_finished(pending)
        self.assertFalse(self.probe.pending_requests)

    def test_hash_navigation_preserves_current_document_pending_fetch(self):
        navigation = Request(self.main, self.main.url, True)
        self.probe.request_started(navigation)
        self.probe.frame_navigated(self.main)
        pending = Request(self.main, "https://console.test/slow-bootstrap")
        self.probe.request_started(pending)
        self.main.url += "#login"
        self.probe.frame_navigated(self.main)
        self.assertIn(pending, self.probe.pending_requests)
        self.probe.request_finished(navigation)
        self.main.url += "-next"
        self.probe.frame_navigated(self.main)
        self.assertIn(pending, self.probe.pending_requests)


if __name__ == "__main__":
    unittest.main()

"""Web recording gate distinguishes storage failure from the first-frame wait."""
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

import test_classification  # Existing isolated API fixture, never deployment DB.
from app import main as m
from app.web_sessions import WebSessionError


class WebRecordingProbeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name) / "recordings"
        self.session_id = str(uuid.uuid4())
        self.enterContext(patch.object(m.settings, "recording_root", str(self.root)))

    def test_missing_or_invalid_mount_fails_instead_of_waiting_for_frames(self):
        self.assertEqual(m.recording_probe(self.session_id), ([], "root_missing"))
        with self.assertRaisesRegex(WebSessionError, "^recording-root-missing$"):
            m.web_recording_file(self.session_id)
        self.root.write_bytes(b"not-a-directory")
        self.assertEqual(m.recording_probe(self.session_id), ([], "root_invalid"))
        with self.assertRaisesRegex(WebSessionError, "^recording-root-invalid$"):
            m.web_recording_file(self.session_id)

    def test_unreadable_mount_is_not_reported_as_pending_recording(self):
        self.root.mkdir()
        for error, status in ((PermissionError("private mount"), "permission_denied"),
                              (OSError("unavailable mount"), "root_unreadable")):
            with self.subTest(status=status), patch.object(Path, "iterdir", side_effect=error):
                self.assertEqual(m.recording_probe(self.session_id), ([], status))
                with self.assertRaisesRegex(WebSessionError, "^recording-" + status.replace("_", "-") + "$"):
                    m.web_recording_file(self.session_id)

    def test_initial_empty_file_waits_then_exact_recording_becomes_available(self):
        self.root.mkdir()
        self.assertEqual(m.recording_probe(self.session_id), ([], "not_found"))
        self.assertIsNone(m.web_recording_file(self.session_id))
        path = self.root / (self.session_id + ".guac")
        path.touch()
        self.assertEqual(m.recording_probe(self.session_id), ([], "empty"))
        self.assertIsNone(m.web_recording_file(self.session_id))
        path.write_bytes(b"recorded-frame")
        # A typescript is not the graphical recording which opens the web gate.
        (self.root / (self.session_id + ".typescript")).write_bytes(b"typed-data")
        self.assertEqual(m.web_recording_file(self.session_id), path.resolve())

    def test_invalid_identifier_never_probes_a_path(self):
        with patch.object(Path, "resolve") as resolve:
            with self.assertRaisesRegex(WebSessionError, "^recording-invalid-session$"):
                m.web_recording_file("../other-session")
            resolve.assert_not_called()

"""Readiness checks only read the exact temporary marker from a shared mount."""
import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("verify_recording_storage", Path(__file__).resolve().parents[2] / "deploy" / "verify-recording-storage.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class RecordingStorageReadinessTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.name = ".operation-portal-storage.a123B456c789"

    def test_matching_marker_is_read_without_mutating_other_recordings(self):
        marker = self.root / self.name
        marker.write_bytes(probe.MARKER)
        recording = self.root / "existing.guac"
        recording.write_bytes(b"existing-recording-must-not-change")
        probe.verify_recording_storage(self.name, self.root)
        self.assertEqual(marker.read_bytes(), probe.MARKER)
        self.assertEqual(recording.read_bytes(), b"existing-recording-must-not-change")

    def test_wrong_mount_or_partial_marker_cannot_pass(self):
        with self.assertRaises(ValueError):
            probe.verify_recording_storage(self.name, self.root)
        marker = self.root / self.name
        for contents in (b"", probe.MARKER[:-1], probe.MARKER + b"unexpected"):
            with self.subTest(contents=contents):
                marker.write_bytes(contents)
                with self.assertRaises(ValueError):
                    probe.verify_recording_storage(self.name, self.root)

    def test_directory_read_permission_is_required(self):
        (self.root / self.name).write_bytes(probe.MARKER)
        with patch.object(probe.os, "scandir", side_effect=PermissionError("fixture")):
            with self.assertRaises(PermissionError):
                probe.verify_recording_storage(self.name, self.root)

    def test_regular_recordings_and_path_traversal_are_rejected_before_io(self):
        for name in ("existing.guac", "../other", "/recordings/other", ".operation-portal-storage." + "a" * 13):
            with self.subTest(name=name), patch.object(probe.os, "scandir") as scan:
                with self.assertRaises(ValueError):
                    probe.verify_recording_storage(name, self.root)
                scan.assert_not_called()

    def test_root_identity_cannot_produce_a_false_positive(self):
        with patch.object(probe.os, "geteuid", return_value=0, create=True), \
                patch.object(probe.sys, "argv", ["verify", self.name]), \
                patch.object(probe, "verify_recording_storage") as verify:
            self.assertEqual(probe.main(), 1)
            verify.assert_not_called()

"""
Tests for session-based dataset splitting and management in engine/ml/dataset.py.
Verifies the project rule: Split by recording session; no session is in two splits!
"""

import json
from pathlib import Path
import tempfile
import unittest

from engine.ml.dataset import (
    generate_baseline_sessions,
    split_sessions_train_val_test,
    export_ml_datasets
)


class TestMLDataset(unittest.TestCase):

    def test_baseline_sessions_contain_ordinary_usb(self):
        """Verifies baseline recordings include benign USB usage to prevent false positives."""
        sessions = generate_baseline_sessions()
        self.assertGreaterEqual(len(sessions), 4)

        # Confirm at least one session models normal USB drive usage
        has_usb = any(
            any(ev.get("source") == "usb" or "SanDisk" in ev.get("entity", "") for ev in evs)
            for evs in sessions.values()
        )
        self.assertTrue(has_usb, "Baseline sessions must include benign USB usage.")

    def test_session_splits_are_strictly_disjoint(self):
        """Verifies that no recording session ever leaks into multiple splits."""
        sessions = generate_baseline_sessions()
        train_events, val_events, test_events, assignment_map = split_sessions_train_val_test(sessions)

        train_sessions = {e["session_id"] for e in train_events}
        val_sessions = {e["session_id"] for e in val_events}
        test_sessions = {e["session_id"] for e in test_events}

        # Check disjointness
        self.assertTrue(train_sessions.isdisjoint(val_sessions), "Train and Val share sessions!")
        self.assertTrue(train_sessions.isdisjoint(test_sessions), "Train and Test share sessions!")
        self.assertTrue(val_sessions.isdisjoint(test_sessions), "Val and Test share sessions!")

        # Verify all sessions are accounted for
        all_split_sessions = train_sessions | val_sessions | test_sessions
        self.assertEqual(all_split_sessions, set(sessions.keys()))

    def test_export_and_load_datasets(self):
        """Verifies JSON dataset export and manifest verification in a temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = export_ml_datasets(tmpdir)

            self.assertTrue(Path(paths["train"]).exists())
            self.assertTrue(Path(paths["val"]).exists())
            self.assertTrue(Path(paths["test"]).exists())
            self.assertTrue(Path(paths["manifest"]).exists())

            with open(paths["manifest"], "r", encoding="utf-8") as f:
                manifest = json.load(f)

            self.assertIn("session_assignments", manifest)
            self.assertIn("counts", manifest)
            self.assertGreater(manifest["counts"]["train_events"], 0)
            self.assertGreater(manifest["counts"]["val_events"], 0)
            self.assertGreater(manifest["counts"]["test_events"], 0)


if __name__ == "__main__":
    unittest.main()

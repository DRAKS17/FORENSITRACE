"""
Tests for dynamic feature extraction in engine/ml/features.py.
Verifies dynamic sizing (actions + 3), flags, time deltas, and windowing.
"""

from datetime import datetime, timezone, timedelta
import math
import unittest
import numpy as np

from engine.ml.features import (
    FeatureExtractor,
    SCHEMA_ACTIONS,
    get_feature_vector_size,
    extract_event_features,
    create_sliding_windows
)


class TestMLFeatures(unittest.TestCase):

    def setUp(self):
        self.extractor = FeatureExtractor()
        self.expected_dim = len(SCHEMA_ACTIONS) + 3

    def test_vector_size_equals_actions_plus_three(self):
        """Rule verification: The input vector size is computed from schema actions plus 3. Never hard-code it."""
        dim = get_feature_vector_size()
        self.assertEqual(dim, len(SCHEMA_ACTIONS) + 3)
        self.assertEqual(self.extractor.vector_size, dim)

    def test_action_one_hot_encoding(self):
        """Verifies that each canonical action lights up its designated one-hot slot."""
        for idx, action in enumerate(SCHEMA_ACTIONS):
            ev = {
                "action": action,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "entity": "C:\\test.txt"
            }
            vec = extract_event_features(ev)
            self.assertEqual(vec.shape[0], self.expected_dim)
            self.assertEqual(vec[idx], 1.0, f"Action {action} did not activate index {idx}")
            self.assertEqual(sum(vec[:len(SCHEMA_ACTIONS)]), 1.0)

    def test_time_delta_continuous_feature(self):
        """Verifies log(1 + dt) calculation for elapsed seconds between events."""
        t0 = datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc)
        t1 = t0 + timedelta(seconds=9)

        ev0 = {"action": "HEARTBEAT", "timestamp": t0, "entity": "agent"}
        ev1 = {"action": "HEARTBEAT", "timestamp": t1, "entity": "agent"}

        # First event (no prev) -> delta=0 -> log(1+0) = 0.0
        vec0 = extract_event_features(ev0, None)
        self.assertAlmostEqual(vec0[len(SCHEMA_ACTIONS)], 0.0)

        # Second event 9 seconds later -> log(1+9) = log(10)
        vec1 = extract_event_features(ev1, ev0)
        expected_log = float(math.log(10.0))
        self.assertAlmostEqual(vec1[len(SCHEMA_ACTIONS)], expected_log, places=4)

    def test_executable_flag_fire_and_not_fire(self):
        """Test that must fire and test that must not fire for executable detection."""
        # Must FIRE:
        ev_exe = {"action": "FILE_CREATED", "entity": "C:\\temp\\backdoor.exe"}
        vec_exe = extract_event_features(ev_exe)
        self.assertEqual(vec_exe[len(SCHEMA_ACTIONS) + 1], 1.0)

        ev_ps1 = {"action": "FILE_CREATED", "entity": "C:\\scripts\\runner.ps1"}
        vec_ps1 = extract_event_features(ev_ps1)
        self.assertEqual(vec_ps1[len(SCHEMA_ACTIONS) + 1], 1.0)

        # Must NOT fire:
        ev_doc = {"action": "FILE_CREATED", "entity": "C:\\users\\doc.docx"}
        vec_doc = extract_event_features(ev_doc)
        self.assertEqual(vec_doc[len(SCHEMA_ACTIONS) + 1], 0.0)

    def test_removable_drive_flag_fire_and_not_fire(self):
        """Test that must fire and test that must not fire for removable storage detection."""
        # Must FIRE:
        ev_usb = {"action": "FILE_CREATED", "entity": "E:\\payload.bin"}
        vec_usb = extract_event_features(ev_usb)
        self.assertEqual(vec_usb[len(SCHEMA_ACTIONS) + 2], 1.0)

        ev_usb_drive = {"action": "DEVICE_ARRIVED", "entity": "D: (SanDisk)", "details": {"drive_letter": "D:"}}
        vec_usb_drive = extract_event_features(ev_usb_drive)
        self.assertEqual(vec_usb_drive[len(SCHEMA_ACTIONS) + 2], 1.0)

        # Must NOT fire:
        ev_c = {"action": "FILE_CREATED", "entity": "C:\\Windows\\system32\\calc.exe"}
        vec_c = extract_event_features(ev_c)
        self.assertEqual(vec_c[len(SCHEMA_ACTIONS) + 2], 0.0)

    def test_sliding_window_generation(self):
        """Verifies sliding window generation on 15 sequential events with window_size=10."""
        t0 = datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc)
        events = []
        for i in range(15):
            events.append({
                "action": "FILE_MODIFIED",
                "timestamp": t0 + timedelta(seconds=i),
                "entity": f"C:\\workspace\\file_{i}.txt"
            })

        windows, event_sublists = create_sliding_windows(events, window_size=10, step=1)
        # 15 events with window=10 and step=1 -> 15 - 10 + 1 = 6 windows
        self.assertEqual(windows.shape, (6, 10, self.expected_dim))
        self.assertEqual(len(event_sublists), 6)
        self.assertEqual(len(event_sublists[0]), 10)


if __name__ == "__main__":
    unittest.main()

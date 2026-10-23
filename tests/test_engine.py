"""
ForensiTrace - Correlation Engine Unit & Firing Tests (AKASH)
Verifies that each rule (R1-R7) correctly fires on malicious/suspicious sequences
and stays quiet on non-matching or benign operations.
Uses standard Python unittest.
"""

from datetime import datetime, timezone, timedelta
import unittest
from backend.app.models import EventRecord
from backend.app.engine import CorrelationEngine


def _make_record(id_: int, source: str, action: str, entity: str, ts: datetime, raw: dict = None, details: dict = None) -> EventRecord:
    return EventRecord(
        id=id_,
        event_id=f"hash_{id_}",
        source=source,
        timestamp=ts,
        entity=entity,
        action=action,
        host="TEST-WIN",
        user="TargetUser",
        raw_data=raw or {},
        details=details or {},
        prev_hash="0" * 64,
        record_hash=f"rec_hash_{id_}"
    )


class TestCorrelationEngineRules(unittest.TestCase):

    def setUp(self):
        self.engine = CorrelationEngine()

    # -------------------------------------------------------------------------
    # RULE R1: Device File Staging Tests
    # -------------------------------------------------------------------------
    def test_rule_r1_firing(self):
        """R1 must fire when USB arrives and a file is written to that drive within 5 min."""
        t0 = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
        ev1 = _make_record(1, "usb", "DEVICE_ARRIVED", "E: (SanDisk)", t0)
        ev2 = _make_record(2, "fs", "FILE_CREATED", "E:\\payload.exe", t0 + timedelta(seconds=15))

        activities = self.engine.analyze([ev1, ev2])
        r1_acts = [a for a in activities if "R1" in a.rule_name]
        self.assertEqual(len(r1_acts), 1)
        self.assertEqual(r1_acts[0].rule_name, "R1_DEVICE_FILE_STAGING")
        self.assertEqual(len(r1_acts[0].evidence_event_ids), 2)

    def test_rule_r1_must_not_fire_outside_window(self):
        """R1 must NOT fire if file is written after the 5 min window."""
        t0 = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
        ev1 = _make_record(1, "usb", "DEVICE_ARRIVED", "E: (SanDisk)", t0)
        ev2 = _make_record(2, "fs", "FILE_CREATED", "E:\\payload.exe", t0 + timedelta(minutes=10))

        activities = self.engine.analyze([ev1, ev2])
        r1_acts = [a for a in activities if "R1" in a.rule_name]
        self.assertEqual(len(r1_acts), 0)

    # -------------------------------------------------------------------------
    # RULE R2: Staged File Execution Tests
    # -------------------------------------------------------------------------
    def test_rule_r2_firing(self):
        """R2 must fire when an executable file is written and then spawned as a process."""
        t0 = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
        ev1 = _make_record(1, "fs", "FILE_CREATED", "C:\\Users\\User\\malware.exe", t0)
        ev2 = _make_record(2, "eventlog", "PROCESS_STARTED", "C:\\Users\\User\\malware.exe", t0 + timedelta(seconds=5))

        activities = self.engine.analyze([ev1, ev2])
        r2_acts = [a for a in activities if "R2" in a.rule_name]
        self.assertEqual(len(r2_acts), 1)
        self.assertEqual(r2_acts[0].confidence_level, "HIGH")

    def test_rule_r2_must_not_fire_unrelated_process(self):
        """R2 must NOT fire if process executed does not match staged file name."""
        t0 = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
        ev1 = _make_record(1, "fs", "FILE_CREATED", "C:\\Users\\User\\malware.exe", t0)
        ev2 = _make_record(2, "eventlog", "PROCESS_STARTED", "C:\\Windows\\notepad.exe", t0 + timedelta(seconds=5))

        activities = self.engine.analyze([ev1, ev2])
        r2_acts = [a for a in activities if "R2" in a.rule_name]
        self.assertEqual(len(r2_acts), 0)

    # -------------------------------------------------------------------------
    # RULE R3: Direct Removable Execution Tests
    # -------------------------------------------------------------------------
    def test_rule_r3_firing(self):
        """R3 must fire when process runs directly from removable volume without prior write."""
        t0 = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
        ev_usb = _make_record(1, "usb", "DEVICE_ARRIVED", "E: (USB_DRIVE)", t0)
        ev_proc = _make_record(2, "eventlog", "PROCESS_STARTED", "E:\\standalone_tool.exe", t0 + timedelta(seconds=10))

        activities = self.engine.analyze([ev_usb, ev_proc])
        r3_acts = [a for a in activities if "R3" in a.rule_name]
        self.assertEqual(len(r3_acts), 1)
        self.assertGreaterEqual(r3_acts[0].confidence_score, 0.75)

    # -------------------------------------------------------------------------
    # RULE R4: Bulk Copy Tests
    # -------------------------------------------------------------------------
    def test_rule_r4_firing(self):
        """R4 must fire when 5 or more files are created on removable drive in under 60 seconds."""
        t0 = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
        events = []
        for i in range(6):
            events.append(_make_record(i + 1, "fs", "FILE_CREATED", f"E:\\doc_{i}.pdf", t0 + timedelta(seconds=i * 2)))

        activities = self.engine.analyze(events)
        r4_acts = [a for a in activities if "R4" in a.rule_name]
        self.assertEqual(len(r4_acts), 1)
        self.assertEqual(r4_acts[0].metadata["file_count"], 6)

    def test_rule_r4_must_not_fire_below_threshold(self):
        """R4 must NOT fire if fewer than 5 files are copied."""
        t0 = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_record(1, "fs", "FILE_CREATED", "E:\\doc_1.pdf", t0),
            _make_record(2, "fs", "FILE_CREATED", "E:\\doc_2.pdf", t0 + timedelta(seconds=2))
        ]
        activities = self.engine.analyze(events)
        r4_acts = [a for a in activities if "R4" in a.rule_name]
        self.assertEqual(len(r4_acts), 0)

    # -------------------------------------------------------------------------
    # RULE R5: Log Cleared Coverup Tests
    # -------------------------------------------------------------------------
    def test_rule_r5_firing(self):
        """R5 must fire when audit log is cleared within 10 min of file activity."""
        t0 = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
        ev_file = _make_record(1, "fs", "FILE_CREATED", "C:\\temp\\exploit.exe", t0)
        ev_clear = _make_record(2, "eventlog", "LOG_CLEARED", "LogCleared:Security", t0 + timedelta(seconds=15))

        activities = self.engine.analyze([ev_file, ev_clear])
        r5_acts = [a for a in activities if "R5" in a.rule_name]
        self.assertEqual(len(r5_acts), 1)
        self.assertEqual(r5_acts[0].confidence_level, "HIGH")

    # -------------------------------------------------------------------------
    # RULE R6: Timestamp Disagreement (Timestomping) Tests
    # -------------------------------------------------------------------------
    def test_rule_r6_firing(self):
        """R6 must fire when file modified timestamp diverges from agent collection time by > 120s."""
        t_agent = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
        t_stomp = t_agent - timedelta(days=365)  # Timestomped 1 year into past
        ev = _make_record(
            1, "fs", "FILE_CREATED", "C:\\malware.dll", t_agent,
            details={"mtime": t_stomp.isoformat()}
        )

        activities = self.engine.analyze([ev])
        r6_acts = [a for a in activities if "R6" in a.rule_name]
        self.assertEqual(len(r6_acts), 1)
        self.assertIn("Timestomping", r6_acts[0].title)

    def test_rule_r6_must_not_fire_normal_timestamp(self):
        """R6 must NOT fire if timestamps are synchronized (<120s diff)."""
        t_agent = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
        t_mtime = t_agent - timedelta(seconds=5)
        ev = _make_record(
            1, "fs", "FILE_CREATED", "C:\\normal.txt", t_agent,
            details={"mtime": t_mtime.isoformat()}
        )

        activities = self.engine.analyze([ev])
        r6_acts = [a for a in activities if "R6" in a.rule_name]
        self.assertEqual(len(r6_acts), 0)

    # -------------------------------------------------------------------------
    # RULE R7: Full USB Copy & Run Chain
    # -------------------------------------------------------------------------
    def test_rule_r7_full_chain_high_confidence(self):
        """R7 must fire with HIGH confidence (0.90) on rapid 3-stage intrusion."""
        t0 = datetime(2026, 10, 23, 12, 0, 0, tzinfo=timezone.utc)
        ev1 = _make_record(1, "usb", "DEVICE_ARRIVED", "E: (USB_PAYLOAD)", t0)
        ev2 = _make_record(2, "fs", "FILE_CREATED", "E:\\trojan.exe", t0 + timedelta(seconds=5))
        ev3 = _make_record(3, "eventlog", "PROCESS_STARTED", "E:\\trojan.exe", t0 + timedelta(seconds=8))

        activities = self.engine.analyze([ev1, ev2, ev3])
        r7_acts = [a for a in activities if "R7" in a.rule_name]
        self.assertEqual(len(r7_acts), 1)
        self.assertGreaterEqual(r7_acts[0].confidence_score, 0.90)
        self.assertEqual(r7_acts[0].confidence_level, "HIGH")
        self.assertIn("[Event #1]", r7_acts[0].narrative)
        self.assertIn("[Event #2]", r7_acts[0].narrative)
        self.assertIn("[Event #3]", r7_acts[0].narrative)
        self.assertEqual(len(r7_acts[0].evidence_event_ids), 3)


if __name__ == "__main__":
    unittest.main()

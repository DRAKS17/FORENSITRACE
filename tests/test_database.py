"""
ForensiTrace - EvidenceStore & Cryptographic Hash Chain Tests (PURVA)
Verifies append-only storage, SHA-256 hash chaining, anti-tamper detection,
idempotent deduplication on event_id, and activity_events link provenance.
"""

from datetime import datetime, timezone
import os
import sqlite3
import tempfile
import unittest

from backend.app.models import EventCreate, ActivityCreate
from backend.app.database import EvidenceStore, GENESIS_HASH


class TestEvidenceStore(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_forensitrace.db")
        self.store = EvidenceStore(self.db_path)

    def tearDown(self):
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except OSError:
                pass
        try:
            os.rmdir(self.temp_dir)
        except OSError:
            pass

    def test_hash_chain_genesis_and_continuity(self):
        """Verifies that the first record links to GENESIS_HASH and next record links to record #1."""
        t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
        ev1 = EventCreate(source="usb", timestamp=t0, entity="E:", action="DEVICE_ARRIVED")
        rec1 = self.store.insert_event(ev1)

        self.assertEqual(rec1.id, 1)
        self.assertEqual(rec1.prev_hash, GENESIS_HASH)
        self.assertTrue(len(rec1.record_hash) == 64)

        t1 = datetime(2026, 10, 23, 10, 0, 5, tzinfo=timezone.utc)
        ev2 = EventCreate(source="fs", timestamp=t1, entity="E:\\tool.exe", action="FILE_CREATED")
        rec2 = self.store.insert_event(ev2)

        self.assertEqual(rec2.id, 2)
        self.assertEqual(rec2.prev_hash, rec1.record_hash)

        is_intact, tampered_id = self.store.verify_integrity()
        self.assertTrue(is_intact)
        self.assertIsNone(tampered_id)

    def test_anti_tamper_detection(self):
        """Verifies that direct database modification is immediately flagged by verify_integrity()."""
        t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
        self.store.insert_event(EventCreate(source="usb", timestamp=t0, entity="E:", action="DEVICE_ARRIVED"))
        self.store.insert_event(EventCreate(source="fs", timestamp=t0, entity="E:\\tool.exe", action="FILE_CREATED"))

        # Illicit direct modification of record #1 entity
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("UPDATE events SET entity = 'Z: (TAMPERED)' WHERE id = 1")
        conn.commit()
        conn.close()

        is_intact, tampered_id = self.store.verify_integrity()
        self.assertFalse(is_intact)
        self.assertEqual(tampered_id, 1)

    def test_event_deduplication(self):
        """Verifies that sending an event with duplicate event_id is safely ignored."""
        t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
        ev = EventCreate(
            event_id="unique_hash_12345",
            source="eventlog",
            timestamp=t0,
            entity="Proc.exe",
            action="PROCESS_STARTED"
        )
        rec1 = self.store.insert_event(ev)
        rec2 = self.store.insert_event(ev)

        self.assertEqual(rec1.id, rec2.id)
        self.assertEqual(rec1.record_hash, rec2.record_hash)

        events = self.store.get_events()
        self.assertEqual(len(events), 1)

    def test_activity_events_provenance_links(self):
        """Verifies that inserting an activity populates the activity_events link table."""
        t0 = datetime(2026, 10, 23, 10, 0, 0, tzinfo=timezone.utc)
        rec1 = self.store.insert_event(EventCreate(source="usb", timestamp=t0, entity="E:", action="DEVICE_ARRIVED"))
        rec2 = self.store.insert_event(EventCreate(source="fs", timestamp=t0, entity="E:\\p.exe", action="FILE_CREATED"))

        activity = ActivityCreate(
            rule_name="R1_DEVICE_FILE_STAGING",
            title="USB File Staging",
            narrative="[Event #1] USB connected. [Event #2] File staged.",
            timestamp_start=t0,
            timestamp_end=t0,
            confidence_score=0.75,
            confidence_level="HIGH",
            evidence_event_ids=[rec1.id, rec2.id],
            evidence_links=[
                {"event_id": rec1.id, "rule_id": "R1", "reason": "Hardware mount"},
                {"event_id": rec2.id, "rule_id": "R1", "reason": "Payload write"}
            ]
        )
        act_rec = self.store.insert_activity(activity)

        detail = self.store.get_activity_by_id(act_rec.id)
        self.assertIsNotNone(detail)
        self.assertEqual(len(detail.evidence), 2)
        self.assertEqual(detail.evidence[0]["reason"], "Hardware mount")
        self.assertEqual(detail.evidence[1]["reason"], "Payload write")


if __name__ == "__main__":
    unittest.main()

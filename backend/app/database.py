"""
ForensiTrace - Evidence Storage Layer.
Implements the EvidenceStore managing an append-only SQLite database backed
by a cryptographic SHA-256 hash chain for anti-tamper verification.
"""

import hashlib
import json
import logging
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    from backend.app.models import EventCreate, EventRecord, ActivityCreate, ActivityRecord
except ModuleNotFoundError:
    # Allow execution directly as script from any working directory
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from backend.app.models import EventCreate, EventRecord, ActivityCreate, ActivityRecord

logger = logging.getLogger(__name__)

# Standard 64-character genesis hash representing the origin of the chain
GENESIS_HASH: str = "0" * 64


class EvidenceStore:
    """
    Append-only evidence store backed by SQLite and a SHA-256 cryptographic hash chain.
    Guarantees forensic non-repudiation and anti-tamper verification across all collected events.
    """

    def __init__(self, db_path: Union[str, Path] = "forensitrace.db") -> None:
        """
        Initialize the EvidenceStore.

        :param db_path: Path to the local SQLite database file.
        """
        self.db_path = Path(db_path).resolve()
        self._init_db()

    def _init_db(self) -> None:
        """Creates the append-only events table and indexes if they do not exist."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    entity TEXT NOT NULL,
                    action TEXT NOT NULL,
                    raw_data TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL
                )
                """
            )
            # Create indexing for rapid query and timeline construction
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)"
            )
            
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS activities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_name TEXT NOT NULL,
                    title TEXT NOT NULL,
                    narrative TEXT NOT NULL,
                    timestamp_start TEXT NOT NULL,
                    timestamp_end TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    confidence_level TEXT NOT NULL,
                    evidence_event_ids TEXT NOT NULL,
                    metadata TEXT NOT NULL
                )
                """
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_activities_timestamp_start ON activities(timestamp_start)"
            )
            conn.commit()
            logger.info("Initialized EvidenceStore database schema at: %s", self.db_path)
        finally:
            conn.close()

    @staticmethod
    def canonical_json(data: Union[Dict[str, Any], str]) -> str:
        """
        Converts arbitrary dictionary or json string into deterministic canonical JSON
        with sorted keys and compact separators to ensure reproducible hash digests.
        """
        if isinstance(data, str):
            try:
                parsed = json.loads(data)
            except Exception:
                return data
        else:
            parsed = data
        return json.dumps(parsed, sort_keys=True, separators=(",", ":"), ensure_ascii=True)

    @classmethod
    def compute_hash(
        cls,
        prev_hash: str,
        source: str,
        timestamp: str,
        entity: str,
        action: str,
        raw_data: Union[Dict[str, Any], str],
    ) -> str:
        """
        Computes the SHA-256 digest over the concatenation of the previous hash and event fields:
        SHA-256(prev_hash + source + timestamp + entity + action + canonical_json(raw_data))
        """
        canonical_raw = cls.canonical_json(raw_data)
        payload = f"{prev_hash}{source}{timestamp}{entity}{action}{canonical_raw}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def insert_event(self, event: EventCreate) -> EventRecord:
        """
        Inserts an incoming event into the append-only log, cryptographically linking it
        to the latest record hash.

        :param event: EventCreate Pydantic instance.
        :return: Stored EventRecord with assigned sequence ID and hashes.
        """
        timestamp_str = (
            event.timestamp.isoformat()
            if isinstance(event.timestamp, datetime)
            else str(event.timestamp)
        )
        canonical_raw = self.canonical_json(event.raw_data)

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            # Retrieve the hash of the most recent record
            cursor.execute("SELECT record_hash FROM events ORDER BY id DESC LIMIT 1")
            last_row = cursor.fetchone()
            prev_hash = str(last_row["record_hash"]) if last_row else GENESIS_HASH

            # Compute current record hash
            record_hash = self.compute_hash(
                prev_hash=prev_hash,
                source=event.source,
                timestamp=timestamp_str,
                entity=event.entity,
                action=event.action,
                raw_data=canonical_raw,
            )

            # Strictly append-only insert
            cursor.execute(
                """
                INSERT INTO events (source, timestamp, entity, action, raw_data, prev_hash, record_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.source,
                    timestamp_str,
                    event.entity,
                    event.action,
                    canonical_raw,
                    prev_hash,
                    record_hash,
                ),
            )
            conn.commit()
            inserted_id = cursor.lastrowid
        finally:
            conn.close()

        logger.debug(
            "Appended evidence record #%s [%s - %s] -> hash: %s",
            inserted_id,
            event.source,
            event.action,
            record_hash[:16] + "...",
        )

        return EventRecord(
            id=inserted_id,
            source=event.source,
            timestamp=event.timestamp,
            entity=event.entity,
            action=event.action,
            raw_data=event.raw_data,
            prev_hash=prev_hash,
            record_hash=record_hash,
        )

    def verify_integrity(self) -> Tuple[bool, Optional[int]]:
        """
        Audits the entire cryptographic hash chain sequentially from ID 1 to N.

        :return: Tuple of (True, None) if the hash chain is fully intact,
                 or (False, tampered_id) if any hash mismatch or tampering is detected.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, source, timestamp, entity, action, raw_data, prev_hash, record_hash
                FROM events
                ORDER BY id ASC
                """
            )
            rows = cursor.fetchall()
        finally:
            conn.close()

        if not rows:
            return True, None

        expected_prev_hash = GENESIS_HASH

        for row in rows:
            row_id = int(row["id"])
            row_prev = str(row["prev_hash"])
            row_hash = str(row["record_hash"])

            # 1. Verify link continuity: previous hash must match preceding record
            if row_prev != expected_prev_hash:
                logger.error(
                    "Integrity violation at record #%s: prev_hash link broken. Expected %s, found %s",
                    row_id,
                    expected_prev_hash,
                    row_prev,
                )
                return False, row_id

            # 2. Recompute and verify payload hash
            computed_hash = self.compute_hash(
                prev_hash=row_prev,
                source=str(row["source"]),
                timestamp=str(row["timestamp"]),
                entity=str(row["entity"]),
                action=str(row["action"]),
                raw_data=str(row["raw_data"]),
            )

            if row_hash != computed_hash:
                logger.error(
                    "Integrity violation at record #%s: data content mismatch. Expected %s, found %s",
                    row_id,
                    computed_hash,
                    row_hash,
                )
                return False, row_id

            expected_prev_hash = row_hash

        return True, None

    def get_events(self, limit: int = 100, offset: int = 0) -> List[EventRecord]:
        """Retrieves stored records chronologically with pagination."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, source, timestamp, entity, action, raw_data, prev_hash, record_hash
                FROM events
                ORDER BY id ASC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            )
            rows = cursor.fetchall()
        finally:
            conn.close()

        records = []
        for r in rows:
            try:
                raw_dict = json.loads(r["raw_data"])
            except Exception:
                raw_dict = {}
            records.append(
                EventRecord(
                    id=r["id"],
                    source=r["source"],
                    timestamp=datetime.fromisoformat(r["timestamp"]),
                    entity=r["entity"],
                    action=r["action"],
                    raw_data=raw_dict,
                    prev_hash=r["prev_hash"],
                    record_hash=r["record_hash"],
                )
            )
        return records


    def insert_activity(self, activity: ActivityCreate) -> ActivityRecord:
        """
        Inserts a correlated activity record.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO activities (
                    rule_name, title, narrative, timestamp_start, timestamp_end,
                    confidence_score, confidence_level, evidence_event_ids, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    activity.rule_name,
                    activity.title,
                    activity.narrative,
                    activity.timestamp_start.isoformat(),
                    activity.timestamp_end.isoformat(),
                    activity.confidence_score,
                    activity.confidence_level,
                    json.dumps(activity.evidence_event_ids),
                    json.dumps(activity.metadata),
                )
            )
            conn.commit()
            inserted_id = cursor.lastrowid
        finally:
            conn.close()

        logger.debug(f"Stored correlated activity #{inserted_id}: {activity.title}")
        
        return ActivityRecord(
            id=inserted_id,
            rule_name=activity.rule_name,
            title=activity.title,
            narrative=activity.narrative,
            timestamp_start=activity.timestamp_start,
            timestamp_end=activity.timestamp_end,
            confidence_score=activity.confidence_score,
            confidence_level=activity.confidence_level,
            evidence_event_ids=activity.evidence_event_ids,
            metadata=activity.metadata
        )

    def get_activities(self, limit: int = 100, offset: int = 0) -> List[ActivityRecord]:
        """Retrieves correlated activities."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, rule_name, title, narrative, timestamp_start, timestamp_end,
                       confidence_score, confidence_level, evidence_event_ids, metadata
                FROM activities
                ORDER BY timestamp_start DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset)
            )
            rows = cursor.fetchall()
        finally:
            conn.close()

        records = []
        for r in rows:
            records.append(ActivityRecord(
                id=r["id"],
                rule_name=r["rule_name"],
                title=r["title"],
                narrative=r["narrative"],
                timestamp_start=datetime.fromisoformat(r["timestamp_start"]),
                timestamp_end=datetime.fromisoformat(r["timestamp_end"]),
                confidence_score=r["confidence_score"],
                confidence_level=r["confidence_level"],
                evidence_event_ids=json.loads(r["evidence_event_ids"]),
                metadata=json.loads(r["metadata"])
            ))
        return records

    def get_activity_evidence(self, activity_id: int) -> List[EventRecord]:
        """Fetches raw evidence events associated with a given activity."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT evidence_event_ids FROM activities WHERE id = ?", (activity_id,))
            row = cursor.fetchone()
            if not row:
                return []
            
            event_ids = json.loads(row["evidence_event_ids"])
            if not event_ids:
                return []

            placeholders = ",".join("?" for _ in event_ids)
            cursor.execute(
                f"""
                SELECT id, source, timestamp, entity, action, raw_data, prev_hash, record_hash
                FROM events
                WHERE id IN ({placeholders})
                ORDER BY timestamp ASC
                """,
                event_ids
            )
            rows = cursor.fetchall()
        finally:
            conn.close()

        records = []
        for r in rows:
            try:
                raw_dict = json.loads(r["raw_data"])
            except Exception:
                raw_dict = {}
            records.append(
                EventRecord(
                    id=r["id"],
                    source=r["source"],
                    timestamp=datetime.fromisoformat(r["timestamp"]),
                    entity=r["entity"],
                    action=r["action"],
                    raw_data=raw_dict,
                    prev_hash=r["prev_hash"],
                    record_hash=r["record_hash"],
                )
            )
        return records


if __name__ == "__main__":
    from datetime import timezone

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    print("=" * 80)
    print(" FORENSITRACE - EVIDENCE STORE & ANTI-TAMPER INTEGRITY TEST")
    print("=" * 80)

    # Use a temporary database for the automated test run
    test_db = Path("test_forensitrace.db").resolve()
    if test_db.exists():
        test_db.unlink()

    store = EvidenceStore(db_path=test_db)

    try:
        # Step 1: Insert three mock events across different telemetry sources
        print("\n[*] 1. Inserting mock events across sources...")

        e1 = EventCreate(
            source="file_system",
            timestamp=datetime.now(timezone.utc),
            entity="C:\\Sensitive\\Financial_Q3.xlsx",
            action="created",
            raw_data={"size_bytes": 1048576, "file_extension": ".xlsx", "is_directory": False},
        )
        rec1 = store.insert_event(e1)
        print(f"  [+] Event #1 stored: ID={rec1.id} | Hash={rec1.record_hash[:16]}... | Prev={rec1.prev_hash[:16]}...")

        e2 = EventCreate(
            source="usb_device",
            timestamp=datetime.now(timezone.utc),
            entity="E:",
            action="connected",
            raw_data={"drive_letter": "E:", "volume_name": "EXFIL_DRIVE", "file_system": "FAT32"},
        )
        rec2 = store.insert_event(e2)
        print(f"  [+] Event #2 stored: ID={rec2.id} | Hash={rec2.record_hash[:16]}... | Prev={rec2.prev_hash[:16]}...")

        e3 = EventCreate(
            source="event_log",
            timestamp=datetime.now(timezone.utc),
            entity="Microsoft-Windows-Security-Auditing/4688",
            action="logged",
            raw_data={
                "process_name": "C:\\Windows\\System32\\cmd.exe",
                "command_line": "cmd.exe /c copy C:\\Sensitive\\Financial_Q3.xlsx E:\\",
            },
        )
        rec3 = store.insert_event(e3)
        print(f"  [+] Event #3 stored: ID={rec3.id} | Hash={rec3.record_hash[:16]}... | Prev={rec3.prev_hash[:16]}...")

        # Step 2: Verify integrity on untampered log (should pass with True, None)
        print("\n[*] 2. Verifying cryptographic chain integrity on clean store...")
        is_intact, tampered_id = store.verify_integrity()
        print(f"  [>] Result: intact={is_intact}, tampered_record_id={tampered_id}")
        assert is_intact is True, "Expected chain integrity to be intact!"
        assert tampered_id is None, "Expected tampered_id to be None on clean database!"
        print("  [+] Initial integrity check PASSED.")

        # Step 3: Simulate malicious tampering via raw SQL UPDATE
        print("\n[*] 3. Simulating malicious attacker tampering on Record #2 via raw SQL...")
        conn = sqlite3.connect(test_db)
        try:
            conn.execute(
                "UPDATE events SET entity = 'Z: (Forged Attacker Volume)' WHERE id = 2"
            )
            conn.commit()
        finally:
            conn.close()
        print("  [!] Direct SQL UPDATE executed: Record #2 entity modified.")

        # Step 4: Run verification again to confirm tamper detection
        print("\n[*] 4. Re-running integrity audit after data alteration...")
        is_intact_post, tampered_id_post = store.verify_integrity()
        print(f"  [>] Result: intact={is_intact_post}, tampered_record_id={tampered_id_post}")
        assert is_intact_post is False, "Expected integrity verification to fail after tampering!"
        assert tampered_id_post == 2, f"Expected tamper detection at record #2, got {tampered_id_post}"
        print(f"  [+] SUCCESS: Anti-tamper chain caught alteration precisely at record ID={tampered_id_post}!")

        print("\n" + "=" * 80)
        print(" ALL STEP 4 TESTS COMPLETED SUCCESSFULLY")
        print("=" * 80)

    finally:
        # Explicit garbage collection and file cleanup
        import gc
        gc.collect()
        if test_db.exists():
            try:
                test_db.unlink()
            except OSError:
                pass

"""
ForensiTrace - Evidence Storage Layer.
Implements the EvidenceStore managing an append-only SQLite database backed
by a cryptographic SHA-256 hash chain for anti-tamper verification.
Includes the canonical events, activities, and activity_events link table for provenance.
"""

from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple, Union

try:
    from backend.app.models import (
        EventCreate,
        EventRecord,
        ActivityCreate,
        ActivityRecord,
        ActivityDetail,
        TimelineItem,
    )
except ModuleNotFoundError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))
    from backend.app.models import (
        EventCreate,
        EventRecord,
        ActivityCreate,
        ActivityRecord,
        ActivityDetail,
        TimelineItem,
    )

logger = logging.getLogger(__name__)

# Standard 64-character genesis hash representing the origin of the chain
GENESIS_HASH: str = "0" * 64


class EvidenceStore:
    """
    Append-only evidence store backed by SQLite and a SHA-256 cryptographic hash chain.
    Guarantees forensic non-repudiation and anti-tamper verification across all collected events.
    """

    def __init__(self, db_path: Union[str, Path] = "forensitrace.db") -> None:
        self.db_path = Path(db_path).resolve()
        self._init_db()

    def _init_db(self) -> None:
        """Creates the append-only events, activities, and activity_events tables."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()

            # 1. Events Table with deduplication support on event_id
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT UNIQUE,
                    source TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    host TEXT,
                    user TEXT,
                    action TEXT NOT NULL,
                    entity_type TEXT,
                    entity TEXT NOT NULL,
                    details TEXT,
                    raw_data TEXT NOT NULL,
                    prev_hash TEXT NOT NULL,
                    record_hash TEXT NOT NULL
                )
                """
            )
            # Seamless column upgrade for existing database instances
            cursor.execute("PRAGMA table_info(events)")
            existing_cols = {col[1] for col in cursor.fetchall()}
            for col_name in ["event_id", "host", "user", "entity_type", "details"]:
                if col_name not in existing_cols:
                    try:
                        cursor.execute(f"ALTER TABLE events ADD COLUMN {col_name} TEXT")
                    except Exception:
                        pass

            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_source ON events(source)")
            try:
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_event_id ON events(event_id)")
            except Exception:
                pass

            # 2. Activities Table
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
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_activities_timestamp_start ON activities(timestamp_start)")

            # 3. Evidence Provenance Link Table: activity_events
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS activity_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    activity_id INTEGER NOT NULL REFERENCES activities(id),
                    event_id INTEGER NOT NULL REFERENCES events(id),
                    rule_id TEXT NOT NULL,
                    reason TEXT NOT NULL
                )
                """
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_act_events_activity_id ON activity_events(activity_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_act_events_event_id ON activity_events(event_id)")

            conn.commit()
            logger.info("Initialized EvidenceStore database schema at: %s", self.db_path)
        finally:
            conn.close()

    @staticmethod
    def canonical_json(data: Union[Dict[str, Any], str, None]) -> str:
        """Converts arbitrary dictionary or json string into deterministic canonical JSON."""
        if not data:
            return "{}"
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
        """Computes SHA-256 over prev_hash + source + timestamp + entity + action + canonical_raw."""
        canonical_raw = cls.canonical_json(raw_data)
        payload = f"{prev_hash}{source}{timestamp}{entity}{action}{canonical_raw}"
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def insert_event(self, event: EventCreate) -> EventRecord:
        """
        Inserts an incoming event into the append-only log with deduplication.
        If an event with the same event_id already exists, returns the existing record.
        """
        eid = event.ensure_event_id()
        timestamp_str = (
            event.timestamp.isoformat()
            if isinstance(event.timestamp, datetime)
            else str(event.timestamp)
        )
        canonical_raw = self.canonical_json(event.raw_data)
        details_str = self.canonical_json(event.details)

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()

            # Deduplication check
            cursor.execute(
                """
                SELECT id, event_id, source, timestamp, host, user, action, entity_type, entity, details, raw_data, prev_hash, record_hash
                FROM events WHERE event_id = ?
                """,
                (eid,)
            )
            existing = cursor.fetchone()
            if existing:
                logger.debug("Duplicate event skipped [event_id=%s, id=%s]", eid[:12], existing["id"])
                return self._row_to_event_record(existing)

            # Retrieve previous record hash
            cursor.execute("SELECT record_hash FROM events ORDER BY id DESC LIMIT 1")
            last_row = cursor.fetchone()
            prev_hash = str(last_row["record_hash"]) if last_row else GENESIS_HASH

            # Compute record hash
            record_hash = self.compute_hash(
                prev_hash=prev_hash,
                source=event.source,
                timestamp=timestamp_str,
                entity=event.entity,
                action=event.action,
                raw_data=canonical_raw,
            )

            cursor.execute(
                """
                INSERT INTO events (
                    event_id, source, timestamp, host, user, action, entity_type, entity, details, raw_data, prev_hash, record_hash
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    eid,
                    event.source,
                    timestamp_str,
                    event.host or "WIN-ENDPOINT",
                    event.user or "SYSTEM",
                    event.action,
                    event.entity_type,
                    event.entity,
                    details_str,
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
            event_id=eid,
            source=event.source,
            timestamp=event.timestamp,
            host=event.host,
            user=event.user,
            entity_type=event.entity_type,
            entity=event.entity,
            action=event.action,
            details=event.details,
            raw_data=event.raw_data,
            prev_hash=prev_hash,
            record_hash=record_hash,
        )

    def insert_events_batch(self, events: List[EventCreate]) -> List[EventRecord]:
        """Inserts a batch of events sequentially to maintain the cryptographic hash chain."""
        records = []
        for ev in events:
            rec = self.insert_event(ev)
            records.append(rec)
        return records

    def _row_to_event_record(self, r: sqlite3.Row) -> EventRecord:
        """Helper to convert a database row to an EventRecord."""
        try:
            raw_dict = json.loads(r["raw_data"])
        except Exception:
            raw_dict = {}
        try:
            details_dict = json.loads(r["details"]) if r["details"] else {}
        except Exception:
            details_dict = {}

        return EventRecord(
            id=r["id"],
            event_id=r["event_id"],
            source=r["source"],
            timestamp=datetime.fromisoformat(r["timestamp"]),
            host=r["host"],
            user=r["user"],
            action=r["action"],
            entity_type=r["entity_type"],
            entity=r["entity"],
            details=details_dict,
            raw_data=raw_dict,
            prev_hash=r["prev_hash"],
            record_hash=r["record_hash"],
        )

    def verify_integrity(self) -> Tuple[bool, Optional[int]]:
        """
        Audits the entire cryptographic hash chain sequentially from ID 1 to N.
        Returns (True, None) if intact, or (False, tampered_id) if corrupted.
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

            # 1. Verify link continuity
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

    def get_events(
        self,
        limit: int = 100,
        offset: int = 0,
        source: Optional[str] = None
    ) -> List[EventRecord]:
        """Retrieves stored records chronologically with pagination and optional source filtering."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            if source:
                cursor.execute(
                    """
                    SELECT * FROM events
                    WHERE source = ? OR source = ?
                    ORDER BY id ASC
                    LIMIT ? OFFSET ?
                    """,
                    (source, source.lower(), limit, offset),
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM events
                    ORDER BY id ASC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                )
            rows = cursor.fetchall()
        finally:
            conn.close()

        return [self._row_to_event_record(r) for r in rows]

    def insert_activity(
        self,
        activity: ActivityCreate,
        links: Optional[List[Dict[str, Any]]] = None
    ) -> ActivityRecord:
        """
        Inserts a correlated activity record and populates the activity_events link table.
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
                ),
            )
            conn.commit()
            activity_id = cursor.lastrowid

            # Populate activity_events provenance links
            link_list = links or activity.evidence_links or []
            if link_list:
                for item in link_list:
                    cursor.execute(
                        """
                        INSERT INTO activity_events (activity_id, event_id, rule_id, reason)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            activity_id,
                            item.get("event_id"),
                            item.get("rule_id", activity.rule_name),
                            item.get("reason", "Correlated sequence supporting evidence")
                        )
                    )
            else:
                # Default provenance links for all evidence IDs
                for eid in activity.evidence_event_ids:
                    cursor.execute(
                        """
                        INSERT INTO activity_events (activity_id, event_id, rule_id, reason)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            activity_id,
                            eid,
                            activity.rule_name,
                            f"Sequential correlation contributor to {activity.title}"
                        )
                    )
            conn.commit()
        finally:
            conn.close()

        logger.info("Stored correlated activity #%s: %s", activity_id, activity.title)

        return ActivityRecord(
            id=activity_id,
            rule_name=activity.rule_name,
            title=activity.title,
            narrative=activity.narrative,
            timestamp_start=activity.timestamp_start,
            timestamp_end=activity.timestamp_end,
            confidence_score=activity.confidence_score,
            confidence_level=activity.confidence_level,
            evidence_event_ids=activity.evidence_event_ids,
            metadata=activity.metadata,
            evidence_links=link_list
        )

    def get_activities(
        self,
        limit: int = 100,
        offset: int = 0,
        confidence_level: Optional[str] = None
    ) -> List[ActivityRecord]:
        """Retrieves correlated activities sorted with newest first."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            if confidence_level:
                cursor.execute(
                    """
                    SELECT * FROM activities
                    WHERE UPPER(confidence_level) = UPPER(?)
                    ORDER BY timestamp_start DESC
                    LIMIT ? OFFSET ?
                    """,
                    (confidence_level, limit, offset),
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM activities
                    ORDER BY timestamp_start DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                )
            rows = cursor.fetchall()
        finally:
            conn.close()

        records = []
        for r in rows:
            records.append(
                ActivityRecord(
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
                )
            )
        return records

    def get_activity_by_id(self, activity_id: int) -> Optional[ActivityDetail]:
        """Retrieves a single activity alongside its full evidence links and provenance reasons."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM activities WHERE id = ?", (activity_id,))
            row = cursor.fetchone()
            if not row:
                return None

            act_record = ActivityRecord(
                id=row["id"],
                rule_name=row["rule_name"],
                title=row["title"],
                narrative=row["narrative"],
                timestamp_start=datetime.fromisoformat(row["timestamp_start"]),
                timestamp_end=datetime.fromisoformat(row["timestamp_end"]),
                confidence_score=row["confidence_score"],
                confidence_level=row["confidence_level"],
                evidence_event_ids=json.loads(row["evidence_event_ids"]),
                metadata=json.loads(row["metadata"])
            )

            cursor.execute(
                """
                SELECT ae.rule_id, ae.reason, e.*
                FROM activity_events ae
                JOIN events e ON ae.event_id = e.id
                WHERE ae.activity_id = ?
                ORDER BY e.timestamp ASC
                """,
                (activity_id,)
            )
            link_rows = cursor.fetchall()
            evidence_list = []
            for lr in link_rows:
                ev_rec = self._row_to_event_record(lr)
                evidence_list.append({
                    "event": ev_rec,
                    "rule_id": lr["rule_id"],
                    "reason": lr["reason"]
                })

            return ActivityDetail(activity=act_record, evidence=evidence_list)
        finally:
            conn.close()

    def get_activity_evidence(self, activity_id: int) -> List[EventRecord]:
        """Fetches raw evidence events associated with a given activity."""
        detail = self.get_activity_by_id(activity_id)
        if not detail:
            return []
        return [item["event"] for item in detail.evidence]

    def get_timeline(self, limit: int = 200) -> List[Dict[str, Any]]:
        """
        Constructs a unified chronological timeline merging activities and key forensic events.
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            cursor = conn.cursor()
            # Fetch recent activities
            cursor.execute(
                """
                SELECT id, rule_name, title, narrative, timestamp_start, confidence_level, confidence_score
                FROM activities
                ORDER BY timestamp_start DESC LIMIT ?
                """,
                (limit // 2,)
            )
            act_rows = cursor.fetchall()

            # Fetch non-heartbeat key events
            cursor.execute(
                """
                SELECT id, source, timestamp, entity, action
                FROM events
                WHERE source != 'heartbeat'
                ORDER BY timestamp DESC LIMIT ?
                """,
                (limit // 2,)
            )
            ev_rows = cursor.fetchall()
        finally:
            conn.close()

        timeline: List[Dict[str, Any]] = []

        for r in act_rows:
            timeline.append({
                "id": f"act-{r['id']}",
                "item_type": "activity",
                "timestamp": r["timestamp_start"],
                "title": r["title"],
                "description": r["narrative"],
                "confidence_level": r["confidence_level"],
                "confidence_score": r["confidence_score"],
                "ref_id": r["id"],
                "rule_name": r["rule_name"]
            })

        for r in ev_rows:
            timeline.append({
                "id": f"ev-{r['id']}",
                "item_type": "event",
                "timestamp": r["timestamp"],
                "title": f"[{r['source'].upper()}] {r['action']}",
                "description": r["entity"],
                "source": r["source"],
                "ref_id": r["id"]
            })

        timeline.sort(key=lambda x: x["timestamp"], reverse=True)
        return timeline[:limit]

    def clear_database(self) -> None:
        """Cleans all tables and resets sequence IDs (useful for demo and testing)."""
        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM activity_events")
            cursor.execute("DELETE FROM activities")
            cursor.execute("DELETE FROM events")
            cursor.execute("DELETE FROM sqlite_sequence")
            conn.commit()
            logger.info("Cleared all records from database.")
        finally:
            conn.close()

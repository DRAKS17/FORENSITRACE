"""
ForensiTrace - Backend Data Models and Pydantic Schemas.
Implements the frozen event schema (docs/schema.md), activity models,
evidence link provenance, and timeline structures.
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, Field, field_validator


def _compute_default_event_id(source: str, entity: str, action: str, ts: str) -> str:
    payload = f"{source}:{entity}:{action}:{ts}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class EventCreate(BaseModel):
    """
    Schema representing an incoming normalized telemetry event from the endpoint agent.
    Fully compatible with docs/schema.md while supporting legacy field aliases.
    """
    source: Literal[
        "file_system", "usb_device", "event_log", "heartbeat",
        "fs", "usb", "eventlog"
    ] = Field(
        ...,
        description="Telemetry source channel that generated the event."
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Event creation timestamp in ISO-8601 UTC format."
    )
    entity: str = Field(
        ...,
        description="Target entity involved (e.g., file path, drive letter, or provider/event ID)."
    )
    action: str = Field(
        ...,
        description="Normalized action descriptor (e.g., FILE_CREATED, DEVICE_ARRIVED, connected, etc.)."
    )
    raw_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Original unnormalized metadata and contextual parameters from the collector."
    )
    event_id: Optional[str] = Field(
        default=None,
        description="SHA-256 hash of source + raw record id + timestamp. Enables idempotent deduplication."
    )
    host: Optional[str] = Field(
        default="WIN-ENDPOINT",
        description="Host machine name where event was observed."
    )
    user: Optional[str] = Field(
        default="SYSTEM",
        description="User account context."
    )
    entity_type: Optional[str] = Field(
        default=None,
        description="Category: device, file, process, or system."
    )
    details: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Source-specific structured extras."
    )

    def get_canonical_source(self) -> str:
        """Maps source aliases to canonical names (usb, fs, eventlog, heartbeat)."""
        mapping = {
            "file_system": "fs",
            "fs": "fs",
            "usb_device": "usb",
            "usb": "usb",
            "event_log": "eventlog",
            "eventlog": "eventlog",
            "heartbeat": "heartbeat"
        }
        return mapping.get(self.source, self.source)

    def get_canonical_action(self) -> str:
        """Normalizes legacy action strings into the canonical enum if possible."""
        action_map = {
            "connected": "DEVICE_ARRIVED",
            "arrival": "DEVICE_ARRIVED",
            "disconnected": "DEVICE_REMOVED",
            "removal": "DEVICE_REMOVED",
            "created": "FILE_CREATED",
            "modified": "FILE_MODIFIED",
            "deleted": "FILE_DELETED",
            "moved": "FILE_MOVED",
            "logged": "PROCESS_STARTED",
            "process_created": "PROCESS_STARTED",
            "process_started": "PROCESS_STARTED",
            "log_cleared": "LOG_CLEARED",
            "audit_cleared": "LOG_CLEARED"
        }
        return action_map.get(self.action.lower(), self.action)

    def ensure_event_id(self) -> str:
        """Returns or lazily calculates a deterministic event_id hash."""
        if self.event_id:
            return self.event_id
        ts_str = self.timestamp.isoformat() if isinstance(self.timestamp, datetime) else str(self.timestamp)
        return _compute_default_event_id(self.source, self.entity, self.action, ts_str)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class EventRecord(EventCreate):
    """
    Schema representing a cryptographically chained evidence record stored in SQLite.
    """
    id: int = Field(
        ...,
        description="Monotonically increasing unique sequence ID."
    )
    prev_hash: str = Field(
        ...,
        description="SHA-256 hash of the preceding evidence record (or genesis zeros)."
    )
    record_hash: str = Field(
        ...,
        description="SHA-256 hash computed over this record's payload and preceding hash."
    )


class ActivityEventLink(BaseModel):
    """
    Represents a link in the activity_events table linking an activity to an event with a reason.
    """
    activity_id: int = Field(..., description="Foreign key to activities table.")
    event_id: int = Field(..., description="Foreign key to events table.")
    rule_id: str = Field(..., description="Identifier of the rule that linked this event.")
    reason: str = Field(..., description="Plain-English explanation of why this event is evidence.")


class ActivityCreate(BaseModel):
    """
    Schema representing a correlated forensic activity identified by the engine.
    """
    rule_name: str = Field(..., description="The name or ID of the correlation rule that triggered.")
    title: str = Field(..., description="Human-readable title of the activity.")
    narrative: str = Field(..., description="Explainable reconstruction description with event citations.")
    timestamp_start: datetime = Field(..., description="Start boundary of the correlated activity.")
    timestamp_end: datetime = Field(..., description="End boundary of the correlated activity.")
    confidence_score: float = Field(..., description="Confidence score from 0.0 to 1.0", ge=0.0, le=1.0)
    confidence_level: Literal["LOW", "MEDIUM", "HIGH"] = Field(..., description="Categorical confidence level.")
    evidence_event_ids: List[int] = Field(..., description="Provenance links to raw EventRecord IDs.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata such as timing breakdown and anomalies.")
    evidence_links: Optional[List[Dict[str, Any]]] = Field(
        default_factory=list,
        description="Structured links [{event_id, rule_id, reason}] for activity_events table."
    )

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class ActivityRecord(ActivityCreate):
    """
    Schema representing a stored forensic activity.
    """
    id: int = Field(..., description="Unique database ID of the activity.")


class ActivityDetail(BaseModel):
    """
    Complete activity view including its linked evidence items and provenance reasons.
    """
    activity: ActivityRecord
    evidence: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="List of evidence entries with event details, rule_id, and provenance reason."
    )


class TimelineItem(BaseModel):
    """
    Represents a unified point on the forensic timeline (either an activity or key event).
    """
    id: str = Field(..., description="Unique key for UI rendering (e.g. 'act-1' or 'ev-5').")
    item_type: Literal["activity", "event"] = Field(..., description="Discriminator type.")
    timestamp: datetime = Field(..., description="Timestamp of the timeline occurrence.")
    title: str = Field(..., description="Short summary title.")
    description: str = Field(..., description="Narrative or detailed context.")
    confidence_level: Optional[str] = Field(default=None, description="Confidence level if activity.")
    source: Optional[str] = Field(default=None, description="Source channel if event.")
    ref_id: int = Field(..., description="Original database ID.")
    metadata: Dict[str, Any] = Field(default_factory=dict)

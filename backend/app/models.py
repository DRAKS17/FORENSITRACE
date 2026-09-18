"""
ForensiTrace - Backend Data Models and Pydantic Schemas.
Defines normalized event schemas for incoming endpoint telemetry and stored records.
"""

from datetime import datetime
from typing import Any, Dict, List, Literal
from pydantic import BaseModel, Field


class EventCreate(BaseModel):
    """
    Schema representing an incoming normalized telemetry event from the endpoint agent.
    """

    source: Literal["file_system", "usb_device", "event_log", "heartbeat"] = Field(
        ...,
        description="Telemetry source channel that generated the event.",
        examples=["file_system", "usb_device", "event_log", "heartbeat"],
    )
    timestamp: datetime = Field(
        ...,
        description="Event creation timestamp in ISO-8601 UTC format.",
    )
    entity: str = Field(
        ...,
        description="Target entity involved (e.g., file path, drive letter, or provider/event ID).",
        examples=["C:\\Windows\\System32\\cmd.exe", "E:", "Microsoft-Windows-Security-Auditing/4688"],
    )
    action: str = Field(
        ...,
        description="Normalized action descriptor (e.g., created, modified, connected, logged).",
        examples=["created", "modified", "deleted", "connected", "disconnected", "logged"],
    )
    raw_data: Dict[str, Any] = Field(
        default_factory=dict,
        description="Original unnormalized metadata and contextual parameters from the collector.",
    )

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class EventRecord(EventCreate):
    """
    Schema representing a cryptographically chained evidence record stored in the database.
    """

    id: int = Field(
        ...,
        description="Monotonically increasing unique sequence ID.",
    )
    prev_hash: str = Field(
        ...,
        description="SHA-256 hash of the preceding evidence record (or genesis zeros).",
    )
    record_hash: str = Field(
        ...,
        description="SHA-256 hash computed over this record's payload and preceding hash.",
    )


class ActivityCreate(BaseModel):
    """
    Schema representing a correlated forensic activity identified by the engine.
    """
    rule_name: str = Field(..., description="The name of the correlation rule that triggered.")
    title: str = Field(..., description="Human-readable title of the activity.")
    narrative: str = Field(..., description="Explainable reconstruction description.")
    timestamp_start: datetime = Field(..., description="Start boundary of the correlated activity.")
    timestamp_end: datetime = Field(..., description="End boundary of the correlated activity.")
    confidence_score: float = Field(..., description="Confidence score from 0.0 to 1.0", ge=0.0, le=1.0)
    confidence_level: Literal["LOW", "MEDIUM", "HIGH"] = Field(..., description="Categorical confidence level.")
    evidence_event_ids: List[int] = Field(..., description="Provenance links to raw EventRecord IDs.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata such as timing breakdown and anomalies.")

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat()}


class ActivityRecord(ActivityCreate):
    """
    Schema representing a stored forensic activity.
    """
    id: int = Field(..., description="Unique database ID of the activity.")

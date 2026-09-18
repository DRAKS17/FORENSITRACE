"""
ForensiTrace - Backend Data Models and Pydantic Schemas.
Defines normalized event schemas for incoming endpoint telemetry and stored records.
"""

from datetime import datetime
from typing import Any, Dict, Literal
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

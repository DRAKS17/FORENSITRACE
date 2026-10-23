"""
ForensiTrace - Telemetry Normalizers
Maps raw events from heterogeneous Windows collectors (USB WMI, FileSystem watchdog,
pywin32/python-evtx Event Logs, psutil Heartbeats) into the canonical EventCreate schema.
"""

from datetime import datetime, timezone
import hashlib
import os
from typing import Any, Dict, Optional
from backend.app.models import EventCreate


def compute_event_id(source: str, record_id: str, ts_iso: str) -> str:
    """Computes a SHA-256 digest over source + record_id + timestamp for deduplication."""
    payload = f"{source}:{record_id}:{ts_iso}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def normalize_usb_event(raw: Dict[str, Any], host: str = "WIN-ENDPOINT", user: str = "SYSTEM") -> EventCreate:
    """Normalizes USB WMI device change / volume change events."""
    event_type = raw.get("event_type") or raw.get("EventType")
    action = "DEVICE_ARRIVED" if event_type in (2, "2", "arrival", "connected", "DEVICE_ARRIVED") else "DEVICE_REMOVED"
    
    drive_letter = raw.get("drive_letter") or raw.get("DriveName") or raw.get("entity") or "Unknown"
    volume_name = raw.get("volume_name") or raw.get("VolumeName") or ""
    serial = raw.get("serial_number") or raw.get("SerialNumber") or raw.get("device_id") or "UNKNOWN_SERIAL"
    
    entity_str = f"{drive_letter} ({volume_name})" if volume_name else str(drive_letter)
    ts = raw.get("timestamp") or raw.get("ts_utc") or datetime.now(timezone.utc).isoformat()
    if isinstance(ts, str):
        try:
            ts_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            ts_dt = datetime.now(timezone.utc)
    else:
        ts_dt = ts

    rec_id = f"{drive_letter}:{serial}:{action}"
    eid = raw.get("event_id") or compute_event_id("usb", rec_id, ts_dt.isoformat())

    details = {
        "drive_letter": drive_letter,
        "volume_name": volume_name,
        "serial_number": serial,
        "file_system": raw.get("file_system", ""),
        "size_bytes": raw.get("size_bytes"),
        "is_removable": raw.get("is_removable", True)
    }

    return EventCreate(
        source="usb",
        timestamp=ts_dt,
        entity=entity_str,
        action=action,
        raw_data=raw,
        event_id=eid,
        host=host,
        user=user,
        entity_type="device",
        details=details
    )


def normalize_fs_event(raw: Dict[str, Any], host: str = "WIN-ENDPOINT", user: str = "TargetUser") -> EventCreate:
    """Normalizes watchdog file system events."""
    event_type = str(raw.get("event_type") or raw.get("action") or "").lower()
    
    if "created" in event_type:
        action = "FILE_CREATED"
    elif "modified" in event_type:
        action = "FILE_MODIFIED"
    elif "deleted" in event_type:
        action = "FILE_DELETED"
    elif "moved" in event_type:
        action = "FILE_MOVED"
    else:
        action = "FILE_CREATED"

    file_path = raw.get("src_path") or raw.get("entity") or raw.get("path") or "UNKNOWN_PATH"
    ts = raw.get("timestamp") or raw.get("ts_utc") or datetime.now(timezone.utc).isoformat()
    if isinstance(ts, str):
        try:
            ts_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            ts_dt = datetime.now(timezone.utc)
    else:
        ts_dt = ts

    mtime = raw.get("mtime")
    if not mtime and os.path.exists(file_path):
        try:
            mtime = datetime.fromtimestamp(os.path.getmtime(file_path), tz=timezone.utc).isoformat()
        except OSError:
            mtime = ts_dt.isoformat()

    rec_id = f"{file_path}:{action}"
    eid = raw.get("event_id") or compute_event_id("fs", rec_id, ts_dt.isoformat())

    details = {
        "file_path": file_path,
        "file_name": os.path.basename(file_path),
        "file_extension": os.path.splitext(file_path)[1].lower(),
        "size_bytes": raw.get("size_bytes"),
        "is_directory": raw.get("is_directory", False),
        "mtime": mtime or ts_dt.isoformat()
    }

    return EventCreate(
        source="fs",
        timestamp=ts_dt,
        entity=file_path,
        action=action,
        raw_data=raw,
        event_id=eid,
        host=host,
        user=user,
        entity_type="file",
        details=details
    )


def normalize_eventlog_event(raw: Dict[str, Any], host: str = "WIN-ENDPOINT", user: str = "TargetUser") -> EventCreate:
    """Normalizes Windows Event Log entries (4688, 4624, 1102, 104)."""
    event_id_val = raw.get("event_id") or raw.get("EventID") or 0
    channel = raw.get("channel") or raw.get("Channel") or "Security"
    record_num = raw.get("record_number") or raw.get("RecordNumber") or 0
    provider = raw.get("provider_name") or raw.get("SourceName") or "Microsoft-Windows-Security-Auditing"

    # Action detection
    if event_id_val == 4688:
        action = "PROCESS_STARTED"
        entity_type = "process"
        entity = raw.get("command_line") or raw.get("process_name") or raw.get("entity") or f"{provider}/{event_id_val}"
    elif event_id_val == 4624:
        action = "USER_LOGON"
        entity_type = "system"
        entity = f"Logon:{raw.get('target_user', user)}"
    elif event_id_val in (1102, 104):
        action = "LOG_CLEARED"
        entity_type = "system"
        entity = f"LogCleared:{channel}"
    else:
        action = "PROCESS_STARTED" if "process" in str(raw).lower() else "EVENT_LOGGED"
        entity_type = "system"
        entity = raw.get("entity") or f"{provider}/{event_id_val}"

    ts = raw.get("timestamp") or raw.get("time_generated") or raw.get("ts_utc") or datetime.now(timezone.utc).isoformat()
    if isinstance(ts, str):
        try:
            ts_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            ts_dt = datetime.now(timezone.utc)
    else:
        ts_dt = ts

    rec_id = f"{channel}:{record_num}:{event_id_val}"
    eid = raw.get("event_id_hash") or compute_event_id("eventlog", rec_id, ts_dt.isoformat())

    details = {
        "channel": channel,
        "event_id": event_id_val,
        "record_number": record_num,
        "provider": provider,
        "process_name": raw.get("process_name", ""),
        "command_line": raw.get("command_line", ""),
        "parent_process": raw.get("parent_process_name", "")
    }

    return EventCreate(
        source="eventlog",
        timestamp=ts_dt,
        entity=str(entity),
        action=action,
        raw_data=raw,
        event_id=eid,
        host=raw.get("computer_name") or host,
        user=raw.get("user") or user,
        entity_type=entity_type,
        details=details
    )


def normalize_heartbeat_event(raw: Dict[str, Any], host: str = "WIN-ENDPOINT") -> EventCreate:
    """Normalizes agent health telemetry."""
    ts = raw.get("timestamp") or raw.get("ts_utc") or datetime.now(timezone.utc).isoformat()
    if isinstance(ts, str):
        try:
            ts_dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            ts_dt = datetime.now(timezone.utc)
    else:
        ts_dt = ts

    cpu = raw.get("cpu_percent", 0.0)
    mem = raw.get("memory_mb", 0.0)
    rec_id = f"heartbeat:{cpu}:{mem}"
    eid = raw.get("event_id") or compute_event_id("heartbeat", rec_id, ts_dt.isoformat())

    return EventCreate(
        source="heartbeat",
        timestamp=ts_dt,
        entity="agent_monitor",
        action="HEARTBEAT",
        raw_data=raw,
        event_id=eid,
        host=host,
        user="SYSTEM",
        entity_type="system",
        details={"cpu_percent": cpu, "memory_mb": mem}
    )

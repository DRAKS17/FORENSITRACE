"""
ForensiTrace - Dynamic ML Feature Extraction (PURVA, AKASH)
Extracts feature vectors from normalized telemetry events strictly according to docs/ml.md.
Dynamically computes feature dimension from the canonical schema actions + 3 context features.
"""

from datetime import datetime, timezone
import logging
import math
import os
import re
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np

logger = logging.getLogger(__name__)

# Canonical actions directly extracted from docs/schema.md Section 2
# Kept in deterministic canonical order
SCHEMA_ACTIONS: List[str] = [
    "DEVICE_ARRIVED",
    "DEVICE_REMOVED",
    "FILE_CREATED",
    "FILE_MODIFIED",
    "FILE_DELETED",
    "FILE_MOVED",
    "PROCESS_STARTED",
    "LOG_CLEARED",
    "USER_LOGON",
    "HEARTBEAT"
]

# Action synonym and alias normalizer
ACTION_ALIASES: Dict[str, str] = {
    "arrival": "DEVICE_ARRIVED",
    "connected": "DEVICE_ARRIVED",
    "removal": "DEVICE_REMOVED",
    "disconnected": "DEVICE_REMOVED",
    "created": "FILE_CREATED",
    "modified": "FILE_MODIFIED",
    "deleted": "FILE_DELETED",
    "moved": "FILE_MOVED",
    "logged": "PROCESS_STARTED",
    "process_created": "PROCESS_STARTED",
    "process_started": "PROCESS_STARTED",
    "log_cleared": "LOG_CLEARED",
    "audit_cleared": "LOG_CLEARED",
    "logon": "USER_LOGON",
    "user_logon": "USER_LOGON",
    "heartbeat": "HEARTBEAT"
}

EXECUTABLE_EXTENSIONS = {
    ".exe", ".bat", ".ps1", ".cmd", ".vbs", ".dll", ".scr", ".msi", ".com", ".pif", ".cpl"
}


def get_feature_vector_size() -> int:
    """
    Returns the dynamic vector dimension D = len(SCHEMA_ACTIONS) + 3.
    Strictly follows the project rule: Never hard-code the feature vector size!
    """
    return len(SCHEMA_ACTIONS) + 3


def normalize_action_name(action: str) -> str:
    """Maps raw action strings or aliases to canonical schema action."""
    if not action:
        return "HEARTBEAT"
    cleaned = str(action).strip()
    upper = cleaned.upper()
    if upper in SCHEMA_ACTIONS:
        return upper
    lower = cleaned.lower()
    return ACTION_ALIASES.get(lower, upper)


def parse_timestamp_utc(ts: Union[str, datetime, float, int]) -> datetime:
    """Parses arbitrary timestamp representations into UTC datetime."""
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(ts, str):
        # Support ISO 8601 strings
        try:
            cleaned = ts.replace("Z", "+00:00")
            dt = datetime.fromisoformat(cleaned)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass
    return datetime.now(timezone.utc)


def is_executable_entity(entity: str, details: Optional[Dict[str, Any]] = None) -> bool:
    """Determines whether the event target represents an executable binary or script."""
    if not entity:
        return False
    path_str = str(entity).lower().strip()
    _, ext = os.path.splitext(path_str)
    if ext in EXECUTABLE_EXTENSIONS:
        return True
    if details:
        ext_detail = str(details.get("file_extension", "")).lower().strip()
        if ext_detail in EXECUTABLE_EXTENSIONS:
            return True
        proc_name = str(details.get("process_name", "")).lower().strip()
        _, pext = os.path.splitext(proc_name)
        if pext in EXECUTABLE_EXTENSIONS:
            return True
    return False


def is_removable_drive(entity: str, details: Optional[Dict[str, Any]] = None) -> bool:
    """Checks whether the entity resides on a drive letter other than the system root C:."""
    if not entity:
        return False
    entity_str = str(entity).strip().upper()
    # Check drive letter prefix, e.g. E: or E:\
    if len(entity_str) >= 2 and entity_str[1] == ":":
        drive = entity_str[:2]
        if drive != "C:":
            return True
    if details:
        drive_letter = str(details.get("drive_letter", "")).strip().upper()
        if drive_letter and drive_letter != "C:":
            return True
    return False


def extract_event_features(
    event: Any,
    prev_event: Optional[Any] = None
) -> np.ndarray:
    """
    Extracts a dynamic (len(SCHEMA_ACTIONS) + 3)-dimensional feature vector from an event.
    
    Layout:
      [0 : len(SCHEMA_ACTIONS)] -> One-hot action encoding
      [len(SCHEMA_ACTIONS) + 0] -> log(1 + seconds_elapsed_since_prev)
      [len(SCHEMA_ACTIONS) + 1] -> Executable flag (1 or 0)
      [len(SCHEMA_ACTIONS) + 2] -> Removable drive flag (1 or 0)
    """
    total_dim = get_feature_vector_size()
    vec = np.zeros(total_dim, dtype=np.float32)

    # 1. Extract raw fields
    if hasattr(event, "action"):
        raw_action = getattr(event, "action", "")
        raw_ts = getattr(event, "timestamp", None)
        raw_entity = getattr(event, "entity", "")
        raw_details = getattr(event, "details", {}) or getattr(event, "raw_data", {})
    elif isinstance(event, dict):
        raw_action = event.get("action", "")
        raw_ts = event.get("timestamp") or event.get("ts_utc")
        raw_entity = event.get("entity", "")
        raw_details = event.get("details", {}) or event.get("raw", {})
    else:
        raw_action = ""
        raw_ts = None
        raw_entity = ""
        raw_details = {}

    # 2. Action One-Hot
    canonical_action = normalize_action_name(raw_action)
    if canonical_action in SCHEMA_ACTIONS:
        idx = SCHEMA_ACTIONS.index(canonical_action)
        vec[idx] = 1.0
    else:
        # If action unrecognized, default to HEARTBEAT slot to maintain total sum
        vec[SCHEMA_ACTIONS.index("HEARTBEAT")] = 1.0

    # 3. Time Delta Feature: log(1 + seconds_elapsed)
    ts_current = parse_timestamp_utc(raw_ts)
    if prev_event is not None:
        if hasattr(prev_event, "timestamp"):
            ts_prev = parse_timestamp_utc(getattr(prev_event, "timestamp"))
        elif isinstance(prev_event, dict):
            ts_prev = parse_timestamp_utc(prev_event.get("timestamp") or prev_event.get("ts_utc"))
        else:
            ts_prev = ts_current
        delta_sec = max(0.0, (ts_current - ts_prev).total_seconds())
    else:
        delta_sec = 0.0

    vec[len(SCHEMA_ACTIONS)] = float(math.log(1.0 + delta_sec))

    # 4. Executable Flag
    vec[len(SCHEMA_ACTIONS) + 1] = 1.0 if is_executable_entity(raw_entity, raw_details) else 0.0

    # 5. Removable Drive Flag
    vec[len(SCHEMA_ACTIONS) + 2] = 1.0 if is_removable_drive(raw_entity, raw_details) else 0.0

    return vec


def create_sliding_windows(
    events: List[Any],
    window_size: int = 10,
    step: int = 1
) -> Tuple[np.ndarray, List[List[Any]]]:
    """
    Transforms a chronological event list into sliding windows of feature vectors.
    Returns:
        windows: np.ndarray of shape (num_windows, window_size, feature_dim)
        window_events: List of event sub-lists corresponding to each window.
    """
    if not events:
        dim = get_feature_vector_size()
        return np.zeros((0, window_size, dim), dtype=np.float32), []

    # Extract sequential feature vectors
    vectors = []
    prev_e = None
    for e in events:
        v = extract_event_features(e, prev_e)
        vectors.append(v)
        prev_e = e

    vectors_arr = np.array(vectors, dtype=np.float32)
    dim = vectors_arr.shape[1]
    total_events = len(events)

    if total_events < window_size:
        # Pad with zero-vectors at the beginning to form at least 1 window
        pad_count = window_size - total_events
        padded = np.zeros((window_size, dim), dtype=np.float32)
        padded[pad_count:] = vectors_arr
        windows = np.expand_dims(padded, axis=0)
        return windows, [list(events)]

    windows_list = []
    events_list = []
    for i in range(0, total_events - window_size + 1, step):
        w = vectors_arr[i : i + window_size]
        windows_list.append(w)
        events_list.append(events[i : i + window_size])

    return np.array(windows_list, dtype=np.float32), events_list


class FeatureExtractor:
    """Wrapper class providing feature extraction services for pipeline integration."""

    def __init__(self):
        self.actions = list(SCHEMA_ACTIONS)
        self.vector_size = get_feature_vector_size()
        logger.info("Initialized FeatureExtractor: dimension=%d (%d actions + 3 context features)",
                    self.vector_size, len(self.actions))

    def extract(self, event: Any, prev_event: Optional[Any] = None) -> np.ndarray:
        return extract_event_features(event, prev_event)

    def extract_windows(self, events: List[Any], window_size: int = 10, step: int = 1) -> Tuple[np.ndarray, List[List[Any]]]:
        return create_sliding_windows(events, window_size=window_size, step=step)

"""
ForensiTrace - Session-Based Dataset Management (PURVA, DAKSH)
Generates, loads, splits, and exports baseline workstation telemetry sessions.
Enforces the project rule: Split by recording session, never by random event!
"""

from datetime import datetime, timezone, timedelta
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

logger = logging.getLogger(__name__)

# Base directory for ML datasets
DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "ml"


def generate_baseline_sessions() -> Dict[str, List[Dict[str, Any]]]:
    """
    Generates realistic normal workstation sessions captured across multiple days/sessions.
    Includes ordinary USB flash drive usage so routine removable drive operations
    are recognized as benign and do not cause false positives.
    """
    sessions: Dict[str, List[Dict[str, Any]]] = {}
    base_time = datetime(2026, 10, 20, 9, 0, 0, tzinfo=timezone.utc)

    # -------------------------------------------------------------------------
    # Session 1: Normal Office & Productivity Work (Host: WIN-OFFICE-01)
    # -------------------------------------------------------------------------
    s1_id = "sess_normal_office_01"
    s1_events = []
    t = base_time
    s1_events.append({
        "session_id": s1_id, "host": "WIN-OFFICE-01", "source": "heartbeat", "action": "HEARTBEAT",
        "timestamp": t.isoformat(), "entity": "agent_service",
        "details": {"cpu_percent": 0.4, "memory_mb": 22.0}
    })
    t += timedelta(seconds=15)
    s1_events.append({
        "session_id": s1_id, "host": "WIN-OFFICE-01", "source": "eventlog", "action": "USER_LOGON",
        "timestamp": t.isoformat(), "entity": "TargetUser",
        "details": {"event_id": 4624, "logon_type": 2, "user": "TargetUser"}
    })
    t += timedelta(seconds=10)
    s1_events.append({
        "session_id": s1_id, "host": "WIN-OFFICE-01", "source": "eventlog", "action": "PROCESS_STARTED",
        "timestamp": t.isoformat(), "entity": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
        "details": {"event_id": 4688, "process_name": "WINWORD.EXE"}
    })
    t += timedelta(seconds=8)
    s1_events.append({
        "session_id": s1_id, "host": "WIN-OFFICE-01", "source": "fs", "action": "FILE_CREATED",
        "timestamp": t.isoformat(), "entity": "C:\\Users\\TargetUser\\Documents\\Quarterly_Report.docx",
        "details": {"file_extension": ".docx", "size_bytes": 45056}
    })
    t += timedelta(seconds=35)
    s1_events.append({
        "session_id": s1_id, "host": "WIN-OFFICE-01", "source": "fs", "action": "FILE_MODIFIED",
        "timestamp": t.isoformat(), "entity": "C:\\Users\\TargetUser\\Documents\\Quarterly_Report.docx",
        "details": {"file_extension": ".docx", "size_bytes": 52100}
    })
    t += timedelta(seconds=30)
    s1_events.append({
        "session_id": s1_id, "host": "WIN-OFFICE-01", "source": "heartbeat", "action": "HEARTBEAT",
        "timestamp": t.isoformat(), "entity": "agent_service",
        "details": {"cpu_percent": 0.5, "memory_mb": 22.8}
    })
    t += timedelta(seconds=12)
    s1_events.append({
        "session_id": s1_id, "host": "WIN-OFFICE-01", "source": "eventlog", "action": "PROCESS_STARTED",
        "timestamp": t.isoformat(), "entity": "C:\\Program Files\\Microsoft Office\\EXCEL.EXE",
        "details": {"event_id": 4688, "process_name": "EXCEL.EXE"}
    })
    t += timedelta(seconds=6)
    s1_events.append({
        "session_id": s1_id, "host": "WIN-OFFICE-01", "source": "fs", "action": "FILE_CREATED",
        "timestamp": t.isoformat(), "entity": "C:\\Users\\TargetUser\\Documents\\Financial_Model.xlsx",
        "details": {"file_extension": ".xlsx", "size_bytes": 128000}
    })
    t += timedelta(seconds=20)
    s1_events.append({
        "session_id": s1_id, "host": "WIN-OFFICE-01", "source": "fs", "action": "FILE_MODIFIED",
        "timestamp": t.isoformat(), "entity": "C:\\Users\\TargetUser\\Documents\\Financial_Model.xlsx",
        "details": {"file_extension": ".xlsx", "size_bytes": 132400}
    })
    t += timedelta(seconds=30)
    s1_events.append({
        "session_id": s1_id, "host": "WIN-OFFICE-01", "source": "heartbeat", "action": "HEARTBEAT",
        "timestamp": t.isoformat(), "entity": "agent_service",
        "details": {"cpu_percent": 0.3, "memory_mb": 22.4}
    })
    sessions[s1_id] = s1_events

    # -------------------------------------------------------------------------
    # Session 2: Developer & Engineering Activity (Host: WIN-DEV-02)
    # -------------------------------------------------------------------------
    s2_id = "sess_normal_dev_02"
    s2_events = []
    t = base_time + timedelta(hours=2)
    s2_events.append({
        "session_id": s2_id, "host": "WIN-DEV-02", "source": "heartbeat", "action": "HEARTBEAT",
        "timestamp": t.isoformat(), "entity": "agent_service",
        "details": {"cpu_percent": 0.6, "memory_mb": 24.1}
    })
    t += timedelta(seconds=10)
    s2_events.append({
        "session_id": s2_id, "host": "WIN-DEV-02", "source": "eventlog", "action": "PROCESS_STARTED",
        "timestamp": t.isoformat(), "entity": "C:\\Users\\Dev\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
        "details": {"event_id": 4688, "process_name": "Code.exe"}
    })
    t += timedelta(seconds=15)
    s2_events.append({
        "session_id": s2_id, "host": "WIN-DEV-02", "source": "fs", "action": "FILE_CREATED",
        "timestamp": t.isoformat(), "entity": "C:\\Users\\Dev\\Projects\\app\\main.py",
        "details": {"file_extension": ".py", "size_bytes": 2048}
    })
    t += timedelta(seconds=18)
    s2_events.append({
        "session_id": s2_id, "host": "WIN-DEV-02", "source": "fs", "action": "FILE_MODIFIED",
        "timestamp": t.isoformat(), "entity": "C:\\Users\\Dev\\Projects\\app\\main.py",
        "details": {"file_extension": ".py", "size_bytes": 3120}
    })
    t += timedelta(seconds=25)
    s2_events.append({
        "session_id": s2_id, "host": "WIN-DEV-02", "source": "eventlog", "action": "PROCESS_STARTED",
        "timestamp": t.isoformat(), "entity": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "details": {"event_id": 4688, "process_name": "powershell.exe"}
    })
    t += timedelta(seconds=12)
    s2_events.append({
        "session_id": s2_id, "host": "WIN-DEV-02", "source": "eventlog", "action": "PROCESS_STARTED",
        "timestamp": t.isoformat(), "entity": "C:\\Python313\\python.exe",
        "details": {"event_id": 4688, "process_name": "python.exe", "command_line": "python -m unittest"}
    })
    t += timedelta(seconds=30)
    s2_events.append({
        "session_id": s2_id, "host": "WIN-DEV-02", "source": "heartbeat", "action": "HEARTBEAT",
        "timestamp": t.isoformat(), "entity": "agent_service",
        "details": {"cpu_percent": 0.8, "memory_mb": 25.0}
    })
    sessions[s2_id] = s2_events

    # -------------------------------------------------------------------------
    # Session 3: Benign USB Usage (Ordinary Thumbdrive with Presentation)
    # -------------------------------------------------------------------------
    s3_id = "sess_normal_usb_03"
    s3_events = []
    t = base_time + timedelta(hours=4)
    s3_events.append({
        "session_id": s3_id, "host": "WIN-OFFICE-01", "source": "heartbeat", "action": "HEARTBEAT",
        "timestamp": t.isoformat(), "entity": "agent_service",
        "details": {"cpu_percent": 0.4, "memory_mb": 23.0}
    })
    t += timedelta(seconds=5)
    s3_events.append({
        "session_id": s3_id, "host": "WIN-OFFICE-01", "source": "usb", "action": "DEVICE_ARRIVED",
        "timestamp": t.isoformat(), "entity": "F: (SanDisk Ultra)",
        "details": {"drive_letter": "F:", "volume_name": "SanDisk Ultra", "serial": "SD88123"}
    })
    t += timedelta(seconds=20)
    # User reads presentation slide deck from USB, copies to Desktop
    s3_events.append({
        "session_id": s3_id, "host": "WIN-OFFICE-01", "source": "fs", "action": "FILE_CREATED",
        "timestamp": t.isoformat(), "entity": "C:\\Users\\TargetUser\\Desktop\\Meeting_Slides.pptx",
        "details": {"file_extension": ".pptx", "size_bytes": 5242880}
    })
    t += timedelta(seconds=15)
    s3_events.append({
        "session_id": s3_id, "host": "WIN-OFFICE-01", "source": "eventlog", "action": "PROCESS_STARTED",
        "timestamp": t.isoformat(), "entity": "C:\\Program Files\\Microsoft Office\\POWERPNT.EXE",
        "details": {"event_id": 4688, "process_name": "POWERPNT.EXE"}
    })
    t += timedelta(seconds=60)
    s3_events.append({
        "session_id": s3_id, "host": "WIN-OFFICE-01", "source": "usb", "action": "DEVICE_REMOVED",
        "timestamp": t.isoformat(), "entity": "F: (SanDisk Ultra)",
        "details": {"drive_letter": "F:"}
    })
    t += timedelta(seconds=30)
    s3_events.append({
        "session_id": s3_id, "host": "WIN-OFFICE-01", "source": "heartbeat", "action": "HEARTBEAT",
        "timestamp": t.isoformat(), "entity": "agent_service",
        "details": {"cpu_percent": 0.3, "memory_mb": 22.5}
    })
    sessions[s3_id] = s3_events

    # -------------------------------------------------------------------------
    # Session 4: Web Browsing & System Maintenance (Validation Set Session)
    # -------------------------------------------------------------------------
    s4_id = "sess_normal_web_04"
    s4_events = []
    t = base_time + timedelta(hours=6)
    s4_events.append({
        "session_id": s4_id, "host": "WIN-OFFICE-01", "source": "heartbeat", "action": "HEARTBEAT",
        "timestamp": t.isoformat(), "entity": "agent_service",
        "details": {"cpu_percent": 0.5, "memory_mb": 23.5}
    })
    t += timedelta(seconds=10)
    s4_events.append({
        "session_id": s4_id, "host": "WIN-OFFICE-01", "source": "eventlog", "action": "PROCESS_STARTED",
        "timestamp": t.isoformat(), "entity": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "details": {"event_id": 4688, "process_name": "chrome.exe"}
    })
    t += timedelta(seconds=15)
    s4_events.append({
        "session_id": s4_id, "host": "WIN-OFFICE-01", "source": "fs", "action": "FILE_CREATED",
        "timestamp": t.isoformat(), "entity": "C:\\Users\\TargetUser\\AppData\\Local\\Google\\Chrome\\Cache\\data_0",
        "details": {"file_extension": "", "size_bytes": 1048576}
    })
    t += timedelta(seconds=20)
    s4_events.append({
        "session_id": s4_id, "host": "WIN-OFFICE-01", "source": "fs", "action": "FILE_MODIFIED",
        "timestamp": t.isoformat(), "entity": "C:\\Users\\TargetUser\\AppData\\Local\\Google\\Chrome\\Cache\\data_0",
        "details": {"file_extension": "", "size_bytes": 2097152}
    })
    t += timedelta(seconds=30)
    s4_events.append({
        "session_id": s4_id, "host": "WIN-OFFICE-01", "source": "heartbeat", "action": "HEARTBEAT",
        "timestamp": t.isoformat(), "entity": "agent_service",
        "details": {"cpu_percent": 0.4, "memory_mb": 23.2}
    })
    sessions[s4_id] = s4_events

    # -------------------------------------------------------------------------
    # Session 5: Held-out Normal Evaluation Session (Test Set Session)
    # -------------------------------------------------------------------------
    s5_id = "sess_normal_eval_05"
    s5_events = []
    t = base_time + timedelta(hours=8)
    s5_events.append({
        "session_id": s5_id, "host": "WIN-DEV-02", "source": "heartbeat", "action": "HEARTBEAT",
        "timestamp": t.isoformat(), "entity": "agent_service",
        "details": {"cpu_percent": 0.5, "memory_mb": 24.0}
    })
    t += timedelta(seconds=12)
    s5_events.append({
        "session_id": s5_id, "host": "WIN-DEV-02", "source": "eventlog", "action": "PROCESS_STARTED",
        "timestamp": t.isoformat(), "entity": "C:\\Windows\\System32\\notepad.exe",
        "details": {"event_id": 4688, "process_name": "notepad.exe"}
    })
    t += timedelta(seconds=15)
    s5_events.append({
        "session_id": s5_id, "host": "WIN-DEV-02", "source": "fs", "action": "FILE_CREATED",
        "timestamp": t.isoformat(), "entity": "C:\\Users\\Dev\\Desktop\\meeting_notes.txt",
        "details": {"file_extension": ".txt", "size_bytes": 1024}
    })
    t += timedelta(seconds=20)
    s5_events.append({
        "session_id": s5_id, "host": "WIN-DEV-02", "source": "fs", "action": "FILE_MODIFIED",
        "timestamp": t.isoformat(), "entity": "C:\\Users\\Dev\\Desktop\\meeting_notes.txt",
        "details": {"file_extension": ".txt", "size_bytes": 2450}
    })
    t += timedelta(seconds=30)
    s5_events.append({
        "session_id": s5_id, "host": "WIN-DEV-02", "source": "heartbeat", "action": "HEARTBEAT",
        "timestamp": t.isoformat(), "entity": "agent_service",
        "details": {"cpu_percent": 0.4, "memory_mb": 23.9}
    })
    sessions[s5_id] = s5_events

    return sessions


def split_sessions_train_val_test(
    sessions: Dict[str, List[Dict[str, Any]]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, str]]:
    """
    Performs strict session-based splitting into Train, Validation, and Test sets.
    Guarantee: Events from one session must NEVER appear in multiple splits!
    
    Returns:
        train_events, val_events, test_events, session_assignment_map
    """
    session_names = sorted(sessions.keys())
    # Deterministic split:
    # Train: sess_normal_office_01, sess_normal_dev_02, sess_normal_usb_03
    # Val: sess_normal_web_04
    # Test: sess_normal_eval_05
    train_keys: Set[str] = set()
    val_keys: Set[str] = set()
    test_keys: Set[str] = set()

    for idx, s_key in enumerate(session_names):
        if idx < max(1, len(session_names) - 2):
            train_keys.add(s_key)
        elif idx == len(session_names) - 2:
            val_keys.add(s_key)
        else:
            test_keys.add(s_key)

    # Verification of strict disjointness
    assert train_keys.isdisjoint(val_keys), "Data leakage: Train and Val overlap!"
    assert train_keys.isdisjoint(test_keys), "Data leakage: Train and Test overlap!"
    assert val_keys.isdisjoint(test_keys), "Data leakage: Val and Test overlap!"

    train_events: List[Dict[str, Any]] = []
    val_events: List[Dict[str, Any]] = []
    test_events: List[Dict[str, Any]] = []
    assignment_map: Dict[str, str] = {}

    for k in train_keys:
        train_events.extend(sessions[k])
        assignment_map[k] = "train"
    for k in val_keys:
        val_events.extend(sessions[k])
        assignment_map[k] = "val"
    for k in test_keys:
        test_events.extend(sessions[k])
        assignment_map[k] = "test"

    logger.info("Split %d sessions into Train (%d events from %s), Val (%d events from %s), Test (%d events from %s)",
                len(sessions), len(train_events), list(train_keys),
                len(val_events), list(val_keys),
                len(test_events), list(test_keys))

    return train_events, val_events, test_events, assignment_map


def export_ml_datasets(output_dir: Optional[Union[str, Path]] = None) -> Dict[str, str]:
    """Generates baseline data and writes train.json, val.json, test.json to disk."""
    out_path = Path(output_dir or DATA_DIR).resolve()
    out_path.mkdir(parents=True, exist_ok=True)

    sessions = generate_baseline_sessions()
    train_events, val_events, test_events, assignment_map = split_sessions_train_val_test(sessions)

    paths = {
        "train": str(out_path / "train_events.json"),
        "val": str(out_path / "val_events.json"),
        "test": str(out_path / "test_events.json"),
        "sessions": str(out_path / "sessions.json"),
        "manifest": str(out_path / "manifest.json")
    }

    with open(paths["train"], "w", encoding="utf-8") as f:
        json.dump(train_events, f, indent=2)

    with open(paths["val"], "w", encoding="utf-8") as f:
        json.dump(val_events, f, indent=2)

    with open(paths["test"], "w", encoding="utf-8") as f:
        json.dump(test_events, f, indent=2)

    with open(paths["sessions"], "w", encoding="utf-8") as f:
        json.dump(sessions, f, indent=2)

    with open(paths["manifest"], "w", encoding="utf-8") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "session_counts": len(sessions),
            "session_assignments": assignment_map,
            "counts": {
                "train_events": len(train_events),
                "val_events": len(val_events),
                "test_events": len(test_events)
            }
        }, f, indent=2)

    logger.info("Successfully exported ML datasets to %s", out_path)
    return paths


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    export_ml_datasets()

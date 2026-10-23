"""
ForensiTrace - One-Command Startup & Demo Orchestrator (PURVA)
Prepares the database, seeds demo evidence, triggers correlation,
starts both backend (FastAPI) and frontend (Vite) servers, and opens the dashboard.
"""

from datetime import datetime, timezone, timedelta
import os
import subprocess
import sys
import time
import webbrowser

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from backend.app.database import EvidenceStore
from backend.app.models import EventCreate
from backend.app.engine import CorrelationEngine


def seed_demo_data(store: EvidenceStore):
    print("[*] Seeding initial forensic attack scenario...")
    t0 = datetime.now(timezone.utc) - timedelta(minutes=2)

    # 1. Heartbeat
    store.insert_event(EventCreate(
        source="heartbeat",
        timestamp=t0,
        entity="agent_monitor",
        action="HEARTBEAT",
        details={"cpu_percent": 0.8, "memory_mb": 24.5}
    ))

    # 2. USB Device Arrival (E:)
    t1 = t0 + timedelta(seconds=2)
    ev_usb = store.insert_event(EventCreate(
        source="usb",
        timestamp=t1,
        entity="E: (Kingston DataTraveler)",
        action="DEVICE_ARRIVED",
        entity_type="device",
        details={"drive_letter": "E:", "volume_name": "Kingston DataTraveler", "serial": "KT98412", "file_system": "FAT32"}
    ))

    # 3. File Staging on Removable Drive
    t2 = t0 + timedelta(seconds=5)
    ev_file = store.insert_event(EventCreate(
        source="fs",
        timestamp=t2,
        entity="E:\\backdoor_payload.exe",
        action="FILE_CREATED",
        entity_type="file",
        details={"file_extension": ".exe", "size_bytes": 524288, "mtime": t2.isoformat()}
    ))

    # 4. Process Execution (Event 4688)
    t3 = t0 + timedelta(seconds=7)
    ev_exec = store.insert_event(EventCreate(
        source="eventlog",
        timestamp=t3,
        entity="E:\\backdoor_payload.exe",
        action="PROCESS_STARTED",
        entity_type="process",
        details={"event_id": 4688, "process_name": "backdoor_payload.exe", "command_line": "\"E:\\backdoor_payload.exe\" --silent"}
    ))

    # 5. Anti-Forensic Audit Log Cleared (Event 1102)
    t4 = t0 + timedelta(seconds=12)
    ev_clear = store.insert_event(EventCreate(
        source="eventlog",
        timestamp=t4,
        entity="LogCleared:Security",
        action="LOG_CLEARED",
        entity_type="system",
        details={"event_id": 1102, "channel": "Security"}
    ))

    # Run Correlation Engine
    engine = CorrelationEngine()
    events = store.get_events(limit=100)
    activities = engine.analyze(events)
    for act in activities:
        store.insert_activity(act)

    print(f"[+] Seeding complete: {len(events)} events stored, {len(activities)} correlated activities reconstructed.")


def main():
    print("=" * 80)
    print(" FORENSITRACE - ONE-COMMAND DEMO STARTUP")
    print("=" * 80)

    # 1. Reset and Seed Database
    db_path = os.path.join(ROOT_DIR, "forensitrace.db")
    store = EvidenceStore(db_path)
    store.clear_database()
    seed_demo_data(store)

    # 2. Check Database Integrity
    is_intact, _ = store.verify_integrity()
    print(f"[+] Database Cryptographic Hash Chain: {'VERIFIED' if is_intact else 'COMPROMISED'}")

    # 3. Launch Backend Server
    print("\n[*] Starting FastAPI backend server on http://localhost:8000...")
    backend_env = os.environ.copy()
    backend_env["PYTHONPATH"] = ROOT_DIR
    backend_proc = subprocess.Popen(
        [sys.executable, "-m", "backend.app.main"],
        cwd=ROOT_DIR,
        env=backend_env
    )

    # 4. Launch React Frontend
    print("[*] Starting Vite React dashboard on http://localhost:5173...")
    frontend_dir = os.path.join(ROOT_DIR, "frontend")
    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
    frontend_proc = subprocess.Popen(
        [npm_cmd, "run", "dev"],
        cwd=frontend_dir
    )

    # Give servers 2 seconds to initialize
    time.sleep(2.5)

    # 5. Open Web Browser
    dashboard_url = "http://localhost:5173"
    print(f"[+] Opening ForensiTrace Dashboard at {dashboard_url}...")
    try:
        webbrowser.open(dashboard_url)
    except Exception:
        pass

    print("\n" + "=" * 80)
    print(" DEMO RUNNING: Press Ctrl+C at any time to cleanly stop all servers.")
    print("=" * 80)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down demo servers...")
        frontend_proc.terminate()
        backend_proc.terminate()
        print("[+] All ForensiTrace demo processes stopped cleanly.")


if __name__ == "__main__":
    main()

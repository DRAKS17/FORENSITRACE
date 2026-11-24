"""
ForensiTrace - One-Command Demo Runner (DAKSH, PURVA)
Strictly conforms to Build Plan Page 10 (Step 4):
  Resets database, verifies LSTM model artifacts, seeds Scenario A attack telemetry,
  executes correlation engine with hybrid ML anomaly scoring, launches backend and frontend,
  and opens the web dashboard in the default browser.
"""

from datetime import datetime, timezone, timedelta
import os
from pathlib import Path
import subprocess
import sys
import time
import webbrowser

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.app.database import EvidenceStore
from backend.app.models import EventCreate
from backend.app.engine import CorrelationEngine
from engine.ml.scoring import get_scoring_service


def seed_demo_data(store: EvidenceStore):
    print("[*] Seeding Scenario A (USB Staging -> Execution -> Anti-Forensics)...")
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
    store.insert_event(EventCreate(
        source="usb",
        timestamp=t1,
        entity="E: (Kingston DataTraveler)",
        action="DEVICE_ARRIVED",
        entity_type="device",
        details={"drive_letter": "E:", "volume_name": "Kingston DataTraveler", "serial": "KT98412", "file_system": "FAT32"}
    ))

    # 3. File Staging on Removable Drive
    t2 = t0 + timedelta(seconds=5)
    store.insert_event(EventCreate(
        source="fs",
        timestamp=t2,
        entity="E:\\backdoor_payload.exe",
        action="FILE_CREATED",
        entity_type="file",
        details={"file_extension": ".exe", "size_bytes": 524288, "mtime": t2.isoformat()}
    ))

    # 4. Process Execution (Event 4688)
    t3 = t0 + timedelta(seconds=7)
    store.insert_event(EventCreate(
        source="eventlog",
        timestamp=t3,
        entity="E:\\backdoor_payload.exe",
        action="PROCESS_STARTED",
        entity_type="process",
        details={"event_id": 4688, "process_name": "backdoor_payload.exe", "command_line": "\"E:\\backdoor_payload.exe\" --silent"}
    ))

    # 5. Anti-Forensic Audit Log Cleared (Event 1102)
    t4 = t0 + timedelta(seconds=12)
    store.insert_event(EventCreate(
        source="eventlog",
        timestamp=t4,
        entity="LogCleared:Security",
        action="LOG_CLEARED",
        entity_type="system",
        details={"event_id": 1102, "channel": "Security"}
    ))

    # 6. Execute Correlation Engine with Hybrid ML Scoring
    print("[*] Running Correlation Engine and LSTM Autoencoder Sequence Scorer...")
    engine = CorrelationEngine()
    events = store.get_events(limit=100)
    activities = engine.analyze(events)
    for act in activities:
        store.insert_activity(act)

    print(f"[+] Reconstructed {len(activities)} threat activities with ML anomaly scores and categorical threat levels.")


def main():
    print("=" * 80)
    print(" FORENSITRACE - HYBRID ML FORENSIC DEMO RUNNER")
    print("=" * 80)

    # 1. Verify ML Model Artifacts
    scoring = get_scoring_service()
    if scoring.is_ready:
        print(f"[+] Loaded Trained LSTM Autoencoder (Threshold tau={scoring.threshold:.4f})")
    else:
        print("[!] Note: ML model not found. Retraining lightweight baseline autoencoder...")
        from engine.ml.train import train_lstm_autoencoder
        train_lstm_autoencoder(epochs=40)
        scoring._load_artifacts()

    # 2. Reset and Seed Database
    db_path = ROOT_DIR / "forensitrace.db"
    store = EvidenceStore(db_path)
    store.clear_database()
    seed_demo_data(store)

    # 3. Check Database Integrity
    is_intact, _ = store.verify_integrity()
    print(f"[+] Database Cryptographic Hash Chain: {'VERIFIED' if is_intact else 'COMPROMISED'}")

    # 4. Launch Backend Server
    print("\n[*] Starting FastAPI backend server on http://localhost:8000...")
    backend_env = os.environ.copy()
    backend_env["PYTHONPATH"] = str(ROOT_DIR)
    backend_proc = subprocess.Popen(
        [sys.executable, "-m", "backend.app.main"],
        cwd=str(ROOT_DIR),
        env=backend_env
    )

    # 5. Launch React Frontend
    print("[*] Starting Vite React dashboard on http://localhost:5173...")
    frontend_dir = ROOT_DIR / "frontend"
    npm_cmd = "npm.cmd" if os.name == "nt" else "npm"
    frontend_proc = subprocess.Popen(
        [npm_cmd, "run", "dev"],
        cwd=str(frontend_dir)
    )

    # Allow servers to bind
    time.sleep(2.5)

    # 6. Open Web Browser
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

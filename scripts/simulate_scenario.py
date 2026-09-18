import requests
import time
from datetime import datetime, timezone, timedelta
import json
import sys

BASE_URL = "http://localhost:8000"

def print_step(msg):
    print(f"\n[*] {msg}")

def print_success(msg):
    print(f"[+] {msg}")

def print_error(msg):
    print(f"[!] {msg}")

def main():
    print("=" * 80)
    print(" FORENSITRACE - END-TO-END WORKFLOW SIMULATION")
    print("=" * 80)

    # 1. Ping /health
    print_step("Pinging backend /health...")
    try:
        resp = requests.get(f"{BASE_URL}/health", timeout=3)
        resp.raise_for_status()
        print_success("Backend is reachable.")
    except Exception as e:
        print_error(f"Backend unreachable: {e}. Please start the backend server.")
        sys.exit(1)

    t0 = datetime.now(timezone.utc)

    # 2. Post Heartbeat
    print_step("Posting heartbeat event...")
    hb_event = {
        "source": "heartbeat",
        "timestamp": t0.isoformat(),
        "entity": "agent_monitor",
        "action": "pulse",
        "raw_data": {"cpu_percent": 0.8, "memory_mb": 24.5}
    }
    requests.post(f"{BASE_URL}/api/v1/events", json=hb_event).raise_for_status()
    print_success("Heartbeat posted.")

    # 3. Post USB Connection
    print_step("Posting USB Connection event...")
    usb_event = {
        "source": "usb_device",
        "timestamp": (t0 + timedelta(seconds=1)).isoformat(),
        "entity": "E:\\ (Kingston DataTraveler)",
        "action": "connected",
        "raw_data": {"volume": "MALICIOUS_DRIVE"}
    }
    requests.post(f"{BASE_URL}/api/v1/events", json=usb_event).raise_for_status()
    print_success("USB event posted.")
    time.sleep(2)

    # 4. Post File System Event
    print_step("Posting File System event (malware_staged.exe)...")
    fs_event = {
        "source": "file_system",
        "timestamp": (t0 + timedelta(seconds=3)).isoformat(),
        "entity": "C:\\Users\\Target\\Downloads\\malware_staged.exe",
        "action": "created",
        "raw_data": {"size": 102400, "source_drive": "E:\\"}
    }
    requests.post(f"{BASE_URL}/api/v1/events", json=fs_event).raise_for_status()
    print_success("File System event posted.")
    time.sleep(1)

    # 5. Post Event Log (Process Execution)
    print_step("Posting Event Log (Process Execution)...")
    el_event = {
        "source": "event_log",
        "timestamp": (t0 + timedelta(seconds=4)).isoformat(),
        "entity": "Microsoft-Windows-Security-Auditing/4688",
        "action": "logged",
        "raw_data": {"process": "malware_staged.exe", "pid": 4820, "parent": "cmd.exe"}
    }
    requests.post(f"{BASE_URL}/api/v1/events", json=el_event).raise_for_status()
    print_success("Process Execution event posted.")

    # 6. Trigger Correlation Engine
    print_step("Triggering Correlation Engine (POST /api/v1/correlate)...")
    corr_resp = requests.post(f"{BASE_URL}/api/v1/correlate")
    corr_resp.raise_for_status()
    activities = corr_resp.json()
    
    if not activities:
        print_error("Engine returned 0 activities. Expected 1.")
        sys.exit(1)

    # 7. Assert and Print Activity
    act = activities[-1] # Get latest
    print_success(f"Activity Detected: {act['title']}")
    print(f"    Confidence Score: {act['confidence_score']} ({act['confidence_level']})")
    print(f"    Narrative: {act['narrative']}")
    
    assert act['confidence_score'] >= 0.75, "Confidence score should be HIGH (>0.75)"
    assert len(act['evidence_event_ids']) == 3, "Should have exactly 3 linked evidence IDs"
    
    # Check Evidence retrieval endpoint
    act_id = act['id']
    print_step(f"Fetching full evidence chain for Activity #{act_id}...")
    ev_resp = requests.get(f"{BASE_URL}/api/v1/activities/{act_id}/evidence")
    ev_resp.raise_for_status()
    evidence = ev_resp.json()
    print_success(f"Retrieved {len(evidence)} raw evidence records.")
    for ev in evidence:
        print(f"    - ID {ev['id']} | {ev['source']} | {ev['action']} | {ev['entity']}")

    # 8. Integrity Check
    print_step("Verifying Database Integrity...")
    int_resp = requests.get(f"{BASE_URL}/api/v1/integrity")
    int_resp.raise_for_status()
    integrity_data = int_resp.json()
    
    assert integrity_data["intact"] is True, "Database integrity should be intact!"
    print_success("Cryptographic Hash Chain is intact and fully unbroken.")
    
    print("\n" + "=" * 80)
    print(" SUCCESS: End-to-End Simulation Passed!")
    print("=" * 80)


if __name__ == "__main__":
    main()

"""
ForensiTrace - Scenario A: USB Staging and Process Execution
Simulates an attack sequence where a rogue USB drive is inserted, an executable is staged,
and execution is launched via process creation.
Generates ground_truth_a.json for forensic evaluation verification.
"""

from datetime import datetime, timezone, timedelta
import json
import os
import sys
import requests

BASE_URL = os.environ.get("FORENSITRACE_API", "http://localhost:8000/api/v1")


def main():
    print("=" * 80)
    print(" SCENARIO A: USB Staging -> File Copy -> Execution")
    print("=" * 80)

    t0 = datetime.now(timezone.utc)
    ground_truth = {
        "scenario_id": "SCENARIO_A",
        "description": "Attacker inserts USB flash drive, stages backdoor_payload.exe, and executes it.",
        "start_time": t0.isoformat(),
        "expected_rules": ["R7_USB_STAGING_EXECUTION", "R1_DEVICE_FILE_STAGING", "R2_FILE_CREATION_EXECUTION"],
        "expected_confidence": "HIGH",
        "events": []
    }

    # Step 1: USB Device Arrival
    t_usb = t0 + timedelta(seconds=1)
    ev_usb = {
        "source": "usb",
        "timestamp": t_usb.isoformat(),
        "entity": "E: (Kingston DataTraveler)",
        "action": "DEVICE_ARRIVED",
        "entity_type": "device",
        "details": {"drive_letter": "E:", "volume_name": "Kingston DataTraveler", "serial": "KT98412"},
        "raw_data": {"EventType": 2, "DriveName": "E:"}
    }
    r = requests.post(f"{BASE_URL}/events", json=ev_usb)
    r.raise_for_status()
    rec_usb = r.json()
    ground_truth["events"].append({
        "order": 1,
        "event_id": rec_usb["id"],
        "source": "usb",
        "action": "DEVICE_ARRIVED",
        "target": "E: (Kingston DataTraveler)",
        "timestamp": t_usb.isoformat()
    })
    print(f"[+] Step 1: USB drive mounted on E: (Event #{rec_usb['id']})")

    # Step 2: File Creation (Staging)
    t_file = t0 + timedelta(seconds=3)
    ev_file = {
        "source": "fs",
        "timestamp": t_file.isoformat(),
        "entity": "E:\\backdoor_payload.exe",
        "action": "FILE_CREATED",
        "entity_type": "file",
        "details": {"file_extension": ".exe", "size_bytes": 524288, "mtime": t_file.isoformat()},
        "raw_data": {"src_path": "E:\\backdoor_payload.exe", "size": 524288}
    }
    r = requests.post(f"{BASE_URL}/events", json=ev_file)
    r.raise_for_status()
    rec_file = r.json()
    ground_truth["events"].append({
        "order": 2,
        "event_id": rec_file["id"],
        "source": "fs",
        "action": "FILE_CREATED",
        "target": "E:\\backdoor_payload.exe",
        "timestamp": t_file.isoformat()
    })
    print(f"[+] Step 2: Payload staged on removable storage (Event #{rec_file['id']})")

    # Step 3: Process Execution (Windows Event 4688)
    t_exec = t0 + timedelta(seconds=5)
    ev_exec = {
        "source": "eventlog",
        "timestamp": t_exec.isoformat(),
        "entity": "E:\\backdoor_payload.exe",
        "action": "PROCESS_STARTED",
        "entity_type": "process",
        "details": {"event_id": 4688, "process_name": "backdoor_payload.exe", "command_line": "\"E:\\backdoor_payload.exe\" --silent"},
        "raw_data": {"EventID": 4688, "Process": "backdoor_payload.exe", "PID": 5120}
    }
    r = requests.post(f"{BASE_URL}/events", json=ev_exec)
    r.raise_for_status()
    rec_exec = r.json()
    ground_truth["events"].append({
        "order": 3,
        "event_id": rec_exec["id"],
        "source": "eventlog",
        "action": "PROCESS_STARTED",
        "target": "E:\\backdoor_payload.exe",
        "timestamp": t_exec.isoformat()
    })
    print(f"[+] Step 3: Process execution launched (Event #{rec_exec['id']})")

    # Trigger Correlation Engine
    print("[*] Triggering correlation engine...")
    corr_res = requests.post(f"{BASE_URL}/correlate").json()
    print(f"[+] Correlation engine produced {len(corr_res)} activity records.")

    ground_truth["reconstructed_activities"] = [
        {"id": a["id"], "rule": a["rule_name"], "confidence": a["confidence_level"], "score": a["confidence_score"]}
        for a in corr_res
    ]

    # Save Ground Truth
    gt_path = os.path.join(os.path.dirname(__file__), "ground_truth_a.json")
    with open(gt_path, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2)
    print(f"[+] Ground truth persisted to: {gt_path}")
    print("[SUCCESS] Scenario A complete.")


if __name__ == "__main__":
    main()

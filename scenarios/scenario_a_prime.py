"""
ForensiTrace - Scenario A-Prime (A'): Counterbalanced Variant for Experiment
Simulates an identical attack sequence using different identifiers (device F:, malware update_helper.exe).
Used in the evaluation experiment to test participant comprehension without learning bias.
Generates ground_truth_a_prime.json.
"""

from datetime import datetime, timezone, timedelta
import json
import os
import requests

BASE_URL = os.environ.get("FORENSITRACE_API", "http://localhost:8000/api/v1")


def main():
    print("=" * 80)
    print(" SCENARIO A' (PRIME): Counterbalanced Evaluation Attack")
    print("=" * 80)

    t0 = datetime.now(timezone.utc)
    ground_truth = {
        "scenario_id": "SCENARIO_A_PRIME",
        "description": "Variant attack: SanDisk USB inserted on F:, staging update_helper.exe, followed by execution.",
        "start_time": t0.isoformat(),
        "expected_rules": ["R7_USB_STAGING_EXECUTION", "R1_DEVICE_FILE_STAGING", "R2_FILE_CREATION_EXECUTION"],
        "expected_confidence": "HIGH",
        "events": []
    }

    # Step 1: USB Device Arrival (F:)
    t_usb = t0 + timedelta(seconds=1)
    ev_usb = {
        "source": "usb",
        "timestamp": t_usb.isoformat(),
        "entity": "F: (SanDisk Ultra Flair)",
        "action": "DEVICE_ARRIVED",
        "entity_type": "device",
        "details": {"drive_letter": "F:", "volume_name": "SanDisk Ultra Flair", "serial": "SD88129"},
        "raw_data": {"EventType": 2, "DriveName": "F:"}
    }
    r = requests.post(f"{BASE_URL}/events", json=ev_usb)
    r.raise_for_status()
    rec_usb = r.json()
    ground_truth["events"].append({
        "order": 1,
        "event_id": rec_usb["id"],
        "source": "usb",
        "action": "DEVICE_ARRIVED",
        "target": "F: (SanDisk Ultra Flair)",
        "timestamp": t_usb.isoformat()
    })
    print(f"[+] Step 1: Removable volume F: connected (Event #{rec_usb['id']})")

    # Step 2: File Creation (Staging)
    t_file = t0 + timedelta(seconds=2)
    ev_file = {
        "source": "fs",
        "timestamp": t_file.isoformat(),
        "entity": "F:\\update_helper.exe",
        "action": "FILE_CREATED",
        "entity_type": "file",
        "details": {"file_extension": ".exe", "size_bytes": 1048576, "mtime": t_file.isoformat()},
        "raw_data": {"src_path": "F:\\update_helper.exe", "size": 1048576}
    }
    r = requests.post(f"{BASE_URL}/events", json=ev_file)
    r.raise_for_status()
    rec_file = r.json()
    ground_truth["events"].append({
        "order": 2,
        "event_id": rec_file["id"],
        "source": "fs",
        "action": "FILE_CREATED",
        "target": "F:\\update_helper.exe",
        "timestamp": t_file.isoformat()
    })
    print(f"[+] Step 2: Binary update_helper.exe created (Event #{rec_file['id']})")

    # Step 3: Process Execution (Windows Event 4688)
    t_exec = t0 + timedelta(seconds=4)
    ev_exec = {
        "source": "eventlog",
        "timestamp": t_exec.isoformat(),
        "entity": "F:\\update_helper.exe",
        "action": "PROCESS_STARTED",
        "entity_type": "process",
        "details": {"event_id": 4688, "process_name": "update_helper.exe", "command_line": "\"F:\\update_helper.exe\" /run"},
        "raw_data": {"EventID": 4688, "Process": "update_helper.exe", "PID": 6244}
    }
    r = requests.post(f"{BASE_URL}/events", json=ev_exec)
    r.raise_for_status()
    rec_exec = r.json()
    ground_truth["events"].append({
        "order": 3,
        "event_id": rec_exec["id"],
        "source": "eventlog",
        "action": "PROCESS_STARTED",
        "target": "F:\\update_helper.exe",
        "timestamp": t_exec.isoformat()
    })
    print(f"[+] Step 3: Process execution confirmed (Event #{rec_exec['id']})")

    # Trigger Correlation Engine
    corr_res = requests.post(f"{BASE_URL}/correlate").json()
    print(f"[+] Correlation engine produced {len(corr_res)} activity records.")

    ground_truth["reconstructed_activities"] = [
        {"id": a["id"], "rule": a["rule_name"], "confidence": a["confidence_level"], "score": a["confidence_score"]}
        for a in corr_res
    ]

    # Save Ground Truth
    gt_path = os.path.join(os.path.dirname(__file__), "ground_truth_a_prime.json")
    with open(gt_path, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2)
    print(f"[+] Ground truth persisted to: {gt_path}")
    print("[SUCCESS] Scenario A' complete.")


if __name__ == "__main__":
    main()

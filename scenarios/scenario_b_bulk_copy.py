"""
ForensiTrace - Scenario B: Rapid Bulk File Copy to Removable Storage
Simulates automated data exfiltration or mass payload staging where multiple files
are rapidly copied to a removable volume in a short time burst (triggering Rule R4).
Generates ground_truth_b.json.
"""

from datetime import datetime, timezone, timedelta
import json
import os
import requests

BASE_URL = os.environ.get("FORENSITRACE_API", "http://localhost:8000/api/v1")


def main():
    print("=" * 80)
    print(" SCENARIO B: Rapid Bulk Copy / Exfiltration (Rule R4)")
    print("=" * 80)

    t0 = datetime.now(timezone.utc)
    ground_truth = {
        "scenario_id": "SCENARIO_B_BULK_COPY",
        "description": "Exfiltration simulation: Attacker rapidly copies 8 sensitive documents to removable drive E:.",
        "start_time": t0.isoformat(),
        "expected_rules": ["R4_BULK_REMOVABLE_COPY", "R1_DEVICE_FILE_STAGING"],
        "expected_confidence": "HIGH",
        "events": []
    }

    # Step 1: USB Device Arrival
    t_usb = t0 + timedelta(seconds=1)
    ev_usb = {
        "source": "usb",
        "timestamp": t_usb.isoformat(),
        "entity": "E: (ExfilDrive)",
        "action": "DEVICE_ARRIVED",
        "entity_type": "device",
        "details": {"drive_letter": "E:", "volume_name": "ExfilDrive", "serial": "EX9901"},
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
        "target": "E: (ExfilDrive)"
    })
    print(f"[+] USB drive attached on E: (Event #{rec_usb['id']})")

    # Step 2: Burst of 8 File Creations within 10 seconds
    target_files = [
        "passwords.txt", "customer_data.xlsx", "financial_q3.pdf", "network_topology.vsdx",
        "api_keys.env", "source_dump.zip", "credentials.db", "executive_brief.docx"
    ]

    for idx, fname in enumerate(target_files, start=2):
        t_cur = t0 + timedelta(seconds=2 + (idx * 0.8))
        ev_file = {
            "source": "fs",
            "timestamp": t_cur.isoformat(),
            "entity": f"E:\\Exfiltrated\\{fname}",
            "action": "FILE_CREATED",
            "entity_type": "file",
            "details": {"file_extension": os.path.splitext(fname)[1], "size_bytes": 10240 * idx, "mtime": t_cur.isoformat()},
            "raw_data": {"src_path": f"E:\\Exfiltrated\\{fname}", "size": 10240 * idx}
        }
        r = requests.post(f"{BASE_URL}/events", json=ev_file)
        r.raise_for_status()
        rec = r.json()
        ground_truth["events"].append({
            "order": idx,
            "event_id": rec["id"],
            "source": "fs",
            "action": "FILE_CREATED",
            "target": f"E:\\Exfiltrated\\{fname}"
        })
        print(f"    - Staged file {idx - 1}/8: {fname} (Event #{rec['id']})")

    # Trigger Correlation Engine
    print("[*] Triggering correlation engine...")
    corr_res = requests.post(f"{BASE_URL}/correlate").json()
    print(f"[+] Correlation engine produced {len(corr_res)} activity records.")

    ground_truth["reconstructed_activities"] = [
        {"id": a["id"], "rule": a["rule_name"], "confidence": a["confidence_level"], "score": a["confidence_score"]}
        for a in corr_res
    ]

    # Save Ground Truth
    gt_path = os.path.join(os.path.dirname(__file__), "ground_truth_b.json")
    with open(gt_path, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2)
    print(f"[+] Ground truth persisted to: {gt_path}")
    print("[SUCCESS] Scenario B complete.")


if __name__ == "__main__":
    main()

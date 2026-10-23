"""
ForensiTrace - Scenario C: Anti-Forensic Audit Log Erasure
Simulates an attacker writing an exploit script to disk and then clearing the
Windows Security log (Event ID 1102) to cover their tracks (triggering Rule R5).
Generates ground_truth_c.json.
"""

from datetime import datetime, timezone, timedelta
import json
import os
import requests

BASE_URL = os.environ.get("FORENSITRACE_API", "http://localhost:8000/api/v1")


def main():
    print("=" * 80)
    print(" SCENARIO C: Anti-Forensics / Audit Log Cleared (Rule R5)")
    print("=" * 80)

    t0 = datetime.now(timezone.utc)
    ground_truth = {
        "scenario_id": "SCENARIO_C_LOG_CLEARED",
        "description": "Anti-forensics: Exploit staged, followed immediately by Security log clearing.",
        "start_time": t0.isoformat(),
        "expected_rules": ["R5_LOG_CLEARED_COVERUP"],
        "expected_confidence": "HIGH",
        "events": []
    }

    # Step 1: Malicious file creation
    t_file = t0 + timedelta(seconds=1)
    ev_file = {
        "source": "fs",
        "timestamp": t_file.isoformat(),
        "entity": "C:\\Windows\\Temp\\privesc_exploit.exe",
        "action": "FILE_CREATED",
        "entity_type": "file",
        "details": {"file_extension": ".exe", "size_bytes": 81920, "mtime": t_file.isoformat()},
        "raw_data": {"src_path": "C:\\Windows\\Temp\\privesc_exploit.exe"}
    }
    r = requests.post(f"{BASE_URL}/events", json=ev_file)
    r.raise_for_status()
    rec_file = r.json()
    ground_truth["events"].append({
        "order": 1,
        "event_id": rec_file["id"],
        "source": "fs",
        "action": "FILE_CREATED",
        "target": "C:\\Windows\\Temp\\privesc_exploit.exe"
    })
    print(f"[+] Exploit file created: privesc_exploit.exe (Event #{rec_file['id']})")

    # Step 2: Audit Log Cleared (Windows Event 1102)
    t_clear = t0 + timedelta(seconds=4)
    ev_clear = {
        "source": "eventlog",
        "timestamp": t_clear.isoformat(),
        "entity": "LogCleared:Security",
        "action": "LOG_CLEARED",
        "entity_type": "system",
        "details": {"event_id": 1102, "channel": "Security", "provider": "Microsoft-Windows-Security-Auditing"},
        "raw_data": {"EventID": 1102, "Channel": "Security"}
    }
    r = requests.post(f"{BASE_URL}/events", json=ev_clear)
    r.raise_for_status()
    rec_clear = r.json()
    ground_truth["events"].append({
        "order": 2,
        "event_id": rec_clear["id"],
        "source": "eventlog",
        "action": "LOG_CLEARED",
        "target": "LogCleared:Security"
    })
    print(f"[+] Windows Security Log cleared (Event #{rec_clear['id']})")

    # Trigger Correlation Engine
    print("[*] Triggering correlation engine...")
    corr_res = requests.post(f"{BASE_URL}/correlate").json()
    print(f"[+] Correlation engine produced {len(corr_res)} activity records.")

    ground_truth["reconstructed_activities"] = [
        {"id": a["id"], "rule": a["rule_name"], "confidence": a["confidence_level"], "score": a["confidence_score"]}
        for a in corr_res
    ]

    # Save Ground Truth
    gt_path = os.path.join(os.path.dirname(__file__), "ground_truth_c.json")
    with open(gt_path, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2)
    print(f"[+] Ground truth persisted to: {gt_path}")
    print("[SUCCESS] Scenario C complete.")


if __name__ == "__main__":
    main()

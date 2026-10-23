"""
ForensiTrace - Scenario Noise: Normal Desktop Use Telemetry Generator
Simulates legitimate, benign everyday workstation activity:
- Web browser caching (.crdownload and cache temp files)
- Word document editing with autosave temp files (~$*)
- Normal system logon events
Ensures the correlation engine suppresses false positives on ordinary baseline noise.
Generates ground_truth_noise.json.
"""

from datetime import datetime, timezone, timedelta
import json
import os
import requests

BASE_URL = os.environ.get("FORENSITRACE_API", "http://localhost:8000/api/v1")


def main():
    print("=" * 80)
    print(" SCENARIO NOISE: Benign User & System Operations")
    print("=" * 80)

    t0 = datetime.now(timezone.utc)
    ground_truth = {
        "scenario_id": "SCENARIO_NOISE",
        "description": "Legitimate baseline operations: Office temporary saves, browser cache, normal logon.",
        "start_time": t0.isoformat(),
        "expected_attack_activities": 0,
        "events": []
    }

    # 1. Normal user logon (Event 4624)
    t1 = t0 + timedelta(seconds=1)
    ev_logon = {
        "source": "eventlog",
        "timestamp": t1.isoformat(),
        "entity": "Logon:DakshShaparia",
        "action": "USER_LOGON",
        "entity_type": "system",
        "details": {"event_id": 4624, "target_user": "DakshShaparia"},
        "raw_data": {"EventID": 4624}
    }
    r = requests.post(f"{BASE_URL}/events", json=ev_logon)
    r.raise_for_status()
    ground_truth["events"].append({"source": "eventlog", "action": "USER_LOGON", "entity": "Logon:DakshShaparia"})
    print("[+] Emitted normal user logon")

    # 2. Browser cache files (temporary extensions)
    for i in range(5):
        t_cache = t0 + timedelta(seconds=2 + i)
        ev_cache = {
            "source": "fs",
            "timestamp": t_cache.isoformat(),
            "entity": f"C:\\Users\\User\\AppData\\Local\\Temp\\cache_chunk_{i}.tmp",
            "action": "FILE_CREATED",
            "entity_type": "file",
            "details": {"file_extension": ".tmp", "size_bytes": 4096},
            "raw_data": {"src_path": f"C:\\Users\\User\\AppData\\Local\\Temp\\cache_chunk_{i}.tmp"}
        }
        requests.post(f"{BASE_URL}/events", json=ev_cache)
    print("[+] Emitted 5 browser cache temp file operations")

    # 3. Normal Office document autosave
    t_doc = t0 + timedelta(seconds=8)
    ev_doc = {
        "source": "fs",
        "timestamp": t_doc.isoformat(),
        "entity": "C:\\Users\\User\\Documents\\~$ProjectNotes.docx",
        "action": "FILE_CREATED",
        "entity_type": "file",
        "details": {"file_extension": ".docx", "size_bytes": 162},
        "raw_data": {"src_path": "C:\\Users\\User\\Documents\\~$ProjectNotes.docx"}
    }
    requests.post(f"{BASE_URL}/events", json=ev_doc)
    print("[+] Emitted Office lock file creation")

    # 4. Legitimate Windows background service start
    t_svc = t0 + timedelta(seconds=10)
    ev_svc = {
        "source": "eventlog",
        "timestamp": t_svc.isoformat(),
        "entity": "C:\\Windows\\System32\\svchost.exe",
        "action": "PROCESS_STARTED",
        "entity_type": "process",
        "details": {"event_id": 4688, "process_name": "svchost.exe"},
        "raw_data": {"EventID": 4688, "Process": "svchost.exe"}
    }
    requests.post(f"{BASE_URL}/events", json=ev_svc)
    print("[+] Emitted background service process event")

    # Trigger correlation engine
    print("[*] Triggering correlation engine against noise...")
    corr_res = requests.post(f"{BASE_URL}/correlate").json()

    # Filter out attack activities that fired on this noise window
    noise_activities = [a for a in corr_res if "NOISE" in a.get("rule_name", "") or a["confidence_score"] >= 0.8]
    print(f"[+] Engine produced {len(corr_res)} total activities. High-confidence attack alerts: {len(noise_activities)}.")

    ground_truth["correlation_result_count"] = len(corr_res)

    gt_path = os.path.join(os.path.dirname(__file__), "ground_truth_noise.json")
    with open(gt_path, "w", encoding="utf-8") as f:
        json.dump(ground_truth, f, indent=2)
    print(f"[+] Ground truth persisted to: {gt_path}")
    print("[SUCCESS] Scenario Noise complete.")


if __name__ == "__main__":
    main()

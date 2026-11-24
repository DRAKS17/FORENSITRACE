"""
ForensiTrace - End-to-End System Smoke Test (PURVA)
Executes the full forensic pipeline:
  Scenario Events -> API Ingestion -> Database Hash Chaining -> Correlation Engine ->
  LSTM Anomaly Scoring -> Activity Creation -> Integrity Audit -> PDF Report Generation
Outputs clear PASS or FAIL and returns code 0 or 1.
"""

from datetime import datetime, timezone, timedelta
import os
from pathlib import Path
import sys
from fastapi.testclient import TestClient

ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from backend.app.main import app
from backend.app.database import EvidenceStore

client = TestClient(app)


def run_smoke_test() -> bool:
    print("=" * 80)
    print(" FORENSITRACE - END-TO-END SYSTEM SMOKE TEST")
    print("=" * 80)

    try:
        # Step 1: Health Check
        print("[*] Step 1: Checking API health...")
        r_health = client.get("/health")
        assert r_health.status_code == 200 and r_health.json().get("status") == "ok", "Health check failed"
        print("    [PASS] Backend API is healthy (HTTP 200 OK)")

        # Step 2: Database Reset
        print("\n[*] Step 2: Initializing and resetting database...")
        db_path = ROOT_DIR / "forensitrace.db"
        store = EvidenceStore(db_path)
        store.clear_database()
        print("    [PASS] Database cleared and tables re-initialized")

        # Step 3: Event Ingestion (Scenario A: USB Staging -> Process Execution)
        print("\n[*] Step 3: Ingesting Scenario A telemetry events...")
        t0 = datetime.now(timezone.utc) - timedelta(minutes=1)

        events_payload = [
            {
                "source": "heartbeat",
                "timestamp": (t0).isoformat(),
                "entity": "agent_service",
                "action": "HEARTBEAT",
                "details": {"cpu_percent": 0.5, "memory_mb": 24.0}
            },
            {
                "source": "usb",
                "timestamp": (t0 + timedelta(seconds=2)).isoformat(),
                "entity": "E: (Kingston DataTraveler)",
                "action": "DEVICE_ARRIVED",
                "entity_type": "device",
                "details": {"drive_letter": "E:", "volume_name": "Kingston DataTraveler", "serial": "KT98412"}
            },
            {
                "source": "fs",
                "timestamp": (t0 + timedelta(seconds=5)).isoformat(),
                "entity": "E:\\backdoor_payload.exe",
                "action": "FILE_CREATED",
                "entity_type": "file",
                "details": {"file_extension": ".exe", "size_bytes": 524288}
            },
            {
                "source": "eventlog",
                "timestamp": (t0 + timedelta(seconds=7)).isoformat(),
                "entity": "E:\\backdoor_payload.exe",
                "action": "PROCESS_STARTED",
                "entity_type": "process",
                "details": {"event_id": 4688, "process_name": "backdoor_payload.exe", "command_line": "\"E:\\backdoor_payload.exe\" --silent"}
            },
            {
                "source": "eventlog",
                "timestamp": (t0 + timedelta(seconds=12)).isoformat(),
                "entity": "LogCleared:Security",
                "action": "LOG_CLEARED",
                "entity_type": "system",
                "details": {"event_id": 1102, "channel": "Security"}
            }
        ]

        r_ingest = client.post("/api/v1/events", json=events_payload)
        assert r_ingest.status_code == 200, f"Ingestion failed: {r_ingest.text}"
        ingested_records = r_ingest.json()
        assert len(ingested_records) == 5, f"Expected 5 events, got {len(ingested_records)}"
        print(f"    [PASS] Ingested {len(ingested_records)} events with SHA-256 hash chaining")

        # Step 4: Cryptographic Hash Chain Audit
        print("\n[*] Step 4: Auditing cryptographic hash chain integrity...")
        r_integ = client.get("/api/v1/integrity")
        assert r_integ.status_code == 200, "Integrity query failed"
        integ_data = r_integ.json()
        assert integ_data.get("intact") is True, f"Integrity check failed: {integ_data}"
        assert integ_data.get("status") == "VERIFIED", f"Unexpected status: {integ_data.get('status')}"
        print(f"    [PASS] Cryptographic Hash Chain: VERIFIED ({integ_data.get('total_records')} records)")

        # Step 5: Correlation Engine Execution & ML Anomaly Scoring
        print("\n[*] Step 5: Triggering correlation engine and ML scoring...")
        r_corr = client.post("/api/v1/correlate")
        assert r_corr.status_code == 200, f"Correlation failed: {r_corr.text}"
        activities = r_corr.json()
        assert len(activities) > 0, "No activities reconstructed by correlation engine"

        # Verify ML fields and threat levels
        print(f"    [+] Reconstructed {len(activities)} correlated activities:")
        has_ml_score = False
        for act in activities:
            ml_s = act.get("ml_anomaly_score")
            threat = act.get("threat_level")
            rule = act.get("rule_name")
            conf = act.get("confidence_score")
            print(f"        - [ACT #{act.get('id')}] {rule} | Rule Conf: {conf:.2f} | ML Score: {ml_s} | Threat: {threat}")
            if ml_s is not None:
                has_ml_score = True
            assert threat in ["LOW", "MEDIUM", "HIGH", "CRITICAL"], f"Invalid threat level: {threat}"

        assert has_ml_score, "No activity received an ML anomaly score"
        print("    [PASS] Hybrid correlation verified (Rule Confidence + ML Anomaly + Threat Level)")

        # Step 6: Unified Timeline Verification
        print("\n[*] Step 6: Verifying unified chronological timeline...")
        r_timeline = client.get("/api/v1/timeline")
        assert r_timeline.status_code == 200, "Timeline query failed"
        timeline_items = r_timeline.json()
        assert len(timeline_items) > 0, "Timeline is empty"
        print(f"    [PASS] Timeline returned {len(timeline_items)} chronological items (activities & events)")

        # Step 7: 3-Page Forensic PDF Report Generation & Export
        print("\n[*] Step 7: Generating 3-page forensic PDF dossier...")
        first_act_id = activities[0]["id"]
        r_pdf = client.get(f"/api/v1/report/{first_act_id}")
        assert r_pdf.status_code == 200, f"PDF export failed: {r_pdf.status_code}"
        assert r_pdf.headers.get("content-type") == "application/pdf", "Expected application/pdf content type"
        pdf_bytes = r_pdf.content
        assert pdf_bytes.startswith(b"%PDF-"), "Invalid PDF signature"

        # Check page count
        import pypdf
        import io
        reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
        num_pages = len(reader.pages)
        assert num_pages == 3, f"Expected exactly 3 pages per contract, got {num_pages}"
        print(f"    [PASS] Forensic Report exported: {len(pdf_bytes)} bytes, exactly {num_pages} pages")

        print("\n" + "=" * 80)
        print(" [RESULT] ALL 7 SMOKE TEST SUITES PASSED SUCCESSFULLY (PASS)")
        print("=" * 80)
        return True

    except Exception as e:
        print("\n" + "=" * 80)
        print(f" [RESULT] SMOKE TEST FAILED: {str(e)} (FAIL)")
        print("=" * 80)
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_smoke_test()
    sys.exit(0 if success else 1)

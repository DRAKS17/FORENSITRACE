"""
ForensiTrace - Backend REST API End-to-End Integration Tests (PURVA)
Verifies all FastAPI routes against a temporary test database.
"""

from datetime import datetime, timezone
import os
import tempfile
import unittest
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database import EvidenceStore
import backend.app.routes as routes_module


class TestAPIEndpoints(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.temp_dir, "test_api.db")
        self.test_store = EvidenceStore(self.db_path)
        # Point the router's store to our test database
        routes_module.store = self.test_store
        self.client = TestClient(app)

    def tearDown(self):
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
            except OSError:
                pass
        try:
            os.rmdir(self.temp_dir)
        except OSError:
            pass

    def test_health_check(self):
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "ok")

    def test_event_ingestion_and_retrieval(self):
        ev_payload = {
            "source": "usb",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "entity": "E: (Kingston)",
            "action": "DEVICE_ARRIVED"
        }
        post_res = self.client.post("/api/v1/events", json=ev_payload)
        self.assertEqual(post_res.status_code, 200)
        record = post_res.json()
        self.assertEqual(record["id"], 1)
        self.assertTrue(len(record["record_hash"]) == 64)

        get_res = self.client.get("/api/v1/events")
        self.assertEqual(get_res.status_code, 200)
        events = get_res.json()
        self.assertEqual(len(events), 1)

    def test_integrity_endpoint(self):
        res = self.client.get("/api/v1/integrity")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["intact"])
        self.assertIsNone(data["tampered_id"])

    def test_metrics_endpoint(self):
        hb_payload = {
            "source": "heartbeat",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "entity": "agent_monitor",
            "action": "HEARTBEAT",
            "details": {"cpu_percent": 1.5, "memory_mb": 22.4}
        }
        self.client.post("/api/v1/events", json=hb_payload)

        res = self.client.get("/api/v1/metrics")
        self.assertEqual(res.status_code, 200)
        metrics = res.json()
        self.assertEqual(metrics["avg_cpu_percent"], 1.5)
        self.assertEqual(metrics["avg_memory_mb"], 22.4)

    def test_correlation_and_activities_flow(self):
        t0 = datetime(2026, 10, 23, 14, 0, 0, tzinfo=timezone.utc).isoformat()
        t1 = datetime(2026, 10, 23, 14, 0, 5, tzinfo=timezone.utc).isoformat()
        t2 = datetime(2026, 10, 23, 14, 0, 8, tzinfo=timezone.utc).isoformat()

        # Ingest 3-step attack sequence
        self.client.post("/api/v1/events", json={"source": "usb", "timestamp": t0, "entity": "E: (USB)", "action": "DEVICE_ARRIVED"})
        self.client.post("/api/v1/events", json={"source": "fs", "timestamp": t1, "entity": "E:\\backdoor.exe", "action": "FILE_CREATED"})
        self.client.post("/api/v1/events", json={"source": "eventlog", "timestamp": t2, "entity": "E:\\backdoor.exe", "action": "PROCESS_STARTED"})

        # Run correlation
        corr_res = self.client.post("/api/v1/correlate")
        self.assertEqual(corr_res.status_code, 200)
        activities = corr_res.json()
        self.assertGreaterEqual(len(activities), 1)

        act_id = activities[0]["id"]

        # Fetch detail
        detail_res = self.client.get(f"/api/v1/activities/{act_id}")
        self.assertEqual(detail_res.status_code, 200)
        detail = detail_res.json()
        self.assertEqual(detail["activity"]["id"], act_id)
        self.assertEqual(len(detail["evidence"]), len(activities[0]["evidence_event_ids"]))

        # Fetch timeline
        tl_res = self.client.get("/api/v1/timeline")
        self.assertEqual(tl_res.status_code, 200)
        self.assertGreaterEqual(len(tl_res.json()), 1)

        # Export PDF
        pdf_res = self.client.get(f"/api/v1/activities/{act_id}/export")
        self.assertEqual(pdf_res.status_code, 200)
        self.assertEqual(pdf_res.headers["content-type"], "application/pdf")
        self.assertGreater(len(pdf_res.content), 500)


if __name__ == "__main__":
    unittest.main()

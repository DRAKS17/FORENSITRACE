"""
ForensiTrace - Telemetry Normalizer Unit Tests (PURVA)
Verifies that heterogeneous raw recordings and simulated collector outputs
correctly normalize into the frozen schema (docs/schema.md).
"""

from datetime import datetime, timezone
import unittest
from backend.app.normalizers import (
    normalize_usb_event,
    normalize_fs_event,
    normalize_eventlog_event,
    normalize_heartbeat_event,
)


class TestNormalizers(unittest.TestCase):

    def test_normalize_usb_arrival(self):
        raw = {
            "EventType": 2,
            "DriveName": "E:",
            "VolumeName": "Kingston",
            "SerialNumber": "12345ABC",
            "FileSystem": "FAT32",
            "Size": 16000000000,
            "DriveType": 2
        }
        ev = normalize_usb_event(raw)
        self.assertEqual(ev.source, "usb")
        self.assertEqual(ev.action, "DEVICE_ARRIVED")
        self.assertEqual(ev.entity_type, "device")
        self.assertIn("E:", ev.entity)
        self.assertEqual(ev.details["drive_letter"], "E:")
        self.assertTrue(ev.event_id)

    def test_normalize_usb_removal(self):
        raw = {
            "EventType": 3,
            "DriveName": "E:",
        }
        ev = normalize_usb_event(raw)
        self.assertEqual(ev.source, "usb")
        self.assertEqual(ev.action, "DEVICE_REMOVED")

    def test_normalize_fs_created(self):
        raw = {
            "event_type": "created",
            "src_path": "C:\\Users\\User\\Downloads\\sample.exe",
            "size_bytes": 102400
        }
        ev = normalize_fs_event(raw)
        self.assertEqual(ev.source, "fs")
        self.assertEqual(ev.action, "FILE_CREATED")
        self.assertEqual(ev.entity_type, "file")
        self.assertEqual(ev.details["file_extension"], ".exe")

    def test_normalize_eventlog_4688(self):
        raw = {
            "EventID": 4688,
            "Channel": "Security",
            "RecordNumber": 4012,
            "command_line": "\"C:\\malware.exe\" -arg",
            "process_name": "malware.exe"
        }
        ev = normalize_eventlog_event(raw)
        self.assertEqual(ev.source, "eventlog")
        self.assertEqual(ev.action, "PROCESS_STARTED")
        self.assertEqual(ev.entity_type, "process")
        self.assertIn("malware.exe", ev.entity)

    def test_normalize_eventlog_1102_clear(self):
        raw = {
            "EventID": 1102,
            "Channel": "Security",
            "RecordNumber": 4015
        }
        ev = normalize_eventlog_event(raw)
        self.assertEqual(ev.source, "eventlog")
        self.assertEqual(ev.action, "LOG_CLEARED")
        self.assertEqual(ev.entity_type, "system")

    def test_normalize_heartbeat(self):
        raw = {
            "cpu_percent": 1.2,
            "memory_mb": 28.5
        }
        ev = normalize_heartbeat_event(raw)
        self.assertEqual(ev.source, "heartbeat")
        self.assertEqual(ev.action, "HEARTBEAT")
        self.assertEqual(ev.details["cpu_percent"], 1.2)
        self.assertEqual(ev.details["memory_mb"], 28.5)


if __name__ == "__main__":
    unittest.main()

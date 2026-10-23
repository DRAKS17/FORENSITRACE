# ForensiTrace Normalized Event Schema Specification (v1.0)

**Contract Status:** FROZEN  
**Owners:** PURVA (Primary Author), DAKSH, CHETNA, AKASH (Reviewers)

This document specifies the canonical event schema produced by the Windows Endpoint Agent collectors and consumed by the backend storage and correlation engine.

---

## 1. Schema Fields

| Field Name | Type | Description | Example |
| :--- | :--- | :--- | :--- |
| `event_id` | `str` | SHA-256 hash digest of `(source + raw_record_id + ts_utc)`. Ensures deduplication upon retry. | `"a1b2c3d4e5f6..."` |
| `source` | `str` | Collector source channel: `eventlog`, `usb`, `fs`, `heartbeat`. | `"usb"` |
| `ts_utc` | `str` | ISO-8601 UTC timestamp with millisecond precision (`YYYY-MM-DDTHH:MM:SS.sssZ`). | `"2026-10-23T14:30:00.123Z"` |
| `host` | `str` | Hostname or NetBIOS machine name where event originated. | `"WIN-FORENSIC-01"` |
| `user` | `str` | User account context associated with the action, or `SYSTEM` / `UNKNOWN`. | `"TargetUser"` |
| `action` | `str` | Canonical normalized action descriptor. Fixed enumeration (see Section 2). | `"DEVICE_ARRIVED"` |
| `entity_type` | `str` | Target entity category: `device`, `file`, `process`, or `system`. | `"device"` |
| `entity` | `str` | Primary identifier of the affected entity (drive letter, path, or process). | `"E: (Kingston DataTraveler)"` |
| `details` | `dict` | Key-value dictionary containing structured, source-specific attributes. | `{"serial": "12345", "size_bytes": 1048576}` |
| `raw` | `dict` | Untouched original raw payload from the operating system collector. | `{"EventID": 4688, "TimeGenerated": "..."}` |

---

## 2. Canonical Actions Enum

- **USB Source (`usb`):**
  - `DEVICE_ARRIVED`: New removable storage volume mounted.
  - `DEVICE_REMOVED`: Removable storage volume unmounted.
- **File System Source (`fs`):**
  - `FILE_CREATED`: New file or directory created.
  - `FILE_MODIFIED`: File content modified or written.
  - `FILE_DELETED`: File or directory removed.
  - `FILE_MOVED`: File renamed or relocated.
- **Event Log Source (`eventlog`):**
  - `PROCESS_STARTED`: New process execution spawned (Event ID 4688).
  - `USER_LOGON`: User logon session initiated (Event ID 4624).
  - `LOG_CLEARED`: Security or System audit log erased (Event ID 1102, 104).
- **Health Source (`heartbeat`):**
  - `HEARTBEAT`: Periodic agent telemetry report (CPU, RAM).

---

## 3. Sample Event Payloads

### USB Arrival
```json
{
  "event_id": "7b8d4e9f1a2c3b4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d",
  "source": "usb",
  "ts_utc": "2026-10-23T14:30:00.100Z",
  "host": "WIN-FORENSIC-01",
  "user": "SYSTEM",
  "action": "DEVICE_ARRIVED",
  "entity_type": "device",
  "entity": "E: (Kingston DataTraveler)",
  "details": {
    "drive_letter": "E:",
    "volume_name": "USB_DEMO",
    "serial_number": "0018F30C",
    "file_system": "FAT32",
    "size_bytes": 15998976000
  },
  "raw": {
    "EventType": 2,
    "DriveName": "E:",
    "DeviceID": "USBSTOR\\DISK&VEN_KINGSTON"
  }
}
```

### File Created
```json
{
  "event_id": "8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d",
  "source": "fs",
  "ts_utc": "2026-10-23T14:30:02.350Z",
  "host": "WIN-FORENSIC-01",
  "user": "TargetUser",
  "action": "FILE_CREATED",
  "entity_type": "file",
  "entity": "E:\\payload.exe",
  "details": {
    "file_extension": ".exe",
    "size_bytes": 204800,
    "mtime": "2026-10-23T14:30:02.000Z"
  },
  "raw": {
    "src_path": "E:\\payload.exe",
    "event_type": "created"
  }
}
```

### Process Started (Event 4688)
```json
{
  "event_id": "9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e",
  "source": "eventlog",
  "ts_utc": "2026-10-23T14:30:04.100Z",
  "host": "WIN-FORENSIC-01",
  "user": "TargetUser",
  "action": "PROCESS_STARTED",
  "entity_type": "process",
  "entity": "E:\\payload.exe",
  "details": {
    "channel": "Security",
    "event_id": 4688,
    "process_name": "payload.exe",
    "process_id": 4128,
    "parent_process_name": "explorer.exe",
    "command_line": "\"E:\\payload.exe\" --silent"
  },
  "raw": {
    "Channel": "Security",
    "EventID": 4688,
    "RecordNumber": 10423
  }
}
```

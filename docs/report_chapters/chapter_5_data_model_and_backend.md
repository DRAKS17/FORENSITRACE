# Chapter 5: Data Model, Storage Layer, and Backend API

**Author:** PURVA  
**Reviewer:** AKASH

## 5.1 Normalized Event Schema
ForensiTrace establishes a frozen schema contract (`docs/schema.md`) ensuring all endpoint collectors output uniform telemetry:
- `event_id`: SHA-256 hash digest of `source + record_id + ts_utc`. Enables idempotent deduplication.
- `source`: Canonical channel descriptor (`usb`, `fs`, `eventlog`, `heartbeat`).
- `ts_utc`: ISO-8601 UTC timestamp with millisecond precision.
- `host` & `user`: Machine name and user context.
- `action`: Fixed enumeration (`DEVICE_ARRIVED`, `DEVICE_REMOVED`, `FILE_CREATED`, `FILE_MODIFIED`, `FILE_DELETED`, `FILE_MOVED`, `PROCESS_STARTED`, `USER_LOGON`, `LOG_CLEARED`, `HEARTBEAT`).
- `entity_type` & `entity`: Affected resource identifier.
- `details` & `raw`: Source-specific structured extras and raw operating system capture payloads.

## 5.2 Cryptographic Append-Only Database
Evidence is persisted in local SQLite using recursive SHA-256 hash chaining:
$$\text{record\_hash}_i = \text{SHA-256}(\text{prev\_hash}_{i-1} \parallel \text{source}_i \parallel \text{timestamp}_i \parallel \text{entity}_i \parallel \text{action}_i \parallel \text{canonical\_json}(\text{raw\_data}_i))$$
- **Genesis Block:** Record #1 links to `0` * 64 (`GENESIS_HASH`).
- **Tamper Detection:** The `verify_integrity()` algorithm audits the chain from index 1 to $N$. If any record's payload is altered or deleted, the subsequent `prev_hash` comparison immediately fails and pinpoints the exact compromised record ID.
- **Provenance Link Table (`activity_events`):** Links each activity to its supporting raw event records with the triggering `rule_id` and a one-line explanatory reason.

## 5.3 FastAPI REST API Layer
The backend provides high-performance endpoints:
- `POST /events`: Ingests single events or batches with deduplication.
- `GET /events`: Paginated query with source filtering.
- `POST /correlate`: Triggers correlation engine analysis.
- `GET /activities` & `GET /activities/{id}`: Activity query and detail retrieval.
- `GET /timeline`: Unified chronological timeline generation.
- `GET /integrity`: Cryptographic hash chain audit.
- `GET /metrics`: Resource overhead calculations.
- `GET /report/{id}`: Generates a ReportLab PDF forensic case report with full evidence tables and non-repudiation statements.

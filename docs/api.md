# ForensiTrace REST API Specification (v1.0)

**Contract Status:** FROZEN  
**Owners:** PURVA (Primary Author), CHETNA (Dashboard Consumer), AKASH (Engine Integrator)

The ForensiTrace backend exposes a REST API via FastAPI, enabling ingestion from the endpoint agent and serving the React dashboard and PDF generation services.

---

## Base URLs
All routes are accessible at both `/` and `/api/v1/` for backward compatibility.
- Example: `POST /events` and `POST /api/v1/events`

---

## 1. Event Telemetry Endpoints

### `POST /events` or `POST /api/v1/events`
Accepts a single normalized event or a batch of events from the endpoint agent.
- **Request Body:** Either a single event object or a list of event objects adhering to `docs/schema.md`.
- **Response:** `200 OK` with inserted record(s) containing assigned sequential ID, `prev_hash`, and `record_hash`.
- **Deduplication:** Repeated events sharing the same `event_id` are gracefully acknowledged without chain corruption.

### `GET /events` or `GET /api/v1/events`
Fetches stored raw evidence events with pagination.
- **Query Parameters:**
  - `limit` (integer, default 100): Maximum records to retrieve.
  - `offset` (integer, default 0): Number of records to skip.
  - `source` (string, optional): Filter by source (`usb`, `fs`, `eventlog`, `heartbeat`).
- **Response:** `200 OK` with `List[EventRecord]`.

---

## 2. Forensic Activity & Evidence Endpoints

### `POST /correlate` or `POST /api/v1/correlate`
Executes the rule-based correlation engine over recent stored events.
- **Response:** `200 OK` with `List[ActivityRecord]` of newly identified or updated activities.

### `GET /activities` or `GET /api/v1/activities`
Retrieves all reconstructed forensic activities.
- **Query Parameters:**
  - `confidence_level` (string, optional): Filter by `LOW`, `MEDIUM`, or `HIGH`.
  - `rule_name` (string, optional): Filter by rule identifier.
- **Response:** `200 OK` with `List[ActivityRecord]`.

### `GET /activities/{id}` or `GET /api/v1/activities/{id}`
Retrieves a specific activity including its linked evidence provenance and metadata.
- **Response:** `200 OK` with `ActivityDetail` (activity + list of evidence records with one-line reasons).
- **Error:** `404 Not Found` if activity does not exist.

### `GET /activities/{id}/evidence` or `GET /api/v1/activities/{id}/evidence`
Retrieves the raw `EventRecord` items linked to the specified activity.
- **Response:** `200 OK` with `List[EventRecord]`.

### `GET /timeline` or `GET /api/v1/timeline`
Retrieves a unified chronological timeline combining reconstructed activities and critical endpoint events for time-axis rendering in the UI.
- **Response:** `200 OK` with JSON timeline objects sorted by UTC timestamp.

---

## 3. Reporting & Verification Endpoints

### `GET /report/{id}` or `GET /api/v1/activities/{id}/export`
Generates and downloads a formal forensic PDF report for the activity.
- **Headers:** `Content-Type: application/pdf`, `Content-Disposition: attachment; filename="ForensiTrace_Report_<id>.pdf"`.

### `GET /integrity` or `GET /api/v1/integrity`
Audits the complete SHA-256 cryptographic hash chain across the `events` table.
- **Response:** `200 OK`
  ```json
  {
    "intact": true,
    "tampered_id": null,
    "total_records": 42
  }
  ```

### `GET /metrics` or `GET /api/v1/metrics`
Queries recent agent heartbeat records to calculate performance overhead.
- **Response:** `200 OK`
  ```json
  {
    "avg_cpu_percent": 0.45,
    "avg_memory_mb": 28.4,
    "samples": 12
  }
  ```

### `GET /health`
Returns API service operational health.
- **Response:** `{"status": "ok", "service": "ForensiTrace Backend"}`

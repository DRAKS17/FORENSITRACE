# Chapter 6: Rule-Based Correlation Engine and Provenance

**Author:** AKASH  
**Reviewer:** PURVA

## 6.1 Declarative Correlation Architecture
ForensiTrace intentionally avoids black-box machine learning to guarantee deterministic, legally explainable results. All correlation rules are defined declaratively in `rules.yaml`. This enables tuning temporal sliding windows, thresholds, and scoring weights without code modifications or redeployment.

## 6.2 Rule Catalog (R1 through R7)

### Rule R1: Removable Storage File Staging (`DEVICE_FILE_STAGING`)
- **Pattern:** `usb (DEVICE_ARRIVED)` &rarr; `fs (FILE_CREATED / FILE_MODIFIED)` on the mounted drive within 300s.
- **Base Confidence:** 0.70 (MEDIUM).

### Rule R2: Staged File Execution (`FILE_CREATION_EXECUTION`)
- **Pattern:** Executable file created on disk &rarr; `eventlog (PROCESS_STARTED)` launched from that exact path within 600s.
- **Base Confidence:** 0.75 (HIGH).

### Rule R3: Direct Removable Execution (`DIRECT_REMOVABLE_EXECUTION`)
- **Pattern:** `eventlog (PROCESS_STARTED)` targeting a removable volume without any preceding local write captured in the audit window.
- **Base Confidence:** 0.80 (HIGH).

### Rule R4: Rapid Bulk File Copy (`BULK_REMOVABLE_COPY`)
- **Pattern:** $\ge 5$ files created on a removable drive within a 60-second burst. Flags automated exfiltration.
- **Base Confidence:** 0.85 (HIGH).

### Rule R5: Audit Log Cleared Following Activity (`LOG_CLEARED_COVERUP`)
- **Pattern:** `eventlog (LOG_CLEARED)` (Event ID 1102 or 104) occurring within 600s of file or device operations. Flags anti-forensics cover-up.
- **Base Confidence:** 0.90 (HIGH).

### Rule R6: File Timestamp Inconsistency (`TIMESTAMP_DISAGREEMENT`)
- **Pattern:** Discrepancy between filesystem metadata modified time (`mtime`) and real-time agent observation time $> 120$ seconds. Flags timestomping or clock manipulation.
- **Base Confidence:** 0.80 (HIGH).

### Rule R7: End-to-End USB Staging and Execution (`USB_STAGING_EXECUTION`)
- **Pattern:** Rule R1 followed by Rule R2 within 900s: USB arrival &rarr; file staging &rarr; binary execution.
- **Confidence Scoring:**
  - **0.90 (HIGH):** Tight sequence ($\le 30$ seconds between stages).
  - **0.75 (HIGH):** Looser timing within correlation window.
  - **0.50 (MEDIUM):** Partial match (device arrival + file write without confirmed execution).
  - **-0.15 Penalty:** Negative time deltas or timestamp divergence.

## 6.3 Explainable Narrative Generation
Every generated narrative cites exact event IDs (e.g. `[Event #2]`, `[Event #3]`), ensuring every sentence in the final PDF report is traceable back to an immutable raw database record.

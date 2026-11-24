# Chapter 6: Hybrid Correlation Engine, Declarative Rules, and ML Scoring

**Author:** AKASH  
**Reviewer:** PURVA, DAKSH

## 6.1 Hybrid Correlation Architecture
ForensiTrace utilizes a hybrid correlation tier that combines declarative, explainable rules with a sequence-based machine learning anomaly detector.

Rather than relying on black-box end-to-end classifiers that obscure causality, ForensiTrace enforces a strict separation of concerns:
- **Rules Supply the Causal Chain & Evidence:** Declarative rules defined in `rules.yaml` link disparate telemetry events across USB, File System, and Windows Event Logs into explainable multi-stage attack paths.
- **Machine Learning Supplies the Anomaly Rating:** A lightweight LSTM autoencoder trained on normal workstation activity evaluates the sequence dynamics of the events, producing a normalized reconstruction error score.
- **Non-Replacement Guarantee:** The ML score never replaces rule confidence; both signals are maintained side-by-side to derive the combined risk index and categorical threat level. Every narrative statement cites exact raw event IDs.

---

## 6.2 Rule Catalog (R1 through R7)

All correlation rules are defined declaratively in `rules.yaml`. This enables tuning sliding windows, timing thresholds, and confidence weights without altering or recompiling core engine code.

### Rule R1: Removable Storage File Staging (`DEVICE_FILE_STAGING`)
- **Pattern:** `usb (DEVICE_ARRIVED)` &rarr; `fs (FILE_CREATED / FILE_MODIFIED)` on the newly mounted volume within 300 seconds.
- **Base Confidence:** 0.70 (MEDIUM).
- **Forensic Role:** Flags external software introduction prior to host propagation.

### Rule R2: Staged File Execution (`FILE_CREATION_EXECUTION`)
- **Pattern:** Executable file created on disk &rarr; `eventlog (PROCESS_STARTED)` launched from that exact path within 600 seconds.
- **Base Confidence:** 0.75 (HIGH).
- **Forensic Role:** Correlates filesystem drop with process spawn (Event ID 4688).

### Rule R3: Direct Removable Execution (`DIRECT_REMOVABLE_EXECUTION`)
- **Pattern:** `eventlog (PROCESS_STARTED)` targeting a removable volume without any preceding local write captured in the audit window.
- **Base Confidence:** 0.80 (HIGH).
- **Forensic Role:** Identifies live payload execution straight from external media.

### Rule R4: Rapid Bulk File Copy (`BULK_REMOVABLE_COPY`)
- **Pattern:** $\ge 5$ files created on a removable volume within a 60-second burst.
- **Base Confidence:** 0.85 (HIGH).
- **Forensic Role:** Detects automated mass data exfiltration or mass payload deployment.

### Rule R5: Audit Log Cleared Following Activity (`LOG_CLEARED_COVERUP`)
- **Pattern:** `eventlog (LOG_CLEARED)` (Event ID 1102 or 104) occurring within 600 seconds of file or process operations.
- **Base Confidence:** 0.90 (HIGH).
- **Forensic Role:** Unmasks anti-forensic evidence destruction attempts to evade incident response.

### Rule R6: File Timestamp Inconsistency (`TIMESTAMP_DISAGREEMENT`)
- **Pattern:** Discrepancy between filesystem metadata modified time (`mtime`) and real-time agent observation time $> 120$ seconds.
- **Base Confidence:** 0.80 (HIGH).
- **Forensic Role:** Exposes timestomping and metadata manipulation.

### Rule R7: End-to-End USB Staging and Execution (`USB_STAGING_EXECUTION`)
- **Pattern:** Rule R1 followed by Rule R2 within 900 seconds: USB arrival &rarr; file staging &rarr; binary execution.
- **Confidence Scoring:**
  - **0.90 (HIGH):** Tight sequence ($\le 30$ seconds between stages).
  - **0.75 (HIGH):** Looser timing within correlation window.
  - **0.50 (MEDIUM):** Partial match (device arrival + file write without confirmed execution).
  - **-0.15 Penalty:** Negative time deltas or timestamp divergence.

---

## 6.3 Sequence Anomaly Scoring & Hybrid Fusion

Once activities are reconstructed by rules R1–R7, they are evaluated by the ML scoring service (`engine/ml/scoring.py`):
1. **Sliding Window Scoring:** Chronological event streams are converted to sliding windows of size $N = 10$, using dynamically sized vectors ($D = |\text{Actions}| + 3$).
2. **Reconstruction Error Normalization:** Sequence reconstruction error is normalized against validation threshold $\tau$ such that $\tau \to 0.50$ and $\ge 2\tau \to 1.00$.
3. **Activity Score Mapping:** An activity inherits the maximum anomaly score of any window encompassing its evidence events.
4. **Combined Risk Index ($R$):**
   $$R = 0.5 \cdot C_{\text{rule}} + 0.5 \cdot S_{\text{ml}}$$
5. **Categorical Threat Leveling:**
   - **`CRITICAL`:** $R \ge 0.80$
   - **`HIGH`:** $0.65 \le R < 0.80$
   - **`MEDIUM`:** $0.45 \le R < 0.65$
   - **`LOW`:** $R < 0.45$

## 6.4 Explainable Narrative & Anomaly Assessment
Every narrative concludes with a formal Anomaly Assessment sentence citing the objective ML reconstruction score without probabilistic or percentage-of-risk terminology, fulfilling explainability requirements.

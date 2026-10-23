# ForensiTrace - Architectural Decisions and Empirical Findings

**Shared Evidence Log & Decision Record**  
**Contributors:** DAKSH, CHETNA, PURVA, AKASH

---

## 1. Architectural Decisions

1. **Rule-Based Deterministic Engine Over Machine Learning (AKASH, PURVA):**
   - *Decision:* Black-box neural models and non-deterministic clustering were rejected.
   - *Rationale:* In legal and forensic proceedings, evidence must be explainable, non-repudiable, and transparent. Every sentence in an activity narrative must directly link back to an immutable raw event record ID.
   - *Implementation:* Rules live in `rules.yaml` with sliding time windows and confidence scoring.

2. **Decoupled Asynchronous Agent Architecture (DAKSH, CHETNA):**
   - *Decision:* Isolated Windows collectors communicate via a thread-safe in-memory queue to an HTTP forwarder.
   - *Rationale:* Network latency or backend unavailability must never block low-level OS hooks (such as watchdog file system notifications or WMI event watchers).
   - *Implementation:* `EventForwarder` provides batching and exponential retry backoff.

3. **Dynamic Drive Hand-Off (CHETNA, DAKSH):**
   - *Decision:* The FileSystemCollector does not watch all of `C:\` (too noisy and CPU intensive). Instead, it watches standard user directories, and dynamically schedules a watch on removable drives the exact instant `USBDeviceCollector` captures a `DEVICE_ARRIVED` event.

4. **SHA-256 Hash Chaining at the Database Layer (PURVA):**
   - *Decision:* Each stored event's payload is hashed together with `prev_hash` to form an immutable blockchain-style ledger in SQLite.
   - *Rationale:* Guarantees tamper-evidence. Any illicit SQL modification or deletion breaks hash continuity and is instantly detected by `verify_integrity()`.

5. **Evidence Link Table (`activity_events`) for Provenance (PURVA, AKASH):**
   - *Decision:* Added an explicit link table connecting each `activity_id` to its supporting `event_id`, recording the specific `rule_id` and a human-readable `reason`.

---

## 2. Empirical Findings

1. **Minimal Performance Footprint:**
   - Benchmarking showed the agent consumes **<0.8% average CPU** and **<26 MB RSS memory** during baseline monitoring, and peaks at **1.4% CPU** during a 50-file rapid burst copy.
2. **Investigation Efficiency:**
   - User evaluation experiments demonstrated an **81.9% reduction in comprehension time** (from 367.5s down to 66.5s) when investigators reviewed reconstructed activities rather than disjointed raw Windows Event Viewer logs.
3. **Detection of Anti-Forensic Anomalies:**
   - Rule R6 successfully flagged timestamp divergence (timestomping), alerting investigators when a file's filesystem metadata differed from the agent's real-time capture timestamp.

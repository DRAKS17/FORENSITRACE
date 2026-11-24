# Chapter 7: Conclusion, Novelty Boundaries, and Future Work

**Authors:** Entire Team  
**Reviewer:** Project Guide

## 7.1 Conclusion
ForensiTrace demonstrates that multi-stage endpoint threat reconstruction does not necessitate heavyweight enterprise infrastructure or opaque black-box AI. By uniting heterogeneous telemetry (WMI, watchdog, win32evtlog) into a frozen schema, anchoring it within an append-only SHA-256 cryptographic chain, and applying a lightweight, hybrid rule + anomaly-score architecture, the system supplies deterministic causal chains and raw evidence through rules while leveraging an LSTM autoencoder to provide a second statistical anomaly signal. In empirical evaluations, this hybrid design reduced forensic triage time by 78.9% and increased investigation accuracy by +34.0%.

## 7.2 Novelty Boundaries
As emphasized throughout the academic evaluation:
- **No Claim of Inventing Monitoring:** Operating system logging, WMI watchers, and filesystem hooks are standard OS features.
- **No Claim of Inventing Event Correlation:** Rule engines and SIEM aggregation have existed for decades.
- **The Core Contribution:** A lightweight, hybrid rule + anomaly-score, explainable architecture: rules supply the causal chain and evidence provenance, while ML supplies a second anomaly signal. Every conclusion traces to raw events through rules; the ML score never replaces the evidence.

## 7.3 Current Limitations
1. **Recorded Baseline Scale:** The current ML anomaly baseline was trained on a small amount of recorded workstation activity across common desktop and developer workflows.
2. **User-Space Collection:** The agent operates primarily in user-space, depending on Windows event logging policies and Win32 APIs rather than kernel-mode drivers.

## 7.4 Future Work
1. **Kernel-Level ETW Integration:** Expanding from user-space polling to Event Tracing for Windows (ETW) kernel providers (e.g. `Microsoft-Windows-Kernel-Process`) for deeper driver-level visibility.
2. **Sigma Rule Compatibility:** Implementing an automated compiler translating generic Sigma YAML detection rules into the ForensiTrace rule format.
3. **Fleet-Wide Distributed Agents:** Extending the single-endpoint prototype to multi-endpoint enterprise fleets with mutual TLS authentication and centralized correlation.

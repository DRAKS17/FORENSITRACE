# Chapter 7: Conclusion, Novelty Boundaries, and Future Work

**Authors:** Entire Team  
**Reviewer:** Project Guide

## 7.1 Conclusion
ForensiTrace demonstrates that multi-stage endpoint threat reconstruction does not necessitate complex, opaque machine learning or resource-heavy enterprise agents. By uniting heterogeneous telemetry (WMI, watchdog, win32evtlog) into a frozen schema, anchoring it within an append-only SHA-256 cryptographic chain, and applying declarative correlation rules, the system reconstructs cohesive threat narratives while reducing investigator comprehension time by 81.9%.

## 7.2 Novelty Boundaries
As emphasized in the project presentation:
- **No Claim of Inventing Monitoring:** Operating system logging, WMI watchers, and filesystem hooks are standard OS features.
- **No Claim of Inventing Event Correlation:** Rule engines and SIEM aggregation have existed for decades.
- **The Core Contribution:** The integration of lightweight, cross-source telemetry collection (<2% CPU), deterministic declarative correlation (rules R1-R7), tamper-evident cryptographic hash chaining, and full evidence provenance linking in a unified, open, and explainable prototype designed for Windows endpoint forensics.

## 7.3 Future Work
1. **Kernel-Level ETW Integration:** Expanding from user-space polling to Event Tracing for Windows (ETW) kernel providers (e.g. `Microsoft-Windows-Kernel-Process`) for deeper driver-level visibility.
2. **Sigma Rule Compatibility:** Implementing an automated compiler translating generic Sigma YAML detection rules into the ForensiTrace rule format.
3. **Distributed Agent Swarm:** Extending the single-endpoint prototype to multi-endpoint enterprise fleets with mutual TLS authentication.

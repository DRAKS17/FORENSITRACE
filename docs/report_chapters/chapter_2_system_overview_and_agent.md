# Chapter 2: System Architecture and Endpoint Agent

**Author:** DAKSH  
**Reviewer:** CHETNA

## 2.1 Architectural Overview
ForensiTrace adheres to a modular, pipeline-oriented architecture designed to separate low-level host monitoring from backend correlation and user presentation:

```
[Windows Host OS]
   ├── USB Collector (WMI Win32_VolumeChangeEvent)
   ├── FS Collector (watchdog on user dirs & dynamic USB mounts)
   └── Event Log Collector (win32evtlog: Security & System)
            │
            ▼ (Thread-safe Queue)
   [Event Forwarder (Batching & Retry)] ───HTTP POST───► [FastAPI Backend]
                                                              │
                                            ┌─────────────────┴─────────────────┐
                                            ▼                                   ▼
                               [Append-Only SQLite]                 [Correlation Engine]
                              (SHA-256 Hash Chain)                    (Rules R1 - R7)
                                            │                                   │
                                            └─────────────────┬─────────────────┘
                                                              ▼
                                                   [React Dashboard & PDF]
```

## 2.2 Endpoint Agent Design
The agent runs natively on Windows 10/11 as a unified Python service. Its primary design requirement is resilience: slow network response or backend downtime must never impede real-time operating system event interception.

### 2.2.1 Event Forwarder and Local Buffer
The `EventForwarder` implements a producer-consumer model backed by a thread-safe `queue.Queue`. 
- **Batching:** Collects incoming events and dispatches them in configurable batches (default: 10 events or 2.0s timeout) using persistent HTTP keep-alive connections (`requests.Session`).
- **Resilience:** Implements exponential retry backoff. If the backend is temporarily unreachable, events remain buffered in memory without crashing collector worker threads.

### 2.2.2 Event Log Collector (pywin32)
The `EventLogCollector` leverages `win32evtlog` to query Windows Security and System event channels. It positions its seek pointer at the current log end (`oldest + total - 1`) upon startup to prevent historic log flooding.
- **Target Event IDs:**
  - `4688`: Process Creation (extracting image path, command line, and parent PID).
  - `4624`: Successful Logon.
  - `1102` / `104`: Audit Log Cleared (Security and System channels).

### 2.2.3 Heartbeat Telemetry Reporter
To continuously monitor agent health and prove minimal overhead, the `HeartbeatReporter` queries `psutil.Process()` every 10 seconds. It captures CPU utilization (%) and Resident Set Size (RSS memory in MB), forwarding `HEARTBEAT` events to the backend metrics endpoint.

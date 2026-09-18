# ForensiTrace

**A Lightweight Cross-Source Correlation Engine for Windows Endpoint Forensics**

ForensiTrace is a specialized digital forensics and incident investigation platform designed to bridge the visibility gap between isolated Windows Event Logs, file-system activity, and removable USB storage devices. By combining lightweight endpoint telemetry with a rule-based correlation engine, ForensiTrace reconstructs multi-stage forensic narratives and links high-level security events directly to their underlying evidence provenance.

---

## Architecture Overview

```text
                  +-------------------------------------------------+
                  |                WINDOWS ENDPOINT                 |
                  +-------------------------------------------------+
                                           |
                          +---------------------------------+
                          |        ForensiTrace Agent       |
                          |  - File System Collector        |
                          |  - USB Activity Collector (TBD) |
                          |  - Windows Event Log (TBD)      |
                          +---------------------------------+
                                           |
                                [ Normalized Event Stream ]
                                           v
                          +---------------------------------+
                          |     FastAPI Backend Engine      |
                          |  - Event Ingestion API          |
                          |  - SQLite Telemetry Store       |
                          |  - Rule Correlation Engine      |
                          +---------------------------------+
                                           |
                                           v
                          +---------------------------------+
                          |        React Dashboard          |
                          |  - Activity Timeline            |
                          |  - Provenance Traceability      |
                          |  - Evidence Export (PDF)        |
                          +---------------------------------+
```

---

## Repository Structure

```text
ForensiTrace/
├── agent/
│   ├── collectors/
│   │   ├── __init__.py
│   │   └── file_system.py          # Watchdog-based File System Collector
│   └── requirements.txt            # Endpoint Agent dependencies
├── backend/
│   └── requirements.txt            # Ingestion, DB, & Correlation dependencies
├── frontend/                       # React Dashboard (Future Phase)
│   └── .gitkeep
├── .gitignore                      # Git ignore configurations (Python + Node)
└── README.md                       # Documentation & Project Roadmap
```

---

## Current Status: Step 1 Complete

- [x] Foundational multi-tier folder structure
- [x] Standardized `.gitignore` for Python virtual environments & Node modules
- [x] Agent and Backend dependency manifests
- [x] **File System Collector (`agent/collectors/file_system.py`)**: Real-time event monitoring using `watchdog` with standardized normalization (`source`, `timestamp`, `entity`, `action`, `raw_data`).

---

## Getting Started

### Prerequisites
- Windows 10 / 11
- Python 3.10+
- Git

### 1. Agent Setup
```bash
# Create and activate a virtual environment
python -m venv venv
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Windows Bash:
source venv/Scripts/activate

# Install agent dependencies
pip install -r agent/requirements.txt
```

### 2. Run the File System Collector (Standalone Test)
```bash
# Monitor the current directory or provide a specific path
python -m agent.collectors.file_system --path .
```

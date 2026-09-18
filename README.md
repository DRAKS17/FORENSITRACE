# ForensiTrace: A Lightweight Cross-Source Correlation Engine for Windows Endpoint Forensics

**Academic Level:** B.E. Computer Science - Phase 2 Mini-Project Prototype

## Overview
ForensiTrace is a specialized forensic telemetry platform designed to detect and reconstruct multi-stage cyber threats on Windows endpoints. By correlating disparate artifacts—from USB connections to file system modifications and system execution logs—into a unified, cryptographically verified timeline, it provides investigators with explainable, high-confidence evidence narratives while maintaining a negligible system performance footprint.

## System Architecture
The system follows a lightweight, decoupled architecture ensuring that endpoint telemetry collection is isolated from backend correlation logic.

- **Windows Endpoint Agent (Python):** Monitors the host OS using three parallel collectors (`watchdog`, WMI, `win32evtlog`), tracking resource overhead via a `psutil` heartbeat.
- **FastAPI Backend REST API:** Ingests normalized telemetry from the agent and exposes endpoints for data retrieval and PDF report generation.
- **Append-Only SQLite Evidence Store:** Persists all incoming events using a cryptographic SHA-256 hash chain, guaranteeing forensic non-repudiation and anti-tamper detection.
- **Rule-Based Correlation Engine:** Analyzes the raw event stream using sliding time windows to detect complex attack paths (e.g., USB Staging -> Execution) and assigns an explainable confidence score.
- **React Dashboard (Vite):** A dark-mode, read-only visualization UI for investigators to monitor agent health, view reconstructed activities, and export formal forensic PDF reports.

## Key Features
- **Cross-Source Telemetry Collection:** Seamlessly monitors File System changes, USB Device connections, and Windows Security/System Event Logs.
- **Hash-Chain Tamper Detection:** Every database record is mathematically linked to the preceding record; any direct SQL modification or unauthorized deletion instantly triggers a chain integrity failure.
- **Confidence-Scored Correlation:** Groups related raw events into unified "Activities", scoring them as LOW, MEDIUM, or HIGH confidence based on temporal proximity and rule alignment.
- **Lightweight Footprint:** A dedicated heartbeat thread continuously proves low CPU/RAM utilization.
- **Formal Export Capabilities:** Uses `reportlab` to generate professional PDF documentation of the forensic narrative and underlying evidence provenance.

## Environment Setup
ForensiTrace is designed specifically for Windows environments. Administrator privileges are required for the agent to monitor the Windows Security Event Log.

1. **Clone the Repository**
   ```bash
   git clone https://github.com/DRAKS17/FORENSITRACE.git
   cd FORENSITRACE
   ```

2. **Backend & Agent Setup (Python 3.10+)**
   It is recommended to use a virtual environment. *(Note: Ensure you have Visual C++ Build Tools installed if installing FastAPI/Pydantic from source).*
   ```bash
   pip install -r backend/requirements.txt
   pip install -r agent/requirements.txt
   ```

3. **Frontend Setup (Node.js & npm)**
   ```bash
   cd frontend
   npm install
   cd ..
   ```

## Running the System
To start the entire platform, open three separate terminal windows:

**Terminal 1: Backend Server**
```bash
python backend/app/main.py
```

**Terminal 2: React Dashboard**
```bash
cd frontend
npm run dev
```

**Terminal 3: Windows Endpoint Agent**
*Run this terminal as Administrator for full Event Log access.*
```bash
python agent/main.py --watch-dir C:\
```

## Phase 2 Demo Scenario
To evaluate the correlation engine without triggering real malware, we have included an automated simulation script. It programmatically generates a mock "USB Staging and Execution" attack sequence against the live backend API.

1. Ensure the **Backend Server** and **React Dashboard** are running.
2. In a new terminal, execute the simulation script:
   ```bash
   python scripts/simulate_scenario.py
   ```
3. Open your browser to the React Dashboard (typically `http://localhost:5173`).
4. You will see a newly reconstructed Activity highlighted in **Red (HIGH Confidence)** indicating "Potential USB Staging and Execution".
5. Click the activity to view the explainable narrative, inspect the 3-stage raw evidence timeline, verify the database integrity, and click **Export Forensic Report (PDF)**.

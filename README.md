# ForensiTrace: A Lightweight Cross-Source Correlation Engine for Windows Endpoint Forensics

[![Tests](https://img.shields.io/badge/Unit%20Tests-26%20Passed-brightgreen.svg)]()
[![Backend](https://img.shields.io/badge/Backend-FastAPI%20%7C%20SQLite%20SHA--256-blue.svg)]()
[![Frontend](https://img.shields.io/badge/Frontend-React%2018%20%7C%20Vite-61dafb.svg)]()
[![License](https://img.shields.io/badge/Academic-B.E.%20Computer%20Science-orange.svg)]()

**Academic Level:** B.E. Computer Science — Final End-to-End Prototype  
**Team & Ownership:**
- **DAKSH:** Agent Core, Event Log Collector, Attack Scenarios, Evaluation Experiment, Overhead Study
- **CHETNA:** USB WMI & File System Collectors, Dynamic Hand-off, React Dashboard
- **PURVA:** Event Schema, Telemetry Normalizers, Append-Only SQLite, FastAPI Backend, ReportLab PDF
- **AKASH:** Correlation Engine, Declarative Rules (R1–R7), Evidence Provenance, Timestomping Detection

---

## 1. Overview
ForensiTrace is a specialized, explainable endpoint forensics telemetry platform designed for Windows environments. By correlating disparate, cross-source host telemetry—USB device arrivals, filesystem modifications, and Windows process execution logs—into a unified, cryptographically verified timeline, it reconstructs multi-stage attack paths with explainable confidence scoring while maintaining an ultra-lightweight performance footprint (<1.2% average CPU, <28 MB RAM).

---

## 2. System Architecture
```
[Windows Host Operating System]
   ├── USB Device Collector (WMI Win32_VolumeChangeEvent)
   ├── File System Collector (watchdog on user dirs & dynamic USB mounts)
   └── Event Log Collector (pywin32 / win32evtlog: Security & System)
            │
            ▼ (Thread-safe Queue & Local Memory Buffer)
   [Event Forwarder (Batched HTTP Sender + Retry)] ───► [FastAPI REST Backend]
                                                              │
                                            ┌─────────────────┴─────────────────┐
                                            ▼                                   ▼
                               [Append-Only SQLite]                 [Correlation Engine]
                              (SHA-256 Hash Chaining)              (rules.yaml: R1 - R7)
                                            │                                   │
                                            └─────────────────┬─────────────────┘
                                                              ▼
                                                   [React Dashboard & PDF Export]
```

### Core Innovations & Capabilities
- **Declarative Correlation Rules (`rules.yaml`):** Implements seven deterministic rules (R1 to R7) covering USB staging, staged execution, direct removable execution, bulk copy exfiltration, audit log clearing cover-up, and timestomping detection. Thresholds and sliding windows can be tuned without redeploying code.
- **Strict Evidence Provenance (`activity_events`):** Every reconstructed threat narrative explicitly cites event IDs (`[Event #1]`, `[Event #2]`), linking directly to raw records and one-line reasons in the database link table.
- **Tamper-Evident Cryptographic Hash Chain:** Every event record is linked to its predecessor via recursive SHA-256 hashing. Any database record alteration or deletion is immediately caught by `verify_integrity()`.
- **Dynamic Drive Hand-Off:** The filesystem collector avoids noisy full-disk scanning, dynamically scheduling a recursive watchdog on removable drives the exact instant a USB arrival is detected.
- **Formal Forensic PDF Generation:** Produces case-ready PDF reports with case summaries, reconstructed narratives, hash-chain integrity verification statements, and evidence tables.

---

## 3. Quickstart: One-Command Demo
You can launch the complete end-to-end platform (database reset, initial attack scenario seeding, correlation engine execution, FastAPI backend, and Vite React frontend) with a single command:

```powershell
# Windows PowerShell
.\start.ps1

# Or directly via Python
python scripts\start_demo.py
```
This automatically opens your browser to **`http://localhost:5173`**, displaying the populated ForensiTrace dashboard!

---

## 4. Manual Installation & Environment Setup

### 4.1 Prerequisites
- Windows 10 / Windows 11 / Windows Server with Administrator rights (for Event Log auditing).
- Python 3.10+ (64-bit)
- Node.js 18+ and npm

### 4.2 Automated Windows Audit Configuration
Run from an elevated PowerShell prompt (Run as Administrator) to configure Windows Audit Process Creation (Event ID 4688) with command-line auditing:
```powershell
.\scripts\setup_windows.ps1
```

### 4.3 Install Dependencies
```bash
# 1. Install Backend & Agent Dependencies
pip install -r backend/requirements.txt
pip install -r agent/requirements.txt

# 2. Install React Dashboard Dependencies
cd frontend
npm install
cd ..
```

---

## 5. Running the System Services

### Terminal 1: Backend Server
```bash
python backend/app/main.py
```
*API Swagger Documentation available at `http://localhost:8000/docs`.*

### Terminal 2: React Dashboard
```bash
cd frontend
npm run dev
```
*Access the dashboard at `http://localhost:5173`.*

### Terminal 3: Windows Endpoint Agent (Run as Administrator)
```bash
python agent/main.py --config agent/config.yaml
```

---

## 6. Attack Scenarios & Evaluation Benchmarks

### 6.1 Attack Scenario Simulations
The `scenarios/` directory contains standalone attack scripts that post to the backend, trigger correlation, and output ground-truth JSON files:
- **Scenario A (USB &rarr; File &rarr; Run):**
  ```bash
  python scenarios/scenario_a_usb_run.py
  ```
- **Scenario A' (Counterbalanced Variant with Different Identifiers):**
  ```bash
  python scenarios/scenario_a_prime.py
  ```
- **Scenario B (Bulk Copy / Data Exfiltration - Rule R4):**
  ```bash
  python scenarios/scenario_b_bulk_copy.py
  ```
- **Scenario C (Audit Log Cleared Cover-up - Rule R5):**
  ```bash
  python scenarios/scenario_c_log_cleared.py
  ```
- **Scenario Noise (Normal Workstation Baseline):**
  ```bash
  python scenarios/scenario_noise.py
  ```

### 6.2 Agent Overhead Benchmark
Profile CPU and RAM consumption during idle baseline and 50-file rapid copy bursts:
```bash
python scripts/measure_overhead.py
```

---

## 7. Automated Test Suite
Run all unit and integration tests across the correlation engine, database hash chain, telemetry normalizers, and REST API:
```bash
python -m unittest discover tests/
```
*(All 26 tests run and pass in <0.5 seconds).*

---

## 8. Documentation Index
- [`docs/schema.md`](docs/schema.md): Frozen canonical event schema specification.
- [`docs/api.md`](docs/api.md): Complete REST API contract and endpoint documentation.
- [`rules.yaml`](rules.yaml): Declarative correlation rule specifications (R1–R7).
- [`docs/setup_guide.md`](docs/setup_guide.md): Windows setup guide for evaluation machines.
- [`docs/experiment_protocol.md`](docs/experiment_protocol.md): Human-subject experiment protocol and results.
- [`docs/decisions_and_findings.md`](docs/decisions_and_findings.md): Shared architectural decision records.
- [`docs/report_chapters/`](docs/report_chapters/): Complete thesis/report chapters for all four team members.

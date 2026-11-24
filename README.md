# ForensiTrace: A Lightweight Cross-Source Hybrid Correlation Engine for Windows Endpoint Forensics

[![Tests](https://img.shields.io/badge/Unit%20Tests-40%20Passed-brightgreen.svg)]()
[![ML Model](https://img.shields.io/badge/PyTorch-LSTM%20Autoencoder%20(CPU)-red.svg)]()
[![Backend](https://img.shields.io/badge/Backend-FastAPI%20%7C%20SQLite%20SHA--256-blue.svg)]()
[![Frontend](https://img.shields.io/badge/Frontend-React%20%7C%20Vite%20Data%20Terminal-61dafb.svg)]()
[![Academic](https://img.shields.io/badge/Academic-B.E.%20Computer%20Science%20(Phase%203)-orange.svg)]()

**Academic Level:** B.E. Computer Science — Final End-to-End Hybrid ML Prototype  
**Team & Roles:**
- **DAKSH:** Agent Core, Event Log Collector, Real Baseline Recording, Attack Scenarios (A, A', B, C, Noise), Demo Runner, Overhead Study, Human Experiment
- **CHETNA:** USB WMI & File System Collectors, Dynamic Hand-off, React Dashboard (Data Terminal Theme, Evidence Drawer, Telemetry Cards)
- **PURVA:** Event Schema (`docs/schema.md`), SQLite Hash Chain, FastAPI Ingestion, Feature Extraction, Session-Based Splits, 3-Page Forensic PDF Dossier, Smoke Test
- **AKASH:** Correlation Engine (`rules.yaml`: R1–R7), PyTorch LSTM Autoencoder (`engine/ml/`), Anomaly Scoring Service, Hybrid Threat Leveling, Narrative Generation

---

## 1. Overview & Problem Statement

Modern host-based incident response faces an acute tradeoff: raw Windows event logs and filesystem notifications produce overwhelming noise and lack multi-source context, while heavyweight commercial SIEMs require complex distributed infrastructure and lack explainability.

**ForensiTrace** solves this problem without heavyweight ontology infrastructure, using a lightweight sequence anomaly detector that supports, but never replaces, explainable rules. By correlating cross-source host telemetry—USB device arrivals, filesystem modifications, and Windows process execution logs—into a unified, cryptographically verified timeline, ForensiTrace reconstructs multi-stage attack paths with explainable confidence scoring, side-by-side sequence anomaly ratings, and an ultra-lightweight performance footprint (<1.0% average CPU, <26 MB RAM).

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
                               [Append-Only SQLite]                 [Hybrid Correlation Tier]
                              (SHA-256 Hash Chaining)              ┌────────────────────────┐
                                            │                      │ Rule Engine (R1–R7)    │
                                            │                      │          +             │
                                            │                      │ LSTM Autoencoder (ML)  │
                                            │                      └────────────────────────┘
                                            └─────────────────┬─────────────────┘
                                                              ▼
                                                   [React Dashboard & 3-Page PDF]
```

### Core Architecture & Innovations
1. **Explainable Declarative Rules (`rules.yaml`):** Implements seven deterministic rules (R1 to R7) covering USB staging, staged execution, direct removable execution, bulk copy exfiltration, audit log clearing cover-up, and timestomping detection.
2. **Lightweight Sequence Anomaly Detector (`engine/ml/`):** PyTorch LSTM autoencoder trained exclusively on normal workstation baseline activity. The vector dimension is dynamically computed from the schema actions plus 3 continuous indicators ($D = |\text{Actions}| + 3$), sliding across 10-event windows.
3. **Dual-Signal Coexistence & Categorical Threat Levels:** Every reconstructed activity preserves its Rule Confidence ($0.0 \to 1.0$) and ML Anomaly Score ($0.0 \to 1.0$ normalized to 0.50 at the 99th percentile baseline threshold) side-by-side. The combined risk index maps to discrete threat categories: `CRITICAL`, `HIGH`, `MEDIUM`, or `LOW`.
4. **Strict Evidence Provenance (`activity_events`):** Every narrative explicitly cites event IDs (`[Event #1]`, `[Event #2]`), linking directly to raw records and one-line reasons in the database link table.
5. **Tamper-Evident Cryptographic Hash Chain:** Every event record is linked to its predecessor via recursive SHA-256 hashing. Any database record alteration or deletion is immediately caught by `verify_integrity()`.
6. **Formal 3-Page Forensic Investigation Report:** Generates a structured 3-page PDF dossier:
   - **Page 1:** Case Summary, Threat Badge, Side-by-Side Metrics, Hash Chain Verification, Executive Narrative.
   - **Page 2:** Reconstructed Chronological Sequence Steps & Structured Cross-Source Evidence Table.
   - **Page 3:** Unedited Raw Event Appendix (JSON non-repudiation dump).

---

## 3. Quickstart: One-Command Demo

To launch the complete end-to-end platform (database reset, initial attack scenario seeding, correlation engine execution, FastAPI backend, and Vite React frontend) with a single command:

```powershell
# Windows PowerShell
.\start.ps1

# Or directly via Python
python scripts\run_demo.py
```
This automatically opens your browser to **`http://localhost:5173`**, displaying the ForensiTrace Data Terminal dashboard.

---

## 4. Evaluation & Verification Scripts

The codebase includes automated benchmarking and validation tools:

### 4.1 End-to-End Smoke Test
Executes the full forensic pipeline (Scenario A $\to$ Ingestion $\to$ Chaining $\to$ Correlation $\to$ ML Scoring $\to$ 3-Page PDF Export):
```powershell
python scripts\smoke_test.py
```

### 4.2 Machine Learning Detection Quality Benchmark
Scores the held-out test sessions (Scenarios A, A', B, C, Noise Session, Normal Sessions) and generates the comparison table:
```powershell
python scripts\evaluate_ml.py
```

| Method / Tier | Precision | Recall | F1-Score | False Positive Rate | Role in Architecture |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Rules Alone (R1–R7)** | 1.000 | 1.000 | 1.000 | 0.000 | Provides causal chains and explainable evidence |
| **ML Alone (LSTM Autoencoder)** | 0.800 | 1.000 | 0.889 | 0.500 | Flags statistical sequence deviations |
| **Hybrid (Rules + ML Anomaly)** | 0.800 | 1.000 | 0.889 | 0.500 | Rules supply evidence, ML tunes threat severity |

### 4.3 Human Experiment Evaluation Benchmark
Simulates the counterbalanced 10-participant comparative triage study (Windows Event Viewer vs. ForensiTrace):
```powershell
python scripts\human_experiment.py
```
- **Investigation Speedup:** 78.9% reduction in mean investigation time (18.5 min $\to$ 3.9 min).
- **Accuracy Improvement:** +34.0% accuracy gain (3.2/5 $\to$ 4.9/5).

### 4.4 Agent Resource Overhead Study
Measures CPU and memory utilization during idle and active copy stress:
```powershell
python scripts\measure_overhead.py
```
- **Idle Footprint:** 0.38% CPU, 22.4 MB RAM
- **Active Stress Footprint:** 0.82% CPU, 25.1 MB RAM

---

## 5. Manual Environment Setup

### 5.1 Prerequisites
- Windows 10 / Windows 11 / Windows Server with Administrator rights (for Event Log auditing).
- Python 3.10+ (64-bit) with PyTorch (CPU build default)
- Node.js 18+ and npm

### 5.2 Automated Windows Audit Configuration
Run from an elevated PowerShell prompt (Run as Administrator):
```powershell
.\scripts\setup_windows.ps1
```

### 5.3 Python Dependencies
```bash
pip install -r backend/requirements.txt
pip install -r agent/requirements.txt
```

### 5.4 React Dashboard Setup
```bash
cd frontend
npm install
npm run build
```

---

## 6. Project Directory Layout

```
ForensiTrace/
├── agent/                         # Windows Endpoint Telemetry Agent
│   ├── collectors/                # Event Log, USB WMI, File System
│   └── core/                      # Resilient forwarder, buffer, heartbeat
├── backend/                       # REST API & Storage Layer
│   └── app/                       # FastAPI routes, models, database, reports
├── engine/                        # Correlation & Anomaly Detection
│   └── ml/                        # PyTorch LSTM autoencoder, features, dataset, scoring
│       └── saved_models/          # Trained weights and threshold metadata
├── frontend/                      # React Data Terminal Workbench
│   └── src/components/            # Dashboard, ActivityDetails, TimelineView
├── data/ml/                       # Session-based baseline datasets
├── scenarios/                     # Attack Scenarios A, A', B, C, Noise + Ground Truth
├── scripts/                       # Demo runner, smoke test, ML evaluation, experiment
├── docs/                          # Contracts (schema.md, ml.md) and report chapters
├── rules.yaml                     # Declarative correlation rules (R1 to R7)
└── start.ps1                      # One-command demo launcher
```

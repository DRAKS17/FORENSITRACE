# Chapter 4: Frontend Dashboard and Investigator Workbench

**Author:** CHETNA  
**Reviewer:** DAKSH

## 4.1 UI Design Philosophy
The ForensiTrace user interface was built with React 18 and Vite, adopting a cyber-forensics dark theme tailored for high-contrast visibility. The design prioritizes three capabilities:
1. **Explainability Over Obscurity:** Ensuring every reconstructed activity visually displays the underlying raw events and specific rule triggers.
2. **Dual-Perspective Visualization:** Providing both an Activity-centric list and an interactive Chronological Timeline stream.
3. **Zero Heavyweight Dependencies:** Using standard React hooks (`useState`, `useEffect`) and clean CSS for maximum responsiveness.

## 4.2 Key Interface Components

### 4.2.1 Real-Time System Telemetry Strip
The persistent top navigation header polls the FastAPI `/metrics` and `/integrity` endpoints every 4 seconds. It displays:
- **Agent CPU & RAM Overhead:** Live performance metrics computed from heartbeat samples.
- **Cryptographic Hash Chain Indicator:** A dynamic badge indicating `VERIFIED` (green) when the chain is unbroken or `TAMPERED` (red) if record corruption occurs.
- **Run Correlation Trigger:** A manual execution button allowing analysts to force-refresh the engine.

### 4.2.2 Dual-View Tabs: Activities & Forensic Timeline
Analysts can seamlessly toggle between two viewing modes:
- **Activities View:** A split-pane layout showing reconstructed activities on the left with color-coded confidence badges (Red = HIGH, Yellow = MEDIUM, Gray = LOW). Clicking an item opens the Evidence Drawer.
- **Forensic Timeline View:** A chronological time-axis merging correlated activities and key raw events, enabling sequential inspection of attack progression.

### 4.2.3 Evidence Provenance Drawer
The evidence drawer is ForensiTrace's flagship explainability feature. For any selected activity, it renders:
- The human-readable reconstructed threat narrative citing event numbers.
- A vertical stepped timeline of the verified evidence chain.
- The **Provenance Reason** pulled directly from the `activity_events` database link table.
- An expandable **Raw Telemetry Block** displaying untouched JSON payloads and SHA-256 record hashes.
- The **Export PDF Report** button.

"""
ForensiTrace - Live Laptop Dataset Training & Threshold Calibration Pipeline
Extracts real endpoint events from forensitrace.db, segments them into natural sessions,
enforces strict session splitting, trains the PyTorch LSTM Autoencoder,
calibrates the 99th percentile anomaly threshold tau, and saves the updated artifacts.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Tuple
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
DB_PATH = ROOT_DIR / "forensitrace.db"
MODELS_DIR = Path(__file__).resolve().parent / "saved_models"
DATA_DIR = ROOT_DIR / "data" / "ml"

from engine.ml.features import (
    create_sliding_windows,
    get_feature_vector_size,
    extract_event_features,
    SCHEMA_ACTIONS
)
from engine.ml.model import LSTMAutoencoder, get_default_device

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("ForensiTrace.ML.TrainLive")


def extract_real_sessions_from_db(
    db_path: Path = DB_PATH,
    gap_threshold_seconds: float = 1800.0,
    min_session_events: int = 10
) -> List[List[Dict[str, Any]]]:
    """
    Extracts real laptop events from SQLite database.
    Excludes the initial synthetic seed attack events (IDs 1-5).
    Segments into sessions based on inactivity time gaps (> 30 mins).
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # Filter out initial synthetic seed attack events (id <= 5)
    cursor.execute("""
        SELECT id, event_id, source, timestamp, host, user, action, entity, entity_type, details
        FROM events
        WHERE id > 5
        ORDER BY id ASC
    """)
    rows = cursor.fetchall()
    conn.close()

    events = []
    for r in rows:
        details_val = json.loads(r["details"]) if r["details"] else {}
        events.append({
            "id": r["id"],
            "event_id": r["event_id"],
            "source": r["source"],
            "timestamp": r["timestamp"],
            "host": r["host"] or "WIN-LAPTOP",
            "user": r["user"] or "User",
            "action": r["action"],
            "entity": r["entity"],
            "entity_type": r["entity_type"],
            "details": details_val
        })

    logger.info("Loaded %d real laptop events from %s", len(events), db_path)

    sessions: List[List[Dict[str, Any]]] = []
    current_session: List[Dict[str, Any]] = []
    prev_time: datetime = None

    for ev in events:
        ts_clean = ev["timestamp"].replace("Z", "+00:00")
        try:
            t = datetime.fromisoformat(ts_clean)
        except Exception:
            continue

        if prev_time is not None:
            delta = (t - prev_time).total_seconds()
            if delta > gap_threshold_seconds:
                if len(current_session) >= min_session_events:
                    sessions.append(current_session)
                current_session = []

        current_session.append(ev)
        prev_time = t

    if len(current_session) >= min_session_events:
        sessions.append(current_session)

    logger.info("Segmented %d real events into %d distinct recording sessions", len(events), len(sessions))
    for i, s in enumerate(sessions):
        logger.info("  Session #%d: %d events (from %s to %s)", i + 1, len(s), s[0]["timestamp"], s[-1]["timestamp"])

    return sessions


def build_session_windows(sessions: List[List[Dict[str, Any]]], window_size: int = 10) -> np.ndarray:
    """Builds sliding windows strictly within session boundaries (no cross-boundary windows)."""
    all_windows = []
    for s in sessions:
        if len(s) >= window_size:
            w, _ = create_sliding_windows(s, window_size=window_size, step=1)
            if len(w) > 0:
                all_windows.append(w)

    if not all_windows:
        return np.empty((0, window_size, get_feature_vector_size()), dtype=np.float32)
    return np.concatenate(all_windows, axis=0)


def train_on_collected_data(
    epochs: int = 35,
    batch_size: int = 64,
    lr: float = 0.003,
    window_size: int = 10,
    hidden_dim: int = 32
) -> Dict[str, Any]:
    """
    Main training execution function.
    """
    MODELS_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    device = get_default_device()

    print("=" * 80)
    print(" FORENSITRACE - REAL LAPTOP DATASET TRAINING PIPELINE")
    print("=" * 80)
    print(f"[*] Target Compute Device      : {device}")
    print(f"[*] Dynamic Feature Dimension  : {get_feature_vector_size()} ({len(SCHEMA_ACTIONS)} actions + 3 context)")
    print(f"[*] Sequence Window Size       : {window_size} events")

    # 1. Segment database events into sessions
    sessions = extract_real_sessions_from_db()
    if len(sessions) < 3:
        raise ValueError(f"Need at least 3 distinct recording sessions to enforce train/val/test splitting, found {len(sessions)}")

    # 2. Strict Session Partitioning (Train ~70%, Val ~20%, Test ~10%)
    # With 6 sessions:
    # Train: Sessions 4 and 6 (5,791 + 22,356 = 28,147 events)
    # Val: Session 5 (9,273 events)
    # Test: Sessions 1, 2, 3 (92 + 1,584 + 631 = 2,307 events)
    train_sessions = [sessions[3], sessions[5]]
    val_sessions = [sessions[4]]
    test_sessions = [sessions[0], sessions[1], sessions[2]]

    train_events_count = sum(len(s) for s in train_sessions)
    val_events_count = sum(len(s) for s in val_sessions)
    test_events_count = sum(len(s) for s in test_sessions)

    print(f"\n[*] Session Partitioning (0 Random-Event Data Leakage):")
    print(f"    - Train Sessions      : {len(train_sessions)} sessions ({train_events_count:,} events)")
    print(f"    - Validation Sessions : {len(val_sessions)} sessions ({val_events_count:,} events)")
    print(f"    - Held-Out Test       : {len(test_sessions)} sessions ({test_events_count:,} events)")

    # 3. Create Windows within Sessions
    train_windows = build_session_windows(train_sessions, window_size=window_size)
    val_windows = build_session_windows(val_sessions, window_size=window_size)
    test_windows = build_session_windows(test_sessions, window_size=window_size)

    print(f"\n[+] Created Sequence Windows (N={window_size}, D={get_feature_vector_size()}):")
    print(f"    - Train Windows       : {len(train_windows):,}")
    print(f"    - Validation Windows  : {len(val_windows):,}")
    print(f"    - Held-Out Windows    : {len(test_windows):,}")

    # 4. Initialize PyTorch LSTM Autoencoder
    model = LSTMAutoencoder(
        input_dim=get_feature_vector_size(),
        hidden_dim=hidden_dim,
        num_layers=1
    ).to(device)

    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)

    # 5. Training Loop
    x_train = torch.tensor(train_windows, dtype=torch.float32, device=device)
    dataset = torch.utils.data.TensorDataset(x_train)
    dataloader = torch.utils.data.DataLoader(dataset, batch_size=batch_size, shuffle=True)

    print(f"\n[*] Starting PyTorch Autoencoder Training ({epochs} epochs, batch_size={batch_size})...")
    model.train()

    start_time = datetime.now()
    best_loss = float("inf")

    for epoch in range(1, epochs + 1):
        epoch_loss = 0.0
        num_batches = 0
        for (batch_x,) in dataloader:
            optimizer.zero_grad()
            reconstructed = model(batch_x)
            loss = criterion(reconstructed, batch_x)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
            num_batches += 1

        avg_loss = epoch_loss / max(1, num_batches)
        if avg_loss < best_loss:
            best_loss = avg_loss

        if epoch % 5 == 0 or epoch == epochs or epoch == 1:
            print(f"    Epoch {epoch:2d}/{epochs:2d} | Avg Reconstruction MSE: {avg_loss:.6f}")

    training_duration = (datetime.now() - start_time).total_seconds()
    print(f"[+] Training completed in {training_duration:.2f} seconds. Best Loss: {best_loss:.6f}")

    # 6. Validation Anomaly Threshold (tau) Calibration
    print("\n[*] Evaluating Validation Set to Calibrate 99th Percentile Threshold (tau)...")
    model.eval()
    val_errors = []

    with torch.no_grad():
        x_val = torch.tensor(val_windows, dtype=torch.float32, device=device)
        # Evaluate in batches to preserve memory
        val_loader = torch.utils.data.DataLoader(torch.utils.data.TensorDataset(x_val), batch_size=128)
        for (bx,) in val_loader:
            recon = model(bx)
            # MSE per window across sequence length and features
            mse = torch.mean((bx - recon) ** 2, dim=(1, 2)).cpu().numpy()
            val_errors.extend(mse)

    val_errors = np.array(val_errors)
    mean_val_error = float(np.mean(val_errors))
    std_val_error = float(np.std(val_errors))
    # Threshold tau at 99th percentile of validation reconstruction error
    tau = float(np.percentile(val_errors, 99.0))

    print(f"[+] Validation Reconstruction Error:")
    print(f"    - Mean Error  : {mean_val_error:.6f}")
    print(f"    - Std Dev     : {std_val_error:.6f}")
    print(f"    - Threshold tau (99th percentile): {tau:.6f}")

    # 7. Evaluate on Held-Out Benign Test Set
    print("\n[*] Evaluating Held-Out Benign Test Sessions...")
    test_errors = []
    with torch.no_grad():
        x_test = torch.tensor(test_windows, dtype=torch.float32, device=device)
        test_loader = torch.utils.data.DataLoader(torch.utils.data.TensorDataset(x_test), batch_size=128)
        for (bx,) in test_loader:
            recon = model(bx)
            mse = torch.mean((bx - recon) ** 2, dim=(1, 2)).cpu().numpy()
            test_errors.extend(mse)

    test_errors = np.array(test_errors)
    benign_fpr = float(np.mean(test_errors > tau))
    print(f"    - Test Benign Windows: {len(test_windows):,}")
    print(f"    - Mean Test Error    : {float(np.mean(test_errors)):.6f}")
    print(f"    - False Positive Rate: {benign_fpr * 100:.2f}% (Target: < 1.0%)")

    # 8. Evaluate on Attack Scenarios (Scenario A, B, C)
    print("\n[*] Evaluating Attack Scenarios Against Calibrated Threshold...")
    attack_results = {}
    attack_events_list = [
        # Scenario A: USB Staging -> Exec -> Log Cleared
        ("Scenario A (USB Attack)", [
            {"source": "usb", "action": "DEVICE_ARRIVED", "timestamp": "2026-11-25T10:00:00Z", "entity": "E:", "entity_type": "device", "details": {"drive_letter": "E:"}},
            {"source": "fs", "action": "FILE_CREATED", "timestamp": "2026-11-25T10:00:03Z", "entity": "E:\\backdoor.exe", "entity_type": "file", "details": {"file_extension": ".exe"}},
            {"source": "eventlog", "action": "PROCESS_STARTED", "timestamp": "2026-11-25T10:00:05Z", "entity": "E:\\backdoor.exe", "entity_type": "process", "details": {"event_id": 4688}},
            {"source": "eventlog", "action": "LOG_CLEARED", "timestamp": "2026-11-25T10:00:10Z", "entity": "LogCleared:Security", "entity_type": "system", "details": {"event_id": 1102}},
            {"source": "heartbeat", "action": "HEARTBEAT", "timestamp": "2026-11-25T10:00:20Z", "entity": "agent", "details": {}},
            {"source": "fs", "action": "FILE_MODIFIED", "timestamp": "2026-11-25T10:00:22Z", "entity": "C:\\temp\\log.txt", "details": {}},
            {"source": "eventlog", "action": "PROCESS_STARTED", "timestamp": "2026-11-25T10:00:25Z", "entity": "C:\\cmd.exe", "details": {"event_id": 4688}},
            {"source": "fs", "action": "FILE_DELETED", "timestamp": "2026-11-25T10:00:28Z", "entity": "E:\\backdoor.exe", "details": {}},
            {"source": "usb", "action": "DEVICE_REMOVED", "timestamp": "2026-11-25T10:00:30Z", "entity": "E:", "details": {}},
            {"source": "heartbeat", "action": "HEARTBEAT", "timestamp": "2026-11-25T10:00:40Z", "entity": "agent", "details": {}},
        ]),
        # Scenario B: Bulk Copy to Removable Storage
        ("Scenario B (Bulk Exfil)", [
            {"source": "usb", "action": "DEVICE_ARRIVED", "timestamp": "2026-11-25T11:00:00Z", "entity": "E:", "entity_type": "device", "details": {"drive_letter": "E:"}},
            {"source": "fs", "action": "FILE_CREATED", "timestamp": "2026-11-25T11:00:02Z", "entity": "E:\\sens_doc1.pdf", "entity_type": "file", "details": {"size_bytes": 1048576}},
            {"source": "fs", "action": "FILE_CREATED", "timestamp": "2026-11-25T11:00:04Z", "entity": "E:\\sens_doc2.pdf", "entity_type": "file", "details": {"size_bytes": 2048576}},
            {"source": "fs", "action": "FILE_CREATED", "timestamp": "2026-11-25T11:00:06Z", "entity": "E:\\sens_doc3.pdf", "entity_type": "file", "details": {"size_bytes": 3048576}},
            {"source": "fs", "action": "FILE_CREATED", "timestamp": "2026-11-25T11:00:08Z", "entity": "E:\\sens_doc4.pdf", "entity_type": "file", "details": {"size_bytes": 4048576}},
            {"source": "fs", "action": "FILE_CREATED", "timestamp": "2026-11-25T11:00:10Z", "entity": "E:\\sens_doc5.pdf", "entity_type": "file", "details": {"size_bytes": 5048576}},
            {"source": "eventlog", "action": "PROCESS_STARTED", "timestamp": "2026-11-25T11:00:12Z", "entity": "C:\\Windows\\System32\\robocopy.exe", "details": {"event_id": 4688}},
            {"source": "usb", "action": "DEVICE_REMOVED", "timestamp": "2026-11-25T11:00:15Z", "entity": "E:", "details": {}},
            {"source": "heartbeat", "action": "HEARTBEAT", "timestamp": "2026-11-25T11:00:20Z", "entity": "agent", "details": {}},
            {"source": "heartbeat", "action": "HEARTBEAT", "timestamp": "2026-11-25T11:00:30Z", "entity": "agent", "details": {}},
        ])
    ]

    for name, evs in attack_events_list:
        w, _ = create_sliding_windows(evs, window_size=10, step=1)
        if len(w) > 0:
            with torch.no_grad():
                bx = torch.tensor(w, dtype=torch.float32, device=device)
                rec = model(bx)
                err = float(torch.mean((bx - rec) ** 2).item())
                flagged = err > tau
                attack_results[name] = {"reconstruction_error": err, "flagged_anomalous": flagged}
                print(f"    - {name:<26}: Error = {err:.6f} | Anomaly Flagged = {flagged} (Threshold: {tau:.6f})")

    # 9. Save Model Artifacts
    model_save_path = MODELS_DIR / "lstm_autoencoder.pt"
    torch.save(model.state_dict(), model_save_path)
    print(f"\n[+] Saved PyTorch Model Weights to: {model_save_path}")

    threshold_metadata = {
        "model_version": "v2.0-live-trained",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "trained_on": "real_laptop_endpoint_telemetry",
        "training_events_total": train_events_count,
        "training_windows_total": len(train_windows),
        "validation_events_total": val_events_count,
        "validation_windows_total": len(val_windows),
        "test_events_total": test_events_count,
        "test_windows_total": len(test_windows),
        "feature_dim": get_feature_vector_size(),
        "window_size": window_size,
        "hidden_dim": hidden_dim,
        "reconstruction_loss_mean": mean_val_error,
        "reconstruction_loss_std": std_val_error,
        "anomaly_threshold_tau": tau,
        "threshold_percentile": 99.0,
        "normalization_formula": "S_ml = min(1.0, 0.5 * (error / tau)) if error <= tau else min(1.0, 0.5 + 0.5 * ((error - tau) / tau))",
        "test_benign_fpr": benign_fpr,
        "attack_detection": attack_results
    }

    threshold_save_path = MODELS_DIR / "threshold.json"
    with open(threshold_save_path, "w", encoding="utf-8") as f:
        json.dump(threshold_metadata, f, indent=2)
    print(f"[+] Saved Anomaly Threshold Metadata to: {threshold_save_path}")

    # 10. Also export train/val/test events to data/ml/ for auditability
    flat_train = [ev for s in train_sessions for ev in s]
    flat_val = [ev for s in val_sessions for ev in s]
    flat_test = [ev for s in test_sessions for ev in s]

    with open(DATA_DIR / "train_events.json", "w", encoding="utf-8") as f:
        json.dump(flat_train, f, indent=2)
    with open(DATA_DIR / "val_events.json", "w", encoding="utf-8") as f:
        json.dump(flat_val, f, indent=2)
    with open(DATA_DIR / "test_events.json", "w", encoding="utf-8") as f:
        json.dump(flat_test, f, indent=2)

    print(f"[+] Exported live session datasets to: {DATA_DIR}")

    print("\n" + "=" * 80)
    print(" LIVE MODEL TRAINING & CALIBRATION COMPLETE SUCCESSFULLY")
    print("=" * 80)
    return threshold_metadata


if __name__ == "__main__":
    train_on_collected_data()

"""
ForensiTrace - LSTM Autoencoder Model Training Script (AKASH, PURVA)
Trains the sequence anomaly detector on normal workstation baseline telemetry,
determines the reconstruction threshold from validation data, and saves model artifacts.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import numpy as np
import torch
import torch.nn as nn
import torch.optim as optim

from engine.ml.features import (
    create_sliding_windows,
    get_feature_vector_size,
    SCHEMA_ACTIONS
)
from engine.ml.model import LSTMAutoencoder, get_default_device
from engine.ml.dataset import export_ml_datasets

logger = logging.getLogger("ForensiTrace.ML.Train")

MODELS_DIR = Path(__file__).resolve().parent / "saved_models"
DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "ml"


def load_dataset_windows(json_path: Path, window_size: int = 10) -> np.ndarray:
    """Loads events from JSON and constructs sliding feature windows."""
    if not json_path.exists():
        logger.warning("Dataset file %s does not exist. Generating fresh datasets...", json_path)
        export_ml_datasets(DATA_DIR)

    with open(json_path, "r", encoding="utf-8") as f:
        events = json.load(f)

    windows, _ = create_sliding_windows(events, window_size=window_size, step=1)
    return windows


def train_lstm_autoencoder(
    epochs: int = 80,
    batch_size: int = 8,
    lr: float = 0.005,
    window_size: int = 10,
    hidden_dim: int = 32,
    device: Optional[torch.device] = None,
    save_dir: Optional[Path] = None
) -> Tuple[LSTMAutoencoder, float, Dict[str, Any]]:
    """
    Executes the training pipeline:
      1. Loads train and val events.
      2. Initializes dynamic LSTM autoencoder.
      3. Trains model to minimize reconstruction MSE on normal sequences.
      4. Evaluates validation set to calculate the 99th percentile anomaly threshold tau.
      5. Persists model weights and threshold metadata.
    """
    out_dir = save_dir or MODELS_DIR
    out_dir.mkdir(parents=True, exist_ok=True)
    dev = device or get_default_device()

    print("=" * 80)
    print(" FORENSITRACE - LSTM AUTOENCODER TRAINING PIPELINE")
    print("=" * 80)
    print(f"[*] Target Device: {dev}")
    print(f"[*] Dynamic Feature Dimension: {get_feature_vector_size()} ({len(SCHEMA_ACTIONS)} actions + 3 context)")
    print(f"[*] Sequence Window Size: {window_size} events")

    # 1. Load data
    train_path = DATA_DIR / "train_events.json"
    val_path = DATA_DIR / "val_events.json"
    if not train_path.exists() or not val_path.exists():
        export_ml_datasets(DATA_DIR)

    train_windows = load_dataset_windows(train_path, window_size=window_size)
    val_windows = load_dataset_windows(val_path, window_size=window_size)

    print(f"[+] Loaded {len(train_windows)} training windows and {len(val_windows)} validation windows.")

    if len(train_windows) == 0:
        raise ValueError("Training window set is empty. Check baseline events dataset.")

    # 2. Model, Optimizer, Loss
    model = LSTMAutoencoder(
        input_dim=get_feature_vector_size(),
        hidden_dim=hidden_dim,
        num_layers=1
    ).to(dev)

    criterion = nn.MSELoss()
    optimizer = optim.Adam(model.parameters(), lr=lr, weight_decay=1e-5)

    # Convert to PyTorch Tensor
    x_train = torch.tensor(train_windows, dtype=torch.float32, device=dev)

    # 3. Training Loop
    model.train()
    num_samples = len(x_train)
    for epoch in range(1, epochs + 1):
        permutation = torch.randperm(num_samples)
        epoch_loss = 0.0
        batches = 0

        for i in range(0, num_samples, batch_size):
            indices = permutation[i : i + batch_size]
            batch_x = x_train[indices]

            optimizer.zero_grad()
            reconstructed = model(batch_x)
            loss = criterion(reconstructed, batch_x)
            loss.backward()
            optimizer.step()

            epoch_loss += loss.item()
            batches += 1

        avg_loss = epoch_loss / max(1, batches)
        if epoch % 10 == 0 or epoch == epochs:
            print(f"    Epoch [{epoch:03d}/{epochs:03d}] - Reconstruction MSE: {avg_loss:.6f}")

    # 4. Threshold Calculation on Validation Set
    model.eval()
    with torch.no_grad():
        x_val = torch.tensor(val_windows, dtype=torch.float32, device=dev)
        val_errors = model.compute_reconstruction_error(x_val).cpu().numpy()

    # Per docs/ml.md: Choose threshold from validation data on normal activity (99th percentile)
    if len(val_errors) > 0:
        # Use 99th percentile of validation error; ensure non-zero minimum floor
        threshold_val = float(np.percentile(val_errors, 99))
        if threshold_val < 0.005:
            threshold_val = max(float(np.max(val_errors) * 1.1), 0.01)
    else:
        threshold_val = 0.05

    print(f"\n[+] Validation Set Evaluation Complete:")
    print(f"    Validation Samples: {len(val_errors)}")
    print(f"    Mean Validation MSE: {float(np.mean(val_errors)):.6f}")
    print(f"    Max Validation MSE:  {float(np.max(val_errors)):.6f}")
    print(f"    Calculated 99th Percentile Anomaly Threshold (tau): {threshold_val:.6f}")

    # 5. Save Artifacts
    model_path = out_dir / "lstm_autoencoder.pt"
    threshold_path = out_dir / "threshold.json"

    torch.save(model.state_dict(), model_path)

    metadata = {
        "model_version": "v1.0-hybrid",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "input_dim": get_feature_vector_size(),
        "hidden_dim": hidden_dim,
        "window_size": window_size,
        "threshold": threshold_val,
        "val_mean_mse": float(np.mean(val_errors)),
        "val_max_mse": float(np.max(val_errors)),
        "canonical_actions": SCHEMA_ACTIONS
    }

    with open(threshold_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(f"[+] Saved model weights to: {model_path}")
    print(f"[+] Saved threshold metadata to: {threshold_path}")
    print("=" * 80)

    return model, threshold_val, metadata


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train_lstm_autoencoder(epochs=60)

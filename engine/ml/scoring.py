"""
ForensiTrace - ML Scoring and Hybrid Risk Service (AKASH, PURVA)
Evaluates sliding sequence windows using the trained LSTM autoencoder,
normalizes reconstruction errors against the validation threshold,
calculates the combined risk index, assigns threat levels, and generates explainable narratives.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import torch

from engine.ml.features import (
    create_sliding_windows,
    get_feature_vector_size,
    extract_event_features,
    SCHEMA_ACTIONS
)
from engine.ml.model import LSTMAutoencoder, get_default_device

logger = logging.getLogger("ForensiTrace.ML.Scoring")

MODELS_DIR = Path(__file__).resolve().parent / "saved_models"


class ScoringService:
    """
    Inference and scoring service implementing docs/ml.md contract.
    Annotates activities with ml_anomaly_score and threat_level while preserving rule confidence.
    """

    def __init__(
        self,
        model_path: Optional[Union[str, Path]] = None,
        threshold_path: Optional[Union[str, Path]] = None
    ):
        self.device = get_default_device()
        self.model_file = Path(model_path or (MODELS_DIR / "lstm_autoencoder.pt")).resolve()
        self.threshold_file = Path(threshold_path or (MODELS_DIR / "threshold.json")).resolve()

        self.model: Optional[LSTMAutoencoder] = None
        self.threshold: float = 0.05
        self.window_size: int = 10
        self.model_version: str = "v1.0-hybrid"
        self._is_ready: bool = False

        self._load_artifacts()

    def _load_artifacts(self) -> None:
        """Loads trained weights and threshold metadata with resilient fallback."""
        if not self.model_file.exists() or not self.threshold_file.exists():
            logger.warning("ML model or threshold artifact not found at %s. Running in rules-only fallback mode.", MODELS_DIR)
            return

        try:
            with open(self.threshold_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
                self.threshold = float(meta.get("threshold", 0.05))
                self.window_size = int(meta.get("window_size", 10))
                self.model_version = str(meta.get("model_version", "v1.0-hybrid"))

            dim = get_feature_vector_size()
            self.model = LSTMAutoencoder(input_dim=dim, hidden_dim=32, num_layers=1).to(self.device)
            state_dict = torch.load(self.model_file, map_location=self.device)
            self.model.load_state_dict(state_dict)
            self.model.eval()
            self._is_ready = True
            logger.info("Loaded LSTM autoencoder (%s) successfully. Anomaly threshold tau=%.6f",
                        self.model_version, self.threshold)
        except Exception as e:
            logger.error("Failed to load LSTM model artifacts: %s. Defaulting to rules-only fallback.", e)
            self._is_ready = False

    @property
    def is_ready(self) -> bool:
        return self._is_ready

    def normalize_error(self, raw_error: float) -> float:
        """
        Normalizes raw reconstruction error into [0.0, 1.0] interval per docs/ml.md:
          - error == 0.0 -> score = 0.0
          - error == tau -> score = 0.50
          - error >= 2 * tau -> score = 1.00
        """
        tau = max(self.threshold, 1e-6)
        if raw_error < tau:
            score = 0.5 * (raw_error / tau)
        else:
            excess = raw_error - tau
            score = 0.5 + 0.5 * min(1.0, excess / tau)
        return float(np.clip(score, 0.0, 1.0))

    def score_windows(self, windows_np: np.ndarray) -> np.ndarray:
        """Computes normalized anomaly score for each window in batch."""
        if not self._is_ready or windows_np.size == 0 or self.model is None:
            return np.zeros((len(windows_np),), dtype=np.float32)

        raw_errors = self.model.predict_numpy_errors(windows_np, device=self.device)
        normalized_scores = np.array([self.normalize_error(err) for err in raw_errors], dtype=np.float32)
        return normalized_scores

    @staticmethod
    def calculate_threat_level(combined_index: float) -> str:
        """
        Categorizes combined risk index R into discrete threat levels:
          R >= 0.80         -> CRITICAL
          0.65 <= R < 0.80  -> HIGH
          0.45 <= R < 0.65  -> MEDIUM
          R < 0.45          -> LOW
        """
        if combined_index >= 0.80:
            return "CRITICAL"
        if combined_index >= 0.65:
            return "HIGH"
        if combined_index >= 0.45:
            return "MEDIUM"
        return "LOW"

    def score_activity(
        self,
        activity: Any,
        all_events: List[Any]
    ) -> Tuple[Optional[float], str, str]:
        """
        Evaluates sequence anomaly context for a correlated activity.
        
        Returns:
            (ml_anomaly_score, threat_level, narrative_assessment_line)
        """
        rule_confidence = float(getattr(activity, "confidence_score", 0.5))
        evidence_ids = set(getattr(activity, "evidence_event_ids", []))

        if not self._is_ready or not all_events:
            # Fallback when ML model is not available
            threat_level = self.calculate_threat_level(rule_confidence)
            narrative_line = (
                f"Threat Assessment: Evaluated under deterministic rule heuristics "
                f"(confidence {rule_confidence:.2f}), categorized as {threat_level} severity."
            )
            return None, threat_level, narrative_line

        # Generate sliding windows from the chronological event stream
        sorted_events = sorted(
            all_events,
            key=lambda e: getattr(e, "timestamp", getattr(e, "ts_utc", ""))
        )
        windows, window_events = create_sliding_windows(sorted_events, window_size=self.window_size, step=1)

        if len(windows) == 0:
            threat_level = self.calculate_threat_level(rule_confidence)
            return None, threat_level, f"Threat Assessment: Categorized as {threat_level} severity based on rule confidence ({rule_confidence:.2f})."

        # Score all windows
        window_scores = self.score_windows(windows)

        # Identify windows overlapping with this activity's evidence events
        overlapping_scores = []
        for idx, sub_evs in enumerate(window_events):
            sub_ids = {
                getattr(e, "id", None) or (e.get("id") if isinstance(e, dict) else None)
                for e in sub_evs
            }
            sub_ids.discard(None)
            if not sub_ids.isdisjoint(evidence_ids):
                overlapping_scores.append(window_scores[idx])

        if overlapping_scores:
            activity_ml_score = float(max(overlapping_scores))
        else:
            # If no direct window overlap found, take mean window score as background context
            activity_ml_score = float(np.mean(window_scores))

        # Calculate Combined Risk Index (0.5 * rule_conf + 0.5 * ml_score)
        combined_index = round(0.5 * rule_confidence + 0.5 * activity_ml_score, 3)
        threat_level = self.calculate_threat_level(combined_index)

        # Generate explainable anomaly assessment line without percentage-of-risk wording
        rule_name = str(getattr(activity, "rule_name", "UNKNOWN"))
        if activity_ml_score >= 0.65:
            assessment_desc = f"atypical temporal clustering and sequence deviation for {rule_name}"
        elif activity_ml_score >= 0.50:
            assessment_desc = f"moderate deviation above the 99th percentile baseline threshold"
        else:
            assessment_desc = f"reconstruction patterns consistent with baseline workstation operations"

        narrative_line = (
            f"Anomaly Assessment: Sequence exhibited an ML anomaly score of {activity_ml_score:.2f} "
            f"(threshold 0.50), driven by {assessment_desc} within a {self.window_size}-event window. "
            f"Combined Risk Index: {combined_index:.2f} ({threat_level})."
        )

        return activity_ml_score, threat_level, narrative_line


# Global singleton instance
_scoring_service_instance: Optional[ScoringService] = None


def get_scoring_service() -> ScoringService:
    global _scoring_service_instance
    if _scoring_service_instance is None:
        _scoring_service_instance = ScoringService()
    return _scoring_service_instance

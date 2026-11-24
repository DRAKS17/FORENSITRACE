"""
Unit tests for PyTorch LSTM autoencoder and scoring service in engine/ml/model.py & scoring.py.
Verifies shapes, error computation, normalization, threshold mapping, and threat level assignment.
"""

from datetime import datetime, timezone, timedelta
import unittest
import numpy as np
import torch

from engine.ml.features import get_feature_vector_size
from engine.ml.model import LSTMAutoencoder
from engine.ml.scoring import ScoringService


class TestMLModelAndScoring(unittest.TestCase):

    def setUp(self):
        self.dim = get_feature_vector_size()
        self.model = LSTMAutoencoder(input_dim=self.dim, hidden_dim=16, num_layers=1)
        self.model.eval()

    def test_model_forward_pass_dimensions(self):
        """Verifies (B, T, D) input produces exact (B, T, D) reconstructed output."""
        batch_size = 4
        seq_len = 10
        x = torch.randn(batch_size, seq_len, self.dim)
        out = self.model(x)
        self.assertEqual(out.shape, (batch_size, seq_len, self.dim))

    def test_reconstruction_error_shape(self):
        """Verifies compute_reconstruction_error outputs 1D tensor of shape (B,)."""
        batch_size = 3
        seq_len = 10
        x = torch.randn(batch_size, seq_len, self.dim)
        errors = self.model.compute_reconstruction_error(x)
        self.assertEqual(errors.shape, (batch_size,))
        self.assertTrue((errors >= 0.0).all())

    def test_score_normalization_formula(self):
        """
        Verifies score normalization contract from docs/ml.md:
          - error = 0.0 -> score = 0.0
          - error = tau -> score = 0.50
          - error = 2 * tau -> score = 1.00
          - error > 2 * tau -> clamped to 1.00
        """
        service = ScoringService()
        service.threshold = 0.10  # Set known threshold for unit test

        # Exactly zero error
        self.assertAlmostEqual(service.normalize_error(0.0), 0.0, places=3)
        # Half of threshold -> 0.25
        self.assertAlmostEqual(service.normalize_error(0.05), 0.25, places=3)
        # At threshold -> exactly 0.50
        self.assertAlmostEqual(service.normalize_error(0.10), 0.50, places=3)
        # 1.5x threshold -> 0.75
        self.assertAlmostEqual(service.normalize_error(0.15), 0.75, places=3)
        # 2x threshold -> 1.00
        self.assertAlmostEqual(service.normalize_error(0.20), 1.00, places=3)
        # Above 2x threshold -> clamped at 1.00
        self.assertAlmostEqual(service.normalize_error(0.50), 1.00, places=3)

    def test_threat_level_assignment_fire_and_not_fire(self):
        """Tests categorical threat level assignment boundaries."""
        self.assertEqual(ScoringService.calculate_threat_level(0.85), "CRITICAL")
        self.assertEqual(ScoringService.calculate_threat_level(0.80), "CRITICAL")
        self.assertEqual(ScoringService.calculate_threat_level(0.75), "HIGH")
        self.assertEqual(ScoringService.calculate_threat_level(0.65), "HIGH")
        self.assertEqual(ScoringService.calculate_threat_level(0.55), "MEDIUM")
        self.assertEqual(ScoringService.calculate_threat_level(0.45), "MEDIUM")
        self.assertEqual(ScoringService.calculate_threat_level(0.35), "LOW")
        self.assertEqual(ScoringService.calculate_threat_level(0.10), "LOW")

    def test_scoring_service_loads_artifacts(self):
        """Verifies ScoringService successfully loads the trained model weights and threshold metadata."""
        service = ScoringService()
        self.assertTrue(service.is_ready, "ScoringService failed to load model and threshold.")
        self.assertGreater(service.threshold, 0.0)
        self.assertEqual(service.window_size, 10)


if __name__ == "__main__":
    unittest.main()

"""
ForensiTrace - PyTorch Sequence Anomaly Detection Model (AKASH)
Implements a lightweight LSTM Autoencoder for temporal sequence anomaly detection.
Supports CPU laptop execution by default with automatic GPU fallback.
"""

import logging
from typing import Optional, Tuple, Union
import numpy as np
import torch
import torch.nn as nn

from engine.ml.features import get_feature_vector_size

logger = logging.getLogger(__name__)


def get_default_device() -> torch.device:
    """Returns CUDA if available, otherwise CPU default."""
    if torch.cuda.is_available():
        logger.info("CUDA device available. Utilizing GPU acceleration.")
        return torch.device("cuda")
    return torch.device("cpu")


class LSTMAutoencoder(nn.Module):
    """
    Sequence-to-sequence LSTM autoencoder.
    Compresses an input sequence (B, T, D) into a latent bottleneck vector and reconstructs it.
    Reconstruction error (MSE) measures how unusual or anomalous the sequence is compared to baseline normal behavior.
    """

    def __init__(
        self,
        input_dim: Optional[int] = None,
        hidden_dim: int = 32,
        num_layers: int = 1,
        dropout: float = 0.0
    ):
        super().__init__()
        # Dynamic input size derived from schema actions + 3
        self.input_dim = input_dim or get_feature_vector_size()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers

        # Encoder: (Batch, Seq_Len, Input_Dim) -> (Batch, Seq_Len, Hidden_Dim)
        self.encoder = nn.LSTM(
            input_size=self.input_dim,
            hidden_size=self.hidden_dim,
            num_layers=self.num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0
        )

        # Decoder: (Batch, Seq_Len, Hidden_Dim) -> (Batch, Seq_Len, Hidden_Dim)
        self.decoder = nn.LSTM(
            input_size=self.hidden_dim,
            hidden_size=self.hidden_dim,
            num_layers=self.num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0
        )

        # Output projection back to input feature space: (Batch, Seq_Len, Input_Dim)
        self.output_linear = nn.Linear(self.hidden_dim, self.input_dim)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass through autoencoder.
        Args:
            x: Tensor of shape (Batch, Seq_Len, Input_Dim)
        Returns:
            reconstructed: Tensor of shape (Batch, Seq_Len, Input_Dim)
        """
        batch_size, seq_len, _ = x.shape

        # 1. Encode: Extract final hidden state as latent vector
        _, (h_n, c_n) = self.encoder(x)
        # h_n shape: (num_layers, batch_size, hidden_dim)
        latent = h_n[-1]  # shape: (batch_size, hidden_dim)

        # 2. Decode: Repeat latent representation across seq_len
        decoder_input = latent.unsqueeze(1).repeat(1, seq_len, 1)  # (batch_size, seq_len, hidden_dim)
        decoder_out, _ = self.decoder(decoder_input)

        # 3. Project to original feature dimension
        reconstructed = self.output_linear(decoder_out)
        return reconstructed

    def compute_reconstruction_error(self, x: torch.Tensor) -> torch.Tensor:
        """
        Calculates the mean squared error per sequence in the batch.
        Args:
            x: Tensor of shape (Batch, Seq_Len, Input_Dim)
        Returns:
            errors: 1D Tensor of shape (Batch,) containing MSE per window.
        """
        self.eval()
        with torch.no_grad():
            reconstructed = self.forward(x)
            # Element-wise squared difference
            diff = (x - reconstructed) ** 2
            # Mean across time steps and features: (Batch,)
            errors = diff.mean(dim=(1, 2))
        return errors

    def predict_numpy_errors(self, windows_np: np.ndarray, device: Optional[torch.device] = None) -> np.ndarray:
        """
        Convenience inference function taking numpy array of shape (B, T, D) and returning numpy 1D array of errors.
        """
        if windows_np.size == 0:
            return np.array([], dtype=np.float32)

        dev = device or next(self.parameters()).device
        x_tensor = torch.tensor(windows_np, dtype=torch.float32, device=dev)
        errors_tensor = self.compute_reconstruction_error(x_tensor)
        return errors_tensor.cpu().numpy()

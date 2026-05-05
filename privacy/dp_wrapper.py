import numpy as np
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.config import NOISE_MULT, MAX_GRAD_NORM


class DifferentialPrivacyWrapper:
    """
    Adds calibrated Gaussian noise to model updates before
    they leave the client. This is the mathematical privacy
    guarantee — even if the server is compromised, it cannot
    reconstruct the original operational data from the updates.

    Mechanism: Gaussian mechanism with L2 sensitivity clipping.
    Privacy guarantee: (epsilon, delta)-differential privacy.
    """

    def __init__(
        self,
        noise_multiplier: float = NOISE_MULT,
        max_grad_norm: float = MAX_GRAD_NORM
    ):
        self.noise_multiplier = noise_multiplier
        self.max_grad_norm = max_grad_norm
        print(f"[DP] Wrapper initialized | "
              f"noise_multiplier={noise_multiplier} | "
              f"max_grad_norm={max_grad_norm}")

    def clip(self, update: np.ndarray) -> np.ndarray:
        """
        Clip update to max L2 norm.
        This bounds the sensitivity of the mechanism.
        Without clipping, a single outlier data point
        could dominate the update and leak information.
        """
        norm = np.linalg.norm(update)
        if norm > self.max_grad_norm:
            update = update * (self.max_grad_norm / norm)
        return update

    def add_noise(self, update: np.ndarray) -> np.ndarray:
        """
        Add Gaussian noise scaled to sensitivity.
        Noise std = noise_multiplier * max_grad_norm.
        Higher noise_multiplier = stronger privacy, lower utility.
        epsilon = 0.5 is strong privacy. epsilon = 10 is weak.
        """
        noise_std = self.noise_multiplier * self.max_grad_norm
        noise = np.random.normal(0, noise_std, update.shape)
        return update + noise

    def privatize(self, parameters: list) -> list:
        """
        Apply clip + noise to each parameter array.
        Called on the client side before sending to server.
        """
        privatized = []
        for param in parameters:
            clipped = self.clip(param.astype(np.float64))
            noisy   = self.add_noise(clipped)
            privatized.append(noisy)

        print(f"[DP] Privatized {len(parameters)} parameter arrays")
        return privatized
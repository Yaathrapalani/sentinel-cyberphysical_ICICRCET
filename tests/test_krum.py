import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import numpy as np
from aggregation.krum import multi_krum


def test_krum_rejects_malicious():
    """
    Three clients. Two honest, one malicious.
    Honest clients send similar small values.
    Malicious client sends extreme values (999).
    Krum should select only the honest clients.
    """
    honest_a = [np.array([-0.15]), np.array([-0.12]),
                np.array([-0.15]), np.array([-0.12])]

    honest_b = [np.array([-0.14]), np.array([-0.13]),
                np.array([-0.14]), np.array([-0.13])]

    malicious = [np.array([999.0]), np.array([999.0]),
                 np.array([999.0]), np.array([999.0])]

    all_updates = [honest_a, honest_b, malicious]

    selected, scores, selected_idx = multi_krum(
        all_updates=all_updates,
        num_to_select=2,
        num_byzantine=1
    )

    print(f"\nKrum scores: {scores}")
    print(f"Selected indices: {selected_idx}")

    malicious_idx = 2
    assert malicious_idx not in selected_idx, (
        f"FAIL: Krum selected malicious client {malicious_idx}. "
        f"Selected: {selected_idx}"
    )
    print("PASS: Krum correctly rejected the malicious client.")


def test_dp_adds_noise():
    """Verify differential privacy adds noise to parameters."""
    from privacy.dp_wrapper import DifferentialPrivacyWrapper

    dp = DifferentialPrivacyWrapper(noise_multiplier=1.1, max_grad_norm=1.0)
    original = [np.array([-0.15]), np.array([-0.12])]
    privatized = dp.privatize(original)

    for orig, priv in zip(original, privatized):
        assert not np.array_equal(orig, priv), "FAIL: DP added no noise."
        print(f"Original: {orig[0]:.6f} | Privatized: {priv[0]:.6f} | "
              f"Noise: {abs(priv[0] - orig[0]):.6f}")

    print("PASS: Differential privacy correctly adds noise.")


if __name__ == "__main__":
    print("=" * 50)
    print("SENTINEL Phase 4 Tests")
    print("=" * 50)
    test_krum_rejects_malicious()
    print()
    test_dp_adds_noise()
    print()
    print("All Phase 4 tests passed.")
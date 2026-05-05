"""
Run this script to train all three node models locally.
This is Phase 2 verification: confirms data loads and models train correctly
before touching any federated code.

Usage:
    python models/train_local.py
"""
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import numpy as np
from utils.preprocessing import run_preprocessing
from models.isolation_forest import SentinelAnomalyDetector


def train_all_nodes():
    print("=" * 60)
    print("SENTINEL — Phase 2: Local Model Training")
    print("=" * 60)

    # Step 1: Load and preprocess data
    processed, phys_cols, cyber_cols = run_preprocessing()

    detectors = {}

    for node_id, features in processed.items():
        print(f"\n--- Training {node_id} ---")

        detector = SentinelAnomalyDetector(
            node_id=node_id,
            contamination=0.05
        )

        # Train on local data only
        detector.fit(
            X_physical=features['X_physical'],
            X_cyber=features['X_cyber']
        )

        # Score local data to verify output shape
        scores = detector.score(
            X_physical=features['X_physical'],
            X_cyber=features['X_cyber']
        )

        print(f"[{node_id}] Score output shapes:")
        print(f"  physical_scores : {scores['physical_scores'].shape}")
        print(f"  cyber_scores    : {scores['cyber_scores'].shape}")
        print(f"  Score range     : "
              f"physical=[{scores['physical_scores'].min():.3f}, "
              f"{scores['physical_scores'].max():.3f}] | "
              f"cyber=[{scores['cyber_scores'].min():.3f}, "
              f"{scores['cyber_scores'].max():.3f}]")

        # Extract weights (verify federated interface works)
        weights = detector.get_weights()
        print(f"[{node_id}] Weights extracted | "
              f"phys_threshold={weights['phys_threshold']:.4f} | "
              f"cyber_threshold={weights['cyber_threshold']:.4f}")

        # Save model
        detector.save()
        detectors[node_id] = detector

    print("\n" + "=" * 60)
    print("Phase 2 Complete. All models trained and saved.")
    print("Expected output: 3 .pkl files in models/saved/")
    print("=" * 60)
    return detectors, processed


def verify_attack_labels(processed):
    """
    Check if ATT_FLAG column is available for evaluation.
    BATADAL training dataset 2 has ground truth labels.
    Dataset 1 (normal operations) may not — that's fine for training.
    """
    print("\n--- Checking for ground truth labels ---")
    for node_id, features in processed.items():
        # ATT_FLAG won't be in features dict since we only kept sensor cols
        # This is just a reminder to check the raw CSV
        print(f"[{node_id}] To evaluate with ground truth, use "
              f"BATADAL_dataset_for_evaluation.csv which includes ATT_FLAG column.")


if __name__ == "__main__":
    detectors, processed = train_all_nodes()
    verify_attack_labels(processed)
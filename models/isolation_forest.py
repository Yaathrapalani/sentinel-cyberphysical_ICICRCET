import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from utils.config import MODEL_SAVED


class SentinelAnomalyDetector:
    """
    Wraps IsolationForest for SENTINEL.
    Each infrastructure node gets one instance of this class.
    Produces separate anomaly scores for physical and cyber signals.
    """

    def __init__(self, node_id: str, contamination: float = 0.05, random_state: int = 42):
        """
        node_id: identifier string e.g. 'node_a'
        contamination: expected fraction of anomalies in training data
                       BATADAL training set 1 is mostly normal, so 0.05 is safe
        """
        self.node_id = node_id
        self.contamination = contamination
        self.random_state = random_state

        # Separate models for physical and cyber domains
        # This is what enables the correlation engine to compare them independently
        self.model_physical = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1
        )
        self.model_cyber = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1
        )

        self.is_fitted = False
        print(f"[{self.node_id}] Detector initialized | contamination={contamination}")

    def fit(self, X_physical: np.ndarray, X_cyber: np.ndarray):
        """Train both models on node's local data."""
        print(f"[{self.node_id}] Fitting physical model on shape {X_physical.shape}")
        self.model_physical.fit(X_physical)
        self.model_physical.predict(X_physical)  # forces threshold_ to be computed

        print(f"[{self.node_id}] Fitting cyber model on shape {X_cyber.shape}")
        self.model_cyber.fit(X_cyber)
        self.model_cyber.predict(X_cyber)  # forces threshold_ to be computed

        self.is_fitted = True
        print(f"[{self.node_id}] Training complete.")

    def score(self, X_physical: np.ndarray, X_cyber: np.ndarray) -> dict:
        """
        Returns anomaly scores normalized to [0, 1].
        IsolationForest.score_samples() returns negative anomaly scores.
        We flip and normalize so that: 1.0 = highly anomalous, 0.0 = normal.
        """
        if not self.is_fitted:
            raise RuntimeError(f"[{self.node_id}] Model not fitted. Call fit() first.")

        raw_phys = self.model_physical.score_samples(X_physical)
        raw_cyber = self.model_cyber.score_samples(X_cyber)

        # Flip sign (more negative = more anomalous in sklearn)
        # Normalize to [0, 1] using min-max across the batch
        def normalize(scores):
            flipped = -scores
            min_s, max_s = flipped.min(), flipped.max()
            if max_s == min_s:
                return np.zeros_like(flipped)
            return (flipped - min_s) / (max_s - min_s)

        phys_scores = normalize(raw_phys)
        cyber_scores = normalize(raw_cyber)

        return {
            'physical_scores': phys_scores,
            'cyber_scores': cyber_scores,
            'combined_scores': (phys_scores + cyber_scores) / 2.0
        }

    def predict_labels(self, X_physical: np.ndarray, X_cyber: np.ndarray) -> np.ndarray:
        """
        Returns binary labels: 1 = anomaly, 0 = normal.
        Uses IsolationForest's built-in predict (-1 = anomaly, 1 = normal).
        """
        phys_labels = self.model_physical.predict(X_physical)
        cyber_labels = self.model_cyber.predict(X_cyber)

        # Convert sklearn convention (-1/1) to (1/0)
        phys_binary = (phys_labels == -1).astype(int)
        cyber_binary = (cyber_labels == -1).astype(int)

        # Flag as anomaly if either domain flags it
        return np.maximum(phys_binary, cyber_binary)

    def get_weights(self) -> dict:
        if not self.is_fitted:
            raise RuntimeError("Model not fitted.")

        # sklearn 1.4+ uses offset_ only, threshold_ computed from it
        phys_thresh  = float(self.model_physical.offset_)
        cyber_thresh = float(self.model_cyber.offset_)

        return {
            'phys_threshold':  phys_thresh,
            'cyber_threshold': cyber_thresh,
            'phys_offset':     phys_thresh,
            'cyber_offset':    cyber_thresh,
            'node_id':         self.node_id
        }

    def set_weights(self, weights: dict):
        if not self.is_fitted:
            raise RuntimeError("Fit local model before applying global weights.")

        self.model_physical.offset_ = weights['phys_offset']
        self.model_cyber.offset_    = weights['cyber_offset']

        print(f"[{self.node_id}] Applied global weights | "
            f"phys_offset={weights['phys_offset']:.4f} | "
            f"cyber_offset={weights['cyber_offset']:.4f}")
    
    def save(self):
        """Persist models to disk."""
        os.makedirs(MODEL_SAVED, exist_ok=True)
        path = os.path.join(MODEL_SAVED, f"{self.node_id}_detector.pkl")
        joblib.dump(self, path)
        print(f"[{self.node_id}] Model saved to {path}")

    @staticmethod
    def load(node_id: str):
        """Load persisted model."""
        path = os.path.join(MODEL_SAVED, f"{node_id}_detector.pkl")
        detector = joblib.load(path)
        print(f"[{node_id}] Model loaded from {path}")
        return detector

    def evaluate(self, X_physical, X_cyber, y_true):
        """
        Evaluate against ground truth labels.
        BATADAL provides ATT_FLAG column (1 = under attack, 0 = normal).
        """
        y_pred = self.predict_labels(X_physical, X_cyber)
        print(f"\n[{self.node_id}] Evaluation Report:")
        print(classification_report(y_true, y_pred,
                                    target_names=['Normal', 'Attack'],
                                    zero_division=0))
        return y_pred
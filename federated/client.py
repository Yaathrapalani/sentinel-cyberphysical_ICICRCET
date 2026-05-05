import flwr as fl
import numpy as np
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from models.isolation_forest import SentinelAnomalyDetector
from utils.preprocessing import run_preprocessing
from privacy.dp_wrapper import DifferentialPrivacyWrapper


class SentinelClient(fl.client.NumPyClient):

    def __init__(self, node_id: str, features: dict, malicious: bool = False):
        self.node_id   = node_id
        self.features  = features
        self.malicious = malicious
        self.dp        = DifferentialPrivacyWrapper()

        self.detector = SentinelAnomalyDetector(
            node_id=node_id,
            contamination=0.05
        )
        self.detector.fit(
            X_physical=features['X_physical'],
            X_cyber=features['X_cyber']
        )
        if malicious:
            print(f"[{self.node_id}] WARNING: running as MALICIOUS node")
        else:
            print(f"[{self.node_id}] Client ready.")

    def get_parameters(self, config):
        weights = self.detector.get_weights()
        params = [
            np.array([weights['phys_threshold']]),
            np.array([weights['cyber_threshold']]),
            np.array([weights['phys_offset']]),
            np.array([weights['cyber_offset']])
        ]

        if self.malicious:
            # Send garbage weights to simulate Byzantine attack
            poisoned = [np.array([999.0]), np.array([999.0]),
                        np.array([999.0]), np.array([999.0])]
            print(f"[{self.node_id}] Sending POISONED update")
            return self.dp.privatize(poisoned)

        # Normal client: apply DP before sending
        return self.dp.privatize(params)

    def set_parameters(self, parameters):
        self.detector.set_weights({
            'phys_threshold': float(parameters[0][0]),
            'cyber_threshold': float(parameters[1][0]),
            'phys_offset':    float(parameters[2][0]),
            'cyber_offset':   float(parameters[3][0])
        })

    def fit(self, parameters, config):
        self.set_parameters(parameters)
        self.detector.fit(
            X_physical=self.features['X_physical'],
            X_cyber=self.features['X_cyber']
        )
        updated_params = self.get_parameters(config={})
        num_samples = len(self.features['X_physical'])
        print(f"[{self.node_id}] fit() complete | samples={num_samples}")
        return updated_params, num_samples, {}

    def evaluate(self, parameters, config):
        self.set_parameters(parameters)
        scores = self.detector.score(
            X_physical=self.features['X_physical'],
            X_cyber=self.features['X_cyber']
        )
        mean_score  = float(np.mean(scores['combined_scores']))
        num_samples = len(self.features['X_physical'])
        print(f"[{self.node_id}] evaluate() | mean_score={mean_score:.4f}")
        return mean_score, num_samples, {"mean_score": mean_score}


def start_client(
    node_id: str,
    server_address: str = "127.0.0.1:8080",
    malicious: bool = False
):
    processed, _, _ = run_preprocessing()
    if node_id not in processed:
        raise ValueError(f"Unknown node_id: {node_id}")

    features = processed[node_id]
    client   = SentinelClient(
        node_id=node_id,
        features=features,
        malicious=malicious
    )
    fl.client.start_numpy_client(
        server_address=server_address,
        client=client
    )
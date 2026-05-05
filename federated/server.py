import flwr as fl
import numpy as np
from typing import List, Tuple, Optional, Dict, Union
from flwr.common import (
    Parameters, FitRes, EvaluateRes, Scalar,
    ndarrays_to_parameters, parameters_to_ndarrays
)
from flwr.server.client_proxy import ClientProxy
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from aggregation.krum import multi_krum
from utils.config import NUM_ROUNDS, MIN_CLIENTS


class SentinelStrategyWithKrum(fl.server.strategy.FedAvg):
    """
    SENTINEL federated strategy.
    Replaces FedAvg aggregation with Multi-Krum Byzantine defense.
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.round_scores = []

    def aggregate_fit(
        self,
        server_round: int,
        results: List[Tuple[ClientProxy, FitRes]],
        failures: List,
    ) -> Tuple[Optional[Parameters], Dict[str, Scalar]]:

        print(f"\n[Server] Round {server_round} | "
              f"Updates received: {len(results)} | "
              f"Failures: {len(failures)}")

        if not results:
            return None, {}

        # Extract parameter arrays from each client
        all_updates = []
        sample_counts = []
        for _, fit_res in results:
            params = parameters_to_ndarrays(fit_res.parameters)
            all_updates.append(params)
            sample_counts.append(fit_res.num_examples)

        # Apply Multi-Krum to filter Byzantine updates
        num_to_select = max(1, len(all_updates) - 1)
        selected_updates, scores, selected_idx = multi_krum(
            all_updates=all_updates,
            num_to_select=num_to_select,
            num_byzantine=1
        )

        self.round_scores.append({
            'round': server_round,
            'scores': scores,
            'selected': selected_idx
        })

        # Average the selected honest updates
        aggregated = []
        for param_idx in range(len(selected_updates[0])):
            stacked = np.array([u[param_idx] for u in selected_updates])
            aggregated.append(np.mean(stacked, axis=0))

        print(f"[Server] Krum selected {len(selected_idx)} of "
              f"{len(all_updates)} updates")
        print(f"[Server] Aggregation complete for round {server_round}")

        return ndarrays_to_parameters(aggregated), {}

    def aggregate_evaluate(
        self,
        server_round: int,
        results: List[Tuple[ClientProxy, EvaluateRes]],
        failures: List,
    ) -> Tuple[Optional[float], Dict[str, Scalar]]:

        if not results:
            return None, {}

        total   = sum(r.num_examples for _, r in results)
        w_loss  = sum(r.loss * r.num_examples for _, r in results) / total

        print(f"[Server] Round {server_round} eval | "
              f"weighted_mean_score={w_loss:.4f}")
        return w_loss, {"weighted_mean_score": w_loss}


def start_server(server_address: str = "0.0.0.0:8080"):
    strategy = SentinelStrategyWithKrum(
        min_fit_clients=MIN_CLIENTS,
        min_evaluate_clients=MIN_CLIENTS,
        min_available_clients=MIN_CLIENTS,
        fraction_fit=1.0,
        fraction_evaluate=1.0,
    )

    print(f"[Server] SENTINEL federated server starting | "
          f"address={server_address} | rounds={NUM_ROUNDS}")

    fl.server.start_server(
        server_address=server_address,
        config=fl.server.ServerConfig(num_rounds=NUM_ROUNDS),
        strategy=strategy,
    )


if __name__ == "__main__":
    start_server()
import numpy as np
from typing import List, Tuple
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.config import BYZANTINE_TOLERANCE


def flatten_parameters(parameters: list) -> np.ndarray:
    """Flatten list of arrays into a single vector for distance computation."""
    return np.concatenate([p.flatten() for p in parameters])


def krum_select(
    all_updates: List[List[np.ndarray]],
    num_byzantine: int = BYZANTINE_TOLERANCE
) -> Tuple[int, List[float]]:
    """
    Krum aggregation algorithm.

    How it works:
    - For each client update, compute its distance to every other update
    - Score each client as the sum of distances to its (n - f - 2) nearest neighbors
    - Select the client with the lowest score (most similar to the honest majority)
    - Byzantine clients send updates far from honest consensus — their score is high

    Parameters:
        all_updates: list of parameter lists, one per client
        num_byzantine: number of Byzantine clients to tolerate (f)

    Returns:
        selected_index: index of the selected honest update
        scores: distance scores for all clients (for logging)

    Mathematical guarantee:
        If f < (n - 2) / 2, Krum converges to the correct answer.
        With n=3 clients and f=1, this holds: 1 < (3-2)/2 = 0.5 is FALSE.
        So for the demo we use Multi-Krum which selects the best m updates.
    """
    n = len(all_updates)
    flat = [flatten_parameters(u) for u in all_updates]

    # Compute pairwise squared distances
    distances = np.zeros((n, n))
    for i in range(n):
        for j in range(n):
            if i != j:
                diff = flat[i] - flat[j]
                distances[i][j] = np.dot(diff, diff)

    # For each client, sum distances to nearest (n - f - 2) neighbors
    num_neighbors = max(1, n - num_byzantine - 2)
    if num_neighbors < 1:
        num_neighbors = 1

    scores = []
    for i in range(n):
        neighbor_distances = sorted(
            [distances[i][j] for j in range(n) if j != i]
        )
        score = sum(neighbor_distances[:num_neighbors])
        scores.append(score)

    selected_index = int(np.argmin(scores))
    return selected_index, scores


def multi_krum(
    all_updates: List[List[np.ndarray]],
    num_to_select: int = 2,
    num_byzantine: int = BYZANTINE_TOLERANCE
) -> List[List[np.ndarray]]:
    """
    Multi-Krum: selects the best m updates instead of just one.
    More practical for aggregation with small n.
    Returns list of selected parameter sets for averaging.
    """
    n = len(all_updates)
    flat = [flatten_parameters(u) for u in all_updates]

    distances = np.zeros((n, n))
    for i in range(n):
        for j in range(n):
            if i != j:
                diff = flat[i] - flat[j]
                distances[i][j] = np.dot(diff, diff)

    num_neighbors = max(1, n - num_byzantine - 2)
    if num_neighbors < 1:
        num_neighbors = 1

    scores = []
    for i in range(n):
        neighbor_distances = sorted(
            [distances[i][j] for j in range(n) if j != i]
        )
        score = sum(neighbor_distances[:num_neighbors])
        scores.append(score)

    # Select top m by lowest score
    selected_indices = sorted(
        range(n), key=lambda i: scores[i]
    )[:num_to_select]

    print(f"[Krum] Scores: {[f'{s:.4f}' for s in scores]}")
    print(f"[Krum] Selected indices: {selected_indices} | "
          f"Rejected: {[i for i in range(n) if i not in selected_indices]}")

    return [all_updates[i] for i in selected_indices], scores, selected_indices
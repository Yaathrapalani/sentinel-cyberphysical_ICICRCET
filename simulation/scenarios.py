"""simulation/scenarios.py — extended with 4 advanced attack types."""
import numpy as np
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.config import (ATTACK_START, ATTACK_DURATION, SPOOF_VALUE)


def generate_normal(n: int = 300) -> tuple:
    np.random.seed(42)
    base = np.random.normal(0.15, 0.05, n).clip(0, 1)
    cyber    = (base + np.random.normal(0, 0.03, n)).clip(0, 1)
    physical = (base + np.random.normal(0, 0.03, n)).clip(0, 1)
    return cyber, physical


def generate_cyber_only(n: int = 300) -> tuple:
    np.random.seed(42)
    cyber, physical = generate_normal(n)
    ae = ATTACK_START + ATTACK_DURATION
    cyber[ATTACK_START:ae]    = np.random.normal(0.75, 0.08, ATTACK_DURATION).clip(0, 1)
    physical[ATTACK_START:ae] = np.random.normal(0.65, 0.08, ATTACK_DURATION).clip(0, 1)
    return cyber, physical


def generate_compound_attack(n: int = 300) -> tuple:
    np.random.seed(42)
    cyber, physical = generate_normal(n)
    ae = ATTACK_START + ATTACK_DURATION
    cyber[ATTACK_START:ae]    = np.random.normal(0.82, 0.06, ATTACK_DURATION).clip(0, 1)
    physical[ATTACK_START:ae] = np.random.normal(SPOOF_VALUE, 0.02, ATTACK_DURATION).clip(0, 1)
    return cyber, physical


def generate_coordinated_attack(n: int = 300) -> tuple:
    """Simultaneous multi-node high-intensity attack."""
    np.random.seed(7)
    cyber, physical = generate_normal(n)
    # Two attack windows
    for start in [ATTACK_START, ATTACK_START + 60]:
        ae = min(start + ATTACK_DURATION, n)
        cyber[start:ae]    = np.random.normal(0.88, 0.04, ae - start).clip(0, 1)
        physical[start:ae] = np.random.normal(0.06, 0.02, ae - start).clip(0, 1)
    return cyber, physical


def generate_delayed_attack(n: int = 300) -> tuple:
    """Quiet reconnaissance phase then sudden spike."""
    np.random.seed(13)
    cyber, physical = generate_normal(n)
    recon_end = ATTACK_START + 20
    strike_end = min(recon_end + ATTACK_DURATION, n)
    # Recon phase: slight cyber elevation
    cyber[ATTACK_START:recon_end] = np.random.normal(0.38, 0.06, 20).clip(0, 1)
    # Strike phase
    cyber[recon_end:strike_end]    = np.random.normal(0.82, 0.05, strike_end - recon_end).clip(0, 1)
    physical[recon_end:strike_end] = np.random.normal(0.05, 0.02, strike_end - recon_end).clip(0, 1)
    return cyber, physical


def generate_stealth_attack(n: int = 300) -> tuple:
    """Slow-burn low-amplitude — designed to evade threshold IDS."""
    np.random.seed(19)
    cyber, physical = generate_normal(n)
    ae = min(ATTACK_START + ATTACK_DURATION * 2, n)
    # Stays just below IDS threshold (0.5) but still high enough to break correlation
    cyber[ATTACK_START:ae]    = np.random.normal(0.52, 0.04, ae - ATTACK_START).clip(0, 1)
    physical[ATTACK_START:ae] = np.random.normal(0.08, 0.02, ae - ATTACK_START).clip(0, 1)
    return cyber, physical


def generate_cascading_attack(n: int = 300) -> tuple:
    """Node-to-node propagation: starts low, grows exponentially."""
    np.random.seed(23)
    cyber, physical = generate_normal(n)
    for i, start in enumerate([ATTACK_START, ATTACK_START + 20, ATTACK_START + 35]):
        intensity = 0.60 + i * 0.10
        ae = min(start + ATTACK_DURATION // 2, n)
        cyber[start:ae]    = np.random.normal(intensity, 0.05, ae - start).clip(0, 1)
        physical[start:ae] = np.random.normal(0.06, 0.02, ae - start).clip(0, 1)
    return cyber, physical


def generate_all_scenarios(n: int = 300) -> dict:
    return {
        "normal":             generate_normal(n),
        "cyber_only":         generate_cyber_only(n),
        "compound_attack":    generate_compound_attack(n),
        "coordinated_attack": generate_coordinated_attack(n),
        "delayed_attack":     generate_delayed_attack(n),
        "stealth_attack":     generate_stealth_attack(n),
        "cascading_attack":   generate_cascading_attack(n),
    }
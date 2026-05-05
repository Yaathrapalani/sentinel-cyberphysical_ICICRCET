import numpy as np
import sys
import os
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from utils.config import ATTACK_START, ATTACK_DURATION, SPOOF_VALUE


class AttackInjector:
    """
    Injects attack scenarios into a live score stream.
    Used by the dashboard's attack injection button.
    Simulates real-time attack arrival during demo.
    """

    def __init__(self):
        self.active       = False
        self.attack_type  = None
        self.steps_left   = 0
        self.total_steps  = ATTACK_DURATION

    def trigger(self, attack_type: str = "compound"):
        """
        Activate an attack scenario.
        attack_type: 'compound' or 'cyber_only'
        """
        self.active      = True
        self.attack_type = attack_type
        self.steps_left  = self.total_steps
        print(f"[AttackInjector] Triggered: {attack_type} | "
              f"duration={self.total_steps} steps")

    def step(
        self,
        base_cyber: float,
        base_physical: float
    ) -> tuple:
        """
        Called once per dashboard refresh cycle.
        Returns (cyber_score, physical_score) for this timestep.
        If attack is active, modifies scores accordingly.
        """
        if not self.active:
            return base_cyber, base_physical

        self.steps_left -= 1
        if self.steps_left <= 0:
            self.active = False
            print("[AttackInjector] Attack scenario complete.")
            return base_cyber, base_physical

        if self.attack_type == "compound":
            # High cyber + spoofed low physical = compound signature
            cyber    = float(np.random.normal(0.82, 0.06))
            physical = float(np.random.normal(SPOOF_VALUE, 0.02))
            return np.clip(cyber, 0, 1), np.clip(physical, 0, 1)

        if self.attack_type == "cyber_only":
            # High cyber + high physical = visible single-domain attack
            cyber    = float(np.random.normal(0.75, 0.08))
            physical = float(np.random.normal(0.65, 0.08))
            return np.clip(cyber, 0, 1), np.clip(physical, 0, 1)

        return base_cyber, base_physical

    @property
    def is_active(self) -> bool:
        return self.active

    @property
    def remaining(self) -> int:
        return self.steps_left
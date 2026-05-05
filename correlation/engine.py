import numpy as np
from collections import deque
from typing import Tuple
import sys
import os
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), '..')))

from utils.config import (
    WINDOW_SIZE, NORMAL_THRESH, CRITICAL_THRESH
)

# Alert levels — used by dashboard and attack injector
ALERT_NORMAL   = "NORMAL"
ALERT_ELEVATED = "ELEVATED"
ALERT_CRITICAL = "CRITICAL"


class CyberPhysicalCorrelationEngine:
    """
    Core novelty of SENTINEL.

    Under normal infrastructure operation, digital network
    events and physical sensor responses are naturally coupled.
    When the control system sends a command, actuators respond
    and sensors reflect the change within seconds.

    During a compound attack:
      - Attacker manipulates network (cyber anomaly rises)
      - Attacker simultaneously spoofs sensors to hide the
        physical response (physical anomaly stays falsely low)
      - The natural coupling between cyber and physical breaks

    This engine measures that coupling using rolling Pearson
    correlation over a sliding time window. When correlation
    drops below the critical threshold, a compound attack
    signature is confirmed.

    Single-domain IDS sees:
      - Cyber: anomaly detected (moderate alert)
      - Physical: all normal (cancel alert)
      - Result: no confident detection

    SENTINEL sees:
      - Correlation: broken (these two should move together)
      - Result: CRITICAL compound attack confirmed
    """

    def __init__(
        self,
        window_size: int = WINDOW_SIZE,
        normal_thresh: float = NORMAL_THRESH,
        critical_thresh: float = CRITICAL_THRESH
    ):
        self.window_size     = window_size
        self.normal_thresh   = normal_thresh
        self.critical_thresh = critical_thresh

        # Rolling windows — store recent scores
        self.cyber_window    = deque(maxlen=window_size)
        self.physical_window = deque(maxlen=window_size)

        # Alert history for dashboard
        self.alert_log = []
        self.current_correlation = 1.0
        self.current_alert = ALERT_NORMAL

        print(f"[CorrelationEngine] Initialized | "
              f"window={window_size} | "
              f"normal_thresh={normal_thresh} | "
              f"critical_thresh={critical_thresh}")

    def update(
        self,
        cyber_score: float,
        physical_score: float,
        timestamp: str = None
    ) -> dict:
        """
        Ingest one timestep of anomaly scores.
        Returns current alert state and correlation value.

        Called every time new scores arrive from the local model.
        """
        self.cyber_window.append(float(cyber_score))
        self.physical_window.append(float(physical_score))

        result = {
            'cyber_score':    cyber_score,
            'physical_score': physical_score,
            'correlation':    None,
            'alert':          ALERT_NORMAL,
            'timestamp':      timestamp,
            'window_full':    False
        }

        # Need full window before correlation is meaningful
        if len(self.cyber_window) < self.window_size:
            result['alert'] = ALERT_NORMAL
            self.current_alert = ALERT_NORMAL
            return result

        result['window_full'] = True
        correlation = self._compute_correlation()
        result['correlation'] = correlation
        self.current_correlation = correlation

        # Determine alert level
        alert = self._classify_alert(
            correlation, cyber_score, physical_score
        )
        result['alert'] = alert
        self.current_alert = alert

        # Log significant alerts
        if alert != ALERT_NORMAL:
            entry = {
                'timestamp':      timestamp,
                'alert':          alert,
                'correlation':    round(correlation, 4),
                'cyber_score':    round(cyber_score, 4),
                'physical_score': round(physical_score, 4)
            }
            self.alert_log.append(entry)
            print(f"[CorrelationEngine] {alert} | "
                  f"corr={correlation:.4f} | "
                  f"cyber={cyber_score:.4f} | "
                  f"physical={physical_score:.4f}")

        return result

    def _compute_correlation(self) -> float:
        """
        Pearson correlation between cyber and physical
        score windows.

        Returns value in [-1, 1]:
          +1.0 = perfectly coupled (normal)
           0.0 = uncorrelated (suspicious)
          -1.0 = inversely coupled (strong attack signal)

        Edge case: if either window has zero variance
        (all values identical), correlation is undefined.
        We return 1.0 (assume normal) to avoid false alerts
        during system startup.
        """
        cyber    = np.array(self.cyber_window)
        physical = np.array(self.physical_window)

        cyber_std    = np.std(cyber)
        physical_std = np.std(physical)

        # Zero variance means all scores identical
        # This happens at startup before any variation
        if cyber_std < 1e-10 or physical_std < 1e-10:
            return 1.0

        correlation = np.corrcoef(cyber, physical)[0, 1]

        # corrcoef can return NaN in edge cases
        if np.isnan(correlation):
            return 1.0

        return float(correlation)

    def _classify_alert(
        self,
        correlation: float,
        cyber_score: float,
        physical_score: float
    ) -> str:
        """
        Alert classification logic.

        CRITICAL: correlation broken AND cyber anomaly is high
                  This is the compound attack signature.
                  High cyber activity but physical looks normal.

        ELEVATED: correlation degraded but not critical.
                  Could be sensor noise or early attack stage.

        NORMAL:   correlation healthy. System operating normally.

        The key insight: a low cyber score with low correlation
        is NOT an attack — it just means both domains are quiet.
        We need HIGH cyber activity with LOW correlation to
        confirm the physical spoofing pattern.
        """
        if (correlation < self.critical_thresh
                and cyber_score > 0.5):
            return ALERT_CRITICAL

        if correlation < self.normal_thresh:
            return ALERT_ELEVATED

        return ALERT_NORMAL

    def batch_score(
        self,
        cyber_scores: np.ndarray,
        physical_scores: np.ndarray,
        timestamps: list = None
    ) -> list:
        """
        Process a full array of scores at once.
        Used for offline evaluation on BATADAL dataset.
        Returns list of result dicts one per timestep.
        """
        results = []
        n = len(cyber_scores)

        for i in range(n):
            ts = timestamps[i] if timestamps else str(i)
            result = self.update(
                cyber_score=float(cyber_scores[i]),
                physical_score=float(physical_scores[i]),
                timestamp=ts
            )
            results.append(result)

        return results

    def get_summary(self) -> dict:
        """Summary statistics for dashboard display."""
        alerts = [r['alert'] for r in self.alert_log]
        return {
            'total_alerts':    len(self.alert_log),
            'critical_count':  alerts.count(ALERT_CRITICAL),
            'elevated_count':  alerts.count(ALERT_ELEVATED),
            'current_corr':    round(self.current_correlation, 4),
            'current_alert':   self.current_alert,
            'window_size':     self.window_size
        }

    def reset(self):
        """Clear windows and alert log. Used between scenarios."""
        self.cyber_window.clear()
        self.physical_window.clear()
        self.alert_log.clear()
        self.current_correlation = 1.0
        self.current_alert = ALERT_NORMAL
        print("[CorrelationEngine] Reset.")
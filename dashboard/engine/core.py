"""engine/core.py — SENTINEL computation core. Zero Streamlit imports."""
from __future__ import annotations
import numpy as np
from collections import deque
from dataclasses import dataclass, field
from typing import Literal, Optional

AlertLevel = Literal["NORMAL", "ELEVATED", "CRITICAL"]
WINDOW      = 20
NORM_THRESH = 0.70
CRIT_THRESH = 0.30


@dataclass
class Tick:
    t:           int
    cyber:       float
    physical:    float
    correlation: Optional[float]
    alert:       AlertLevel
    ids_flag:    bool


@dataclass
class InsightReport:
    label:       str
    description: str
    severity:    AlertLevel
    tick:        int
    corr_delta:  float = 0.0


class CorrelationEngine:
    def __init__(self):
        self.cyber_win:    deque[float] = deque(maxlen=WINDOW)
        self.phys_win:     deque[float] = deque(maxlen=WINDOW)
        self.current_corr: float        = 1.0
        self.current_alert: AlertLevel  = "NORMAL"
        self.alert_log:    list[dict]   = []

    def update(self, cyber: float, physical: float, t: int) -> Tick:
        self.cyber_win.append(cyber)
        self.phys_win.append(physical)
        corr  = self._pearson() if len(self.cyber_win) >= WINDOW else None
        alert = self._classify(corr, cyber) if corr is not None else "NORMAL"
        self.current_corr  = corr if corr is not None else self.current_corr
        self.current_alert = alert
        if alert != "NORMAL":
            self.alert_log.append(dict(
                t=t, alert=alert,
                corr=round(self.current_corr, 4),
                cyber=round(cyber, 4),
                physical=round(physical, 4)
            ))
        return Tick(t=t, cyber=cyber, physical=physical,
                    correlation=corr, alert=alert,
                    ids_flag=cyber > 0.50)

    def _pearson(self) -> float:
        c, p = np.array(self.cyber_win), np.array(self.phys_win)
        if c.std() < 1e-9 or p.std() < 1e-9:
            return 1.0
        v = float(np.corrcoef(c, p)[0, 1])
        return v if not np.isnan(v) else 1.0

    def _classify(self, corr: float, cyber: float) -> AlertLevel:
        if corr < CRIT_THRESH and cyber > 0.50:
            return "CRITICAL"
        if corr < NORM_THRESH:
            return "ELEVATED"
        return "NORMAL"

    def reset(self):
        self.cyber_win.clear()
        self.phys_win.clear()
        self.current_corr  = 1.0
        self.current_alert = "NORMAL"
        self.alert_log.clear()


class AttackInjector:
    def __init__(self):
        self._kind:    Optional[str] = None
        self._steps:   int           = 0
        self._elapsed: int           = 0

    def trigger(self, kind: str):
        self._kind    = kind
        self._steps   = 55
        self._elapsed = 0

    @property
    def active(self) -> bool:
        return self._kind is not None and self._elapsed < self._steps

    def step(self, bc: float, bp: float) -> tuple[float, float]:
        if not self.active:
            return bc, bp
        self._elapsed += 1
        if self._kind == "compound":
            c = float(np.clip(np.random.normal(0.82, 0.06), 0, 1))
            p = float(np.clip(np.random.normal(0.04, 0.02), 0, 1))
        else:
            c = float(np.clip(np.random.normal(0.75, 0.08), 0, 1))
            p = float(np.clip(np.random.normal(0.65, 0.08), 0, 1))
        return c, p


class InsightEngine:
    def __init__(self, history: list[Tick]):
        self.h = history

    def generate(self) -> list[InsightReport]:
        if len(self.h) < WINDOW + 5:
            return []
        out: list[InsightReport] = []
        out += self._corr_break()
        out += self._spoofing()
        out += self._sustained()
        return out

    def _corr_break(self) -> list[InsightReport]:
        corrs = [t.correlation for t in self.h if t.correlation is not None]
        if len(corrs) < 10:
            return []
        delta = float(np.mean(corrs[-5:])) - float(np.mean(corrs[-10:-5]))
        if delta < -0.28:
            return [InsightReport(
                label="Correlation Break Detected",
                description=(
                    f"Coupling index fell {abs(delta):.2f} pts over last "
                    f"10 ticks. Cyber and physical signals diverging — "
                    f"consistent with active sensor spoofing."
                ),
                severity="CRITICAL",
                tick=self.h[-1].t,
                corr_delta=round(delta, 3)
            )]
        return []

    def _spoofing(self) -> list[InsightReport]:
        recent = self.h[-20:]
        overlap = sum(1 for t in recent if t.cyber > 0.60 and t.physical < 0.20)
        if overlap >= 5:
            return [InsightReport(
                label="Physical Spoofing Pattern",
                description=(
                    f"{overlap} timesteps with high cyber activity "
                    f"coinciding with abnormally low physical readings. "
                    f"Replay-attack sensor concealment confirmed."
                ),
                severity="CRITICAL",
                tick=self.h[-1].t
            )]
        return []

    def _sustained(self) -> list[InsightReport]:
        crits = sum(1 for t in self.h[-30:] if t.alert == "CRITICAL")
        if crits >= 8:
            return [InsightReport(
                label="Sustained Attack Window",
                description=(
                    f"{crits} CRITICAL alerts in last 30 ticks. "
                    f"Attack is persistent — not a transient anomaly. "
                    f"Recommend manual intervention."
                ),
                severity="CRITICAL",
                tick=self.h[-1].t
            )]
        return []

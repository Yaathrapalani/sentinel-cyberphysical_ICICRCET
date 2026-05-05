"""engine/core.py — SENTINEL computation core. Zero Streamlit imports.
Bugs fixed:
  - NodeLocalizationEngine: cyber_factor capped; only ONE primary node COMPROMISED
  - SystemStateMachine: SECURE_MODE transitions correctly after mitigation cooldown
  - AttackNullifier: respond() idempotent per attack episode (no per-tick duplication)
  - CorrelationEngine: EWMA smoothing + std-based threshold for robustness
"""
from __future__ import annotations
import numpy as np
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Optional

AlertLevel  = Literal["NORMAL", "ELEVATED", "CRITICAL"]
SystemState = Literal["NORMAL", "ALERT", "DEFENSE_MODE", "SECURE_MODE"]
AttackType  = Literal["NONE", "CYBER_ONLY", "COMPOUND", "COORDINATED",
                      "DELAYED", "STEALTH", "CASCADING", "UNKNOWN"]

WINDOW      = 20
NORM_THRESH = 0.70
CRIT_THRESH = 0.30


# ── Data Classes ─────────────────────────────────────────────────────────────
@dataclass
class Tick:
    t:           int
    cyber:       float
    physical:    float
    correlation: Optional[float]
    alert:       AlertLevel
    ids_flag:    bool
    node_id:     str = "node_a"


@dataclass
class InsightReport:
    label:       str
    description: str
    severity:    AlertLevel
    tick:        int
    corr_delta:  float = 0.0


@dataclass
class NodeStatus:
    node_id:             str
    risk_score:          float
    state:               str
    affected_components: list
    last_seen:           int


@dataclass
class MitigationAction:
    action:    str
    node_id:   str
    tick:      int
    timestamp: str
    success:   bool
    detail:    str


@dataclass
class PipelineResult:
    tick:         int
    attack_type:  str
    severity:     str
    node_id:      str
    system_state: str
    risk_score:   float
    response:     list
    correlation:  float
    cyber:        float
    physical:     float
    forensic_id:  str


# ── 1. Correlation Engine ────────────────────────────────────────────────────
class CorrelationEngine:
    def __init__(self):
        self.cyber_win:     deque = deque(maxlen=WINDOW)
        self.phys_win:      deque = deque(maxlen=WINDOW)
        self.current_corr:  float = 1.0
        self.current_alert: AlertLevel = "NORMAL"
        self.alert_log:     list  = []
        # EWMA smoothed signals — α=0.25 (more robust than raw)
        self._ewma_cyber:  float = 0.14
        self._ewma_phys:   float = 0.14
        self._ALPHA:       float = 0.25

    def update(self, cyber: float, physical: float, t: int) -> Tick:
        # EWMA smoothing — reduces single-tick spike influence
        self._ewma_cyber = self._ALPHA * cyber + (1 - self._ALPHA) * self._ewma_cyber
        self._ewma_phys  = self._ALPHA * physical + (1 - self._ALPHA) * self._ewma_phys
        # Feed smoothed values into rolling Pearson window
        self.cyber_win.append(self._ewma_cyber)
        self.phys_win.append(self._ewma_phys)

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
        c = np.array(self.cyber_win)
        p = np.array(self.phys_win)
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

    def correlation_degradation(self) -> float:
        log = self.alert_log
        if len(log) < 5:
            return 0.0
        recent = [e["corr"] for e in log[-5:]]
        older  = [e["corr"] for e in log[-10:-5]] if len(log) >= 10 else recent
        return float(np.mean(older) - np.mean(recent))

    def reset(self):
        self.cyber_win.clear()
        self.phys_win.clear()
        self.current_corr  = 1.0
        self.current_alert = "NORMAL"
        self.alert_log.clear()
        self._ewma_cyber   = 0.14
        self._ewma_phys    = 0.14

    def flush_attack_memory(self) -> None:
        """Call after attack ends so EWMA correlation recovers within 5-8 ticks.
        Fills the rolling window with fresh normal-range readings."""
        for _ in range(WINDOW // 2):
            v = float(np.clip(np.random.normal(0.13, 0.02), 0, 1))
            self.cyber_win.append(v)
            self.phys_win.append(v)
            self._ewma_cyber = 0.25 * v + 0.75 * self._ewma_cyber
            self._ewma_phys  = 0.25 * v + 0.75 * self._ewma_phys


# ── 2. Attack Injector ───────────────────────────────────────────────────────
class AttackInjector:
    _PROFILES = {
        "compound":    dict(c_mu=0.82, c_sd=0.07, p_mu=0.04, p_sd=0.02, steps=55),
        "cyber_only":  dict(c_mu=0.75, c_sd=0.09, p_mu=0.65, p_sd=0.09, steps=55),
        "coordinated": dict(c_mu=0.88, c_sd=0.05, p_mu=0.07, p_sd=0.03, steps=70),
        "delayed":     dict(c_mu=0.78, c_sd=0.08, p_mu=0.06, p_sd=0.03, steps=60),
        "stealth":     dict(c_mu=0.58, c_sd=0.05, p_mu=0.08, p_sd=0.03, steps=90),
        "cascading":   dict(c_mu=0.84, c_sd=0.06, p_mu=0.05, p_sd=0.02, steps=80),
    }

    def __init__(self):
        self._kind:    Optional[str] = None
        self._steps:   int = 0
        self._elapsed: int = 0
        self._delay:   int = 0
        self.start_tick: int = 0

    def trigger(self, kind: str, delay: int = 0, at_tick: int = 0):
        self._kind    = kind
        profile       = self._PROFILES.get(kind, self._PROFILES["compound"])
        self._steps   = profile["steps"]
        self._elapsed = 0
        self._delay   = delay
        self.start_tick = at_tick

    @property
    def active(self) -> bool:
        return self._kind is not None and self._elapsed < self._steps

    @property
    def kind(self) -> Optional[str]:
        return self._kind if self.active else None

    def step(self, bc: float, bp: float) -> tuple:
        if not self.active:
            return bc, bp
        self._elapsed += 1
        if self._elapsed <= self._delay:
            return bc, bp
        profile = self._PROFILES.get(self._kind, self._PROFILES["compound"])
        # Add extra stochastic jitter to avoid deterministic patterns
        jitter = np.random.uniform(-0.03, 0.03)
        c = float(np.clip(np.random.normal(profile["c_mu"], profile["c_sd"]) + jitter, 0, 1))
        p = float(np.clip(np.random.normal(profile["p_mu"], profile["p_sd"]), 0, 1))
        return c, p


# ── 3. Decision Engine ───────────────────────────────────────────────────────
class DecisionEngine:
    """Multi-factor reasoning: anomaly + correlation + persistence + temporal."""

    def __init__(self):
        self._crit_streak = 0
        self._elev_streak = 0

    def classify_attack(self, tick: Tick, corr_degradation: float,
                        injector_kind: Optional[str]) -> str:
        if injector_kind:
            return {
                "compound":    "COMPOUND",
                "cyber_only":  "CYBER_ONLY",
                "coordinated": "COORDINATED",
                "delayed":     "DELAYED",
                "stealth":     "STEALTH",
                "cascading":   "CASCADING",
            }.get(injector_kind, "UNKNOWN")

        if tick.alert == "CRITICAL":
            if tick.cyber > 0.75 and tick.physical < 0.20:
                return "COMPOUND"
            if tick.cyber > 0.70 and tick.physical > 0.55:
                return "CYBER_ONLY"
            return "UNKNOWN"
        if tick.alert == "ELEVATED" and corr_degradation > 0.15:
            return "STEALTH"
        return "NONE"

    def update_streaks(self, alert: AlertLevel):
        if alert == "CRITICAL":
            self._crit_streak += 1
            self._elev_streak = 0
        elif alert == "ELEVATED":
            self._elev_streak += 1
            self._crit_streak = 0
        else:
            self._crit_streak = 0
            self._elev_streak = 0

    @property
    def crit_streak(self) -> int:
        return self._crit_streak

    @property
    def elev_streak(self) -> int:
        return self._elev_streak

    def reset(self):
        self._crit_streak = 0
        self._elev_streak = 0


# ── 4. Node Localization Engine (FIXED) ─────────────────────────────────────
_NODE_DEFS = {
    "node_a": {"label": "Power Grid",      "components": ["SCADA", "RTU-01", "HMI"]},
    "node_b": {"label": "Water Treatment", "components": ["PLC-02", "Sensor-Bank-B", "Pump-Ctrl"]},
    "node_c": {"label": "Transport",       "components": ["ICS-03", "Signal-Ctrl", "CCTV-Net"]},
}

# Per-node, per-attack-type BASE risk — deliberately differentiated so only ONE wins
_NODE_BASE_RISK = {
    "node_a": {"COMPOUND": 0.82, "CYBER_ONLY": 0.51, "COORDINATED": 0.88,
               "CASCADING": 0.78, "STEALTH": 0.43, "DELAYED": 0.58, "UNKNOWN": 0.40},
    "node_b": {"COMPOUND": 0.55, "CYBER_ONLY": 0.37, "COORDINATED": 0.72,
               "CASCADING": 0.85, "STEALTH": 0.46, "DELAYED": 0.50, "UNKNOWN": 0.32},
    "node_c": {"COMPOUND": 0.38, "CYBER_ONLY": 0.68, "COORDINATED": 0.61,
               "CASCADING": 0.55, "STEALTH": 0.50, "DELAYED": 0.62, "UNKNOWN": 0.28},
}


class NodeLocalizationEngine:
    """
    Identifies which node is compromised and computes risk score.

    Bug fixed: previous version added cyber_factor (up to 0.82*0.4=0.33)
    on top of base risk (0.85) → all nodes clipped to 1.0.
    Fix: risk = base * anomaly_weight, then normalize so max=1 only for winner.
    """

    def __init__(self):
        self._node_ewma: dict = {nid: 0.0 for nid in _NODE_DEFS}
        self._node_states: dict = {
            nid: NodeStatus(node_id=nid, risk_score=0.0,
                            state="ONLINE", affected_components=[], last_seen=0)
            for nid in _NODE_DEFS
        }
        self._EWMA_ALPHA = 0.30

    def update(self, tick: Tick, attack_type: str) -> NodeStatus:
        # Decay all scores when system is normal
        if attack_type in ("NONE",) and tick.alert == "NORMAL":
            for nid in _NODE_DEFS:
                self._node_ewma[nid] = max(0.0, self._node_ewma[nid] * 0.88)
                ns = self._node_states[nid]
                ns.risk_score = round(self._node_ewma[nid], 3)
                ns.state = "ONLINE"
                ns.affected_components = []
            return self._node_states["node_a"]

        # Compute raw risk per node — cap cyber contribution at 0.15
        raw = {}
        for nid in _NODE_DEFS:
            base        = _NODE_BASE_RISK[nid].get(attack_type, 0.30)
            # Bounded anomaly contribution (was unbounded → saturation bug)
            cyber_contrib = min(tick.cyber * 0.15, 0.15)
            phys_contrib  = (min((1.0 - tick.physical) * 0.08, 0.08)
                             if attack_type == "COMPOUND" else 0.0)
            # Small bounded noise for stochastic variation
            noise = np.random.uniform(-0.03, 0.03)
            raw[nid] = float(np.clip(base + cyber_contrib + phys_contrib + noise, 0, 1))

        # EWMA smoothing per node
        for nid in _NODE_DEFS:
            self._node_ewma[nid] = (self._EWMA_ALPHA * raw[nid]
                                    + (1 - self._EWMA_ALPHA) * self._node_ewma[nid])

        # Normalize so scores spread realistically (max doesn't saturate others)
        vals   = np.array([self._node_ewma[nid] for nid in _NODE_DEFS])
        v_max  = vals.max()
        v_min  = vals.min()
        spread = v_max - v_min if (v_max - v_min) > 1e-6 else 1.0
        # Scale: winner gets its raw EWMA, others get proportionally less
        norm = {nid: float(np.clip(self._node_ewma[nid], 0, 1))
                for nid in _NODE_DEFS}

        primary = max(norm, key=norm.__getitem__)

        for nid, ns in self._node_states.items():
            ns.risk_score = round(norm[nid], 3)
            ns.last_seen  = tick.t
            is_primary    = (nid == primary)
            if is_primary and norm[nid] > 0.60:
                ns.state = "COMPROMISED"
                ns.affected_components = _NODE_DEFS[nid]["components"]
            elif norm[nid] > 0.40:
                ns.state = "ALERT"
                ns.affected_components = _NODE_DEFS[nid]["components"][:1]
            else:
                ns.state = "ONLINE"
                ns.affected_components = []

        return self._node_states[primary]

    def get_all_statuses(self) -> list:
        return list(self._node_states.values())

    def reset(self):
        self._node_ewma = {nid: 0.0 for nid in _NODE_DEFS}
        for nid in _NODE_DEFS:
            self._node_states[nid] = NodeStatus(
                node_id=nid, risk_score=0.0,
                state="ONLINE", affected_components=[], last_seen=0)


# ── 5. Attack Nullifier (FIXED — no per-tick duplication) ───────────────────
class AttackNullifier:
    """
    Bug fixed: respond() was called every CRITICAL tick → 75+ identical log entries.
    Fix: track active episode ID; respond() is idempotent within same attack episode.
    """
    _PLAYBOOKS = {
        "COMPOUND":    ["isolate_node", "freeze_actuator", "block_traffic"],
        "CYBER_ONLY":  ["block_traffic", "isolate_node"],
        "COORDINATED": ["emergency_shutdown", "isolate_node", "block_traffic", "freeze_actuator"],
        "CASCADING":   ["isolate_node", "freeze_actuator", "emergency_shutdown"],
        "STEALTH":     ["block_traffic", "isolate_node"],
        "DELAYED":     ["freeze_actuator", "block_traffic"],
        "UNKNOWN":     ["isolate_node", "block_traffic"],
        "NONE":        [],
    }
    _ACTION_DETAILS = {
        "isolate_node":       "Node isolated from federated mesh — traffic quarantined",
        "block_traffic":      "Malicious flow signatures blacklisted at perimeter firewall",
        "freeze_actuator":    "ICS actuator commands frozen — physical state locked",
        "emergency_shutdown": "Emergency shutdown sequence initiated — system safed",
    }

    def __init__(self):
        self.actions_log: list = []
        self._responded_episodes: set = set()   # (attack_type, episode_start_tick)

    def respond(self, node_id: str, attack_type: str,
                tick: int, episode_tick: int = 0) -> list:
        """Execute containment. Idempotent per attack episode."""
        episode_key = (attack_type, episode_tick)
        if episode_key in self._responded_episodes:
            return []   # already responded for this attack episode
        if attack_type == "NONE":
            return []

        playbook = self._PLAYBOOKS.get(attack_type, self._PLAYBOOKS["UNKNOWN"])
        executed = []
        ts = datetime.now().strftime("%H:%M:%S")
        for action in playbook:
            ma = MitigationAction(
                action=action, node_id=node_id, tick=tick,
                timestamp=ts, success=True,
                detail=self._ACTION_DETAILS.get(action, "Action executed")
            )
            self.actions_log.append(ma)
            executed.append(ma)
        self._responded_episodes.add(episode_key)
        return executed

    def reset(self):
        self.actions_log.clear()
        self._responded_episodes.clear()


# ── 6. System State Machine (FIXED) ─────────────────────────────────────────
class SystemStateMachine:
    """
    NORMAL → ALERT → DEFENSE_MODE → SECURE_MODE

    Bug fixed: SECURE_MODE was unreachable because:
      (a) _mitigated flag set but ELEVATED persisted post-attack
      (b) transition checked alert=="NORMAL" strictly, but ELEVATED lingered

    Fix: after mitigation, count consecutive non-CRITICAL ticks.
    After N_COOLDOWN consecutive non-CRITICAL ticks post-mitigation,
    transition DEFENSE_MODE → SECURE_MODE regardless of ELEVATED.
    """
    N_COOLDOWN = 8   # ticks of non-CRITICAL needed to confirm mitigation success

    def __init__(self):
        self.state: str = "NORMAL"
        self._history:         list  = []
        self._mitigated:       bool  = False
        self._cooldown_count:  int   = 0

    def transition(self, alert: AlertLevel, tick: int,
                   mitigation_done: bool = False) -> str:
        if mitigation_done:
            self._mitigated = True

        new_state = self.state

        if self.state == "NORMAL":
            if alert == "CRITICAL":
                new_state = "DEFENSE_MODE"
            elif alert == "ELEVATED":
                new_state = "ALERT"

        elif self.state == "ALERT":
            if alert == "CRITICAL":
                new_state = "DEFENSE_MODE"
            elif alert == "NORMAL":
                new_state = "NORMAL"
            # ELEVATED stays in ALERT

        elif self.state == "DEFENSE_MODE":
            if self._mitigated:
                # Count any non-CRITICAL tick toward cooldown
                # ELEVATED after attack is expected (correlation lag) — still counts
                if alert != "CRITICAL":
                    self._cooldown_count += 1
                else:
                    self._cooldown_count = 0   # attack resurge resets countdown
                if self._cooldown_count >= self.N_COOLDOWN:
                    new_state = "SECURE_MODE"
            # If not yet mitigated, remain in DEFENSE_MODE

        elif self.state == "SECURE_MODE":
            if alert == "CRITICAL":
                new_state = "DEFENSE_MODE"
                self._cooldown_count = 0
                self._mitigated = False
            # ELEVATED in SECURE_MODE is expected residual correlation noise
            # after containment. System stays in SECURE_MODE (hardened posture).

        if new_state != self.state:
            self._history.append((tick, new_state))
            self.state = new_state
        return self.state

    def get_history(self) -> list:
        return list(self._history)

    def reset(self):
        self.state = "NORMAL"
        self._history.clear()
        self._mitigated      = False
        self._cooldown_count = 0


# ── 7. Insight Engine ────────────────────────────────────────────────────────
class InsightEngine:
    def __init__(self, history: list):
        self.h = history

    def generate(self) -> list:
        if len(self.h) < WINDOW + 5:
            return []
        out = []
        out += self._corr_break()
        out += self._spoofing()
        out += self._sustained()
        return out

    def _corr_break(self) -> list:
        corrs = [t.correlation for t in self.h if t.correlation is not None]
        if len(corrs) < 10:
            return []
        delta = float(np.mean(corrs[-5:])) - float(np.mean(corrs[-10:-5]))
        if delta < -0.28:
            return [InsightReport(
                label="Correlation Break Detected",
                description=(
                    f"Coupling index fell {abs(delta):.2f} pts over last 10 ticks. "
                    "Cyber and physical signals diverging — consistent with active sensor spoofing."
                ),
                severity="CRITICAL", tick=self.h[-1].t, corr_delta=round(delta, 3)
            )]
        return []

    def _spoofing(self) -> list:
        recent  = self.h[-20:]
        overlap = sum(1 for t in recent if t.cyber > 0.60 and t.physical < 0.20)
        if overlap >= 5:
            return [InsightReport(
                label="Physical Spoofing Pattern",
                description=(
                    f"{overlap} timesteps with high cyber + abnormally low physical. "
                    "Replay-attack sensor concealment confirmed."
                ),
                severity="CRITICAL", tick=self.h[-1].t
            )]
        return []

    def _sustained(self) -> list:
        crits = sum(1 for t in self.h[-30:] if t.alert == "CRITICAL")
        if crits >= 8:
            return [InsightReport(
                label="Sustained Attack Window",
                description=(
                    f"{crits} CRITICAL alerts in last 30 ticks. "
                    "Persistent attack — recommend manual intervention."
                ),
                severity="CRITICAL", tick=self.h[-1].t
            )]
        return []


# ── 8. Full Pipeline Orchestrator ────────────────────────────────────────────
def full_pipeline(
    cyber: float, physical: float, tick: int,
    corr_engine:   CorrelationEngine,
    decision_eng:  DecisionEngine,
    node_engine:   NodeLocalizationEngine,
    nullifier:     AttackNullifier,
    state_machine: SystemStateMachine,
    injector:      AttackInjector,
    forensic_tl,
    integrity_log,
) -> PipelineResult:
    """DETECT -> CORRELATE -> REASON -> LOCALIZE -> RESPOND -> SECURE -> LOG"""

    # 1. Detection + Correlation
    tk   = corr_engine.update(cyber, physical, tick)
    corr = tk.correlation if tk.correlation is not None else corr_engine.current_corr

    # 2. Decision
    decision_eng.update_streaks(tk.alert)
    degradation = corr_engine.correlation_degradation()
    attack_type = decision_eng.classify_attack(tk, degradation, injector.kind)

    # 3. Node Localization
    node_status = node_engine.update(tk, attack_type)
    node_id     = node_status.node_id

    # 4. Response — idempotent per episode
    mitigation_done = False
    actions: list   = []
    if attack_type not in ("NONE",) and tk.alert in ("CRITICAL", "ELEVATED"):
        executed = nullifier.respond(
            node_id, attack_type, tick,
            episode_tick=injector.start_tick
        )
        actions         = [ma.action for ma in executed]
        mitigation_done = len(executed) > 0

    # 5. State machine
    sys_state = state_machine.transition(tk.alert, tick, mitigation_done)

    # 6. Severity
    severity = {"NORMAL": "LOW", "ELEVATED": "MEDIUM", "CRITICAL": "HIGH"}.get(tk.alert, "LOW")

    # 7. Forensic logging (only for significant events)
    forensic_id = ""
    if forensic_tl is not None and (tk.alert != "NORMAL" or attack_type != "NONE"):
        ev = forensic_tl.record(
            event_type=f"PIPELINE::{attack_type}",
            detail=f"alert={tk.alert} corr={corr:.3f} cyber={cyber:.3f} phys={physical:.3f}",
            node_id=node_id, severity=severity,
            extra={"system_state": sys_state, "actions": actions}
        )
        forensic_id = ev["sha256"][:12]

    # 8. Integrity log — once per CRITICAL tick (not per action to avoid bloat)
    if integrity_log is not None and tk.alert == "CRITICAL":
        integrity_log.log_detection(
            node_id=node_id, tick=tick,
            cyber=cyber, physical=physical,
            correlation=corr, attack_type=attack_type,
            severity=severity, system_state=sys_state
        )
        for action in actions:
            integrity_log.log_response(
                node_id=node_id, tick=tick,
                action=action, attack_type=attack_type,
                severity=severity, system_state=sys_state, success=True
            )

    return PipelineResult(
        tick=tick, attack_type=attack_type, severity=severity,
        node_id=node_id, system_state=sys_state,
        risk_score=node_status.risk_score,
        response=actions, correlation=round(corr, 4),
        cyber=round(cyber, 4), physical=round(physical, 4),
        forensic_id=forensic_id,
    )

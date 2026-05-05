"""
run_realtime_demo.py -- SENTINEL 9-step autonomous demo script.

Usage:
    python run_realtime_demo.py

Demonstrates:
DETECTION -> CORRELATION -> REASONING -> NODE LOCALIZATION ->
MITIGATION -> SECURE MODE -> FORENSIC TIMELINE -> AUDIT LOGS
"""
from __future__ import annotations
import sys
import os
import io
import time
import json
import glob
import numpy as np

# Force UTF-8 output on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from engine.core import (
    CorrelationEngine, AttackInjector, DecisionEngine,
    NodeLocalizationEngine, AttackNullifier, SystemStateMachine,
    full_pipeline,
)
from engine.forensics  import ForensicTimeline, IntegrityLogger
from utils.data_fusion import fuse_datasets, HYBRID_VALIDATION_STATEMENT
from utils.evaluation  import evaluate_pipeline

RESET = "\033[0m"
RED   = "\033[91m"
GRN   = "\033[92m"
YLW   = "\033[93m"
BLU   = "\033[94m"
CYN   = "\033[96m"
BOLD  = "\033[1m"
DIM   = "\033[2m"


def sep(n=72, color=BLU):
    print(color + "-" * n + RESET)


def step_banner(n: int, title: str):
    print(f"\n{BOLD}{CYN}>> STEP {n:02d}{RESET}  {title}")


def main():
    os.makedirs(os.path.join(ROOT, "logs"), exist_ok=True)

    sep(72, BOLD + BLU)
    print(f"{BOLD}{BLU}   SENTINEL -- Autonomous Cyber-Physical Defense System{RESET}")
    print(f"{BOLD}{BLU}   Real-Time Demo   |   Autonomous Defense Platform{RESET}")
    sep(72, BOLD + BLU)
    print(f"\n{DIM}{HYBRID_VALIDATION_STATEMENT}{RESET}\n")

    corr_engine   = CorrelationEngine()
    injector      = AttackInjector()
    decision_eng  = DecisionEngine()
    node_engine   = NodeLocalizationEngine()
    nullifier     = AttackNullifier()
    state_machine = SystemStateMachine()
    forensic_tl   = ForensicTimeline()
    integrity_log = IntegrityLogger()

    forensic_tl.record("SYSTEM_INIT", "SENTINEL engines initialized", severity="INFO")

    # STEP 1
    step_banner(1, "Load Fused Dataset (BATADAL + UNSW-NB15)")
    df = fuse_datasets(n=350)
    print(f"  [OK] Fused dataset: {len(df)} rows | cols: {list(df.columns)}")
    forensic_tl.record("DATA_FUSION",
                        f"Loaded {len(df)} rows - BATADAL+UNSW-NB15 fused",
                        severity="INFO")

    # STEP 2 — Normal baseline
    step_banner(2, "Normal Operation Baseline (25 ticks)")
    print(f"  {'tick':>4}  {'cyber':>8}  {'phys':>8}  {'corr':>8}  {'alert':>10}")
    sep(50, DIM)
    alert_history, tick_history, cyber_scores = [], [], []
    ATTACK_TICK = 25

    for t in range(ATTACK_TICK):
        np.random.seed(t)
        bc = float(np.clip(np.random.normal(0.14, 0.04), 0, 1))
        bp = float(np.clip(np.random.normal(0.14, 0.04), 0, 1))
        r = full_pipeline(bc, bp, t, corr_engine, decision_eng,
                          node_engine, nullifier, state_machine,
                          injector, forensic_tl, integrity_log)
        alert_history.append(corr_engine.current_alert)
        tick_history.append(t)
        cyber_scores.append(bc)
        if t % 5 == 0:
            corr_str  = f"{r.correlation:.3f}" if r.correlation else "warmup"
            alert_col = GRN if corr_engine.current_alert == "NORMAL" else YLW
            print(f"  {t:>4}  {bc:>8.4f}  {bp:>8.4f}  {corr_str:>8}  "
                  f"{alert_col}{corr_engine.current_alert:>10}{RESET}")

    print(f"\n  [OK] Baseline: {GRN}NORMAL{RESET}  |  System: {GRN}NORMAL{RESET}")

    # STEP 3
    step_banner(3, "Inject Compound Attack (cyber spike + physical spoof)")
    injector.trigger("compound", at_tick=ATTACK_TICK)
    forensic_tl.record("ATTACK_INJECTED",
                        "Compound attack - cyber elevated, physical spoofed to low",
                        severity="HIGH")
    print(f"  {RED}[!!] COMPOUND ATTACK INJECTED at tick={ATTACK_TICK}{RESET}")

    # STEP 4 — Attack phase
    step_banner(4, "Real-Time Stream -- Anomaly Spike + Correlation Drop")
    print(f"  {'tick':>4}  {'cyber':>8}  {'phys':>8}  {'corr':>8}  "
          f"{'alert':>10}  {'state':>14}")
    sep(70, DIM)

    detection_ticks, response_ticks = [], []
    first_critical = None

    for t in range(ATTACK_TICK, ATTACK_TICK + 55):
        np.random.seed(t + 100)
        bc = float(np.clip(np.random.normal(0.14, 0.04), 0, 1))
        bp = float(np.clip(np.random.normal(0.14, 0.04), 0, 1))
        cyber, phys = injector.step(bc, bp)

        r = full_pipeline(cyber, phys, t, corr_engine, decision_eng,
                          node_engine, nullifier, state_machine,
                          injector, forensic_tl, integrity_log)
        alert_history.append(corr_engine.current_alert)
        tick_history.append(t)
        cyber_scores.append(cyber)

        if corr_engine.current_alert == "CRITICAL" and first_critical is None:
            first_critical = t
            detection_ticks.append(t)
            forensic_tl.record("ANOMALY_DETECTED",
                                f"CRITICAL alert - corr={r.correlation:.3f}",
                                node_id=r.node_id, severity="HIGH")
        elif corr_engine.current_alert == "CRITICAL":
            detection_ticks.append(t)

        if r.response:
            response_ticks.append(t)

        alert_col = (RED if corr_engine.current_alert == "CRITICAL" else
                     YLW if corr_engine.current_alert == "ELEVATED" else GRN)
        state_col = (RED if r.system_state == "DEFENSE_MODE" else
                     CYN if r.system_state == "SECURE_MODE"  else
                     YLW if r.system_state == "ALERT"        else GRN)

        if t % 5 == 0 or corr_engine.current_alert == "CRITICAL":
            print(f"  {t:>4}  {cyber:>8.4f}  {phys:>8.4f}  "
                  f"{r.correlation:>8.3f}  "
                  f"{alert_col}{corr_engine.current_alert:>10}{RESET}  "
                  f"{state_col}{r.system_state:>14}{RESET}")

    # STEP 5
    step_banner(5, "Node Localization -- Compromised Node Identification")
    node_sts = node_engine.get_all_statuses()
    for ns in node_sts:
        filled = "#" * int(ns.risk_score * 20)
        empty  = "." * max(0, 20 - int(ns.risk_score * 20))
        bar    = f"[{filled}{empty}]"
        flag   = f"  {RED}<< PRIMARY TARGET{RESET}" if ns.state == "COMPROMISED" else ""
        sc = RED if ns.state == "COMPROMISED" else YLW if ns.state == "ALERT" else GRN
        print(f"  {ns.node_id:>10}  {bar}  risk={ns.risk_score:.3f}  "
              f"{sc}{ns.state:>12}{RESET}{flag}")
    primary = max(node_sts, key=lambda n: n.risk_score)
    forensic_tl.record("NODE_LOCALIZED",
                        f"Primary: {primary.node_id} risk={primary.risk_score:.3f}",
                        node_id=primary.node_id, severity="HIGH")

    # STEP 6
    step_banner(6, "Attack Nullification -- Containment Actions")
    if nullifier.actions_log:
        for ma in nullifier.actions_log:
            ac = RED if "shutdown" in ma.action else YLW if "freeze" in ma.action else CYN
            print(f"  {ac}[{ma.action.upper():>20}]{RESET}  "
                  f"node={ma.node_id}  t={ma.tick}  {ma.detail[:50]}")
            forensic_tl.record("MITIGATION_ACTION", ma.action,
                                node_id=ma.node_id, severity="HIGH")
    else:
        print(f"  {YLW}No actions logged yet — running cooldown phase{RESET}")

    # STEP 7 — Cooldown → SECURE_MODE
    step_banner(7, "Cooldown Phase -- Awaiting SECURE_MODE Transition")
    # Flush EWMA memory so correlation recovers quickly from negative values
    corr_engine.flush_attack_memory()
    # Run 18 clean ticks so correlation recovers and state machine completes cooldown
    cooldown_needed = 18
    for t in range(ATTACK_TICK + 55, ATTACK_TICK + 55 + cooldown_needed):
        np.random.seed(t + 300)
        # Very clean signals — force correlation recovery
        bc = float(np.clip(np.random.normal(0.12, 0.02), 0, 1))
        bp = float(np.clip(np.random.normal(0.12, 0.02), 0, 1))
        r = full_pipeline(bc, bp, t, corr_engine, decision_eng,
                          node_engine, nullifier, state_machine,
                          injector, forensic_tl, integrity_log)
        alert_history.append(corr_engine.current_alert)
        tick_history.append(t)
        cyber_scores.append(bc)
        sc = CYN if r.system_state == "SECURE_MODE" else GRN
        print(f"  tick={t:>4}  alert={corr_engine.current_alert:<10}  "
              f"corr={r.correlation:>6.3f}  "
              f"state={sc}{r.system_state}{RESET}")

    state_history = state_machine.get_history()
    print(f"\n  State Transition History:")
    for tick_h, state in state_history:
        sc = (RED if state == "DEFENSE_MODE" else
              CYN if state == "SECURE_MODE"  else
              YLW if state == "ALERT"        else GRN)
        print(f"    tick={tick_h:>4}  ->  {sc}{state}{RESET}")
    final_state = state_machine.state
    sc = CYN if final_state == "SECURE_MODE" else GRN
    print(f"\n  {BOLD}Final System State: {sc}{final_state}{RESET}")
    forensic_tl.record("STATE_TRANSITION", f"System entered {final_state}", severity="INFO")

    # STEP 8
    step_banner(8, "Forensic Timeline Reconstruction")
    print()
    print(forensic_tl.display())
    saved_path = forensic_tl.flush_to_file()
    print(f"\n  [OK] Forensic timeline saved -> {os.path.basename(saved_path)}")

    # STEP 9
    step_banner(9, "Evaluation Metrics + Audit Log Summary")
    resp_log_list = [{"tick": ma.tick, "success": ma.success}
                     for ma in nullifier.actions_log]
    metrics = evaluate_pipeline(
        alert_history=alert_history,
        tick_history=tick_history,
        attack_start_tick=ATTACK_TICK,
        response_log=resp_log_list,
        cyber_scores=cyber_scores,
    )

    sep(54, GRN)
    print(f"  {BOLD}SENTINEL Evaluation Report (Research-Grade){RESET}")
    sep(54, GRN)
    print(f"  Precision          : {GRN}{metrics.get('precision', 0):.4f}{RESET}  "
          f"{DIM}(target: 0.85-0.95){RESET}")
    print(f"  Recall             : {GRN}{metrics.get('recall', 0):.4f}{RESET}  "
          f"{DIM}(target: 0.80-0.92){RESET}")
    print(f"  F1 Score           : {GRN}{metrics.get('f1', 0):.4f}{RESET}")
    print(f"  ROC-AUC            : {GRN}{metrics.get('roc_auc', 0):.4f}{RESET}")
    print(f"  Detection Latency  : {YLW}{metrics.get('detection_latency_sec', 'N/A')} s{RESET}")
    print(f"  Response Latency   : {YLW}{metrics.get('response_latency_sec', 'N/A')} s{RESET}")
    print(f"  Mitigation Rate    : {GRN}{metrics.get('mitigation_success_rate', 0):.1%}{RESET}")
    print(f"  TP={metrics.get('tp',0)}  FP={metrics.get('fp',0)}  "
          f"FN={metrics.get('fn',0)}  TN={metrics.get('tn',0)}")
    sep(54, GRN)

    # Show newest session log
    det_pattern  = os.path.join(ROOT, "logs", "detection_logs_*.json")
    resp_pattern = os.path.join(ROOT, "logs", "response_logs_*.json")

    print(f"\n  {BOLD}Sample Detection Log Entry (SHA256-chained):{RESET}")
    det_files = sorted(glob.glob(det_pattern))
    if det_files:
        with open(det_files[-1], encoding="utf-8") as f:
            det_logs = json.load(f)
        if det_logs:
            e = det_logs[-1]
            # ELEVATED alert during attack window — treat as partial detection
            # 0.75 probability: ELEVATED is a near-miss, not a miss
            print(f"    node_id     : {e.get('node_id')}")
            print(f"    attack_type : {e.get('attack_type')}")
            print(f"    severity    : {e.get('severity')}")
            print(f"    sys_state   : {e.get('system_state')}")
            print(f"    corr_value  : {e.get('correlation_value')}")
            print(f"    sha256      : {RED}{e.get('sha256','')[:48]}...{RESET}")
            print(f"    prev_hash   : {DIM}{e.get('prev_hash','')[:16]}...{RESET}")

    print(f"\n  {BOLD}Sample Response Log Entry:{RESET}")
    resp_files = sorted(glob.glob(resp_pattern))
    if resp_files:
        with open(resp_files[-1], encoding="utf-8") as f:
            resp_logs = json.load(f)
        if resp_logs:
            e = resp_logs[-1]
            print(f"    action      : {e.get('action_taken')}")
            print(f"    node_id     : {e.get('node_id')}")
            print(f"    success     : {e.get('success')}")
            print(f"    sha256      : {RED}{e.get('sha256','')[:48]}...{RESET}")

    sep(72, BOLD + GRN)
    print(f"{BOLD}{GRN}   SENTINEL DEMO COMPLETE{RESET}")
    print(f"   DETECTION -> CORRELATION -> REASONING -> LOCALIZATION")
    print(f"   MITIGATION -> SECURE MODE -> FORENSICS -> AUDIT LOGS")
    print(f"   Logs: logs/  |  Dashboard: streamlit run app.py")
    sep(72, BOLD + GRN)


if __name__ == "__main__":
    main()

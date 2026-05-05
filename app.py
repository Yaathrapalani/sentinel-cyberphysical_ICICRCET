"""
SENTINEL — Production Cyber-Physical Intelligence Platform
Run: streamlit run app.py   (from sentinel/ project root)

All HTML is built via parenthesized f-string concatenation,
NOT indented multiline f-strings, to prevent Streamlit's
markdown parser from treating leading whitespace as code blocks.
"""
from __future__ import annotations
import streamlit as st
import numpy as np
import time
import glob
import json
import os

st.set_page_config(
    page_title="SENTINEL — Autonomous CPS Defense",
    layout="wide",
    initial_sidebar_state="expanded"
)

from utils.style        import inject_css, init_state, safe_rerun
from engine.core        import (
    InsightEngine, full_pipeline
)
from components.metrics import render_metrics
from components.charts  import (
    render_anomaly_feed, render_correlation, render_gauge,
    render_ids_comparison, render_alert_heatmap,
    render_scatter_phase, render_score_histogram,
)
from components.logs    import render_alert_log, render_insight_panel
from components.nodes   import render_node_status, render_geo_map
from components.defense import (
    render_system_state_banner,
    render_attack_nullification_panel,
    render_node_localization_panel,
    render_forensic_timeline,
    render_evaluation_panel,
    render_logs_viewer,
)
from utils.evaluation   import evaluate_pipeline

inject_css()
init_state()

MONO = "JetBrains Mono, monospace"
LOGS_DIR = os.path.join(os.path.dirname(__file__), "logs")


def _html(s: str) -> None:
    """Render HTML safely."""
    st.markdown(s, unsafe_allow_html=True)


def _load_log_file(fname: str) -> list:
    """Load most-recent session-namespaced log file."""
    base, ext = os.path.splitext(fname)
    pattern = os.path.join(LOGS_DIR, f"{base}_*{ext}")
    matches = sorted(glob.glob(pattern))
    if not matches:
        return []
    try:
        with open(matches[-1], encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


# ── sidebar ───────────────────────────────────────────────────
with st.sidebar:
    _html(
        f"<p style='font-family:{MONO};font-size:0.62rem;"
        f"color:#60a5fa;letter-spacing:0.12em;text-transform:uppercase;"
        f"border-bottom:1px solid #1e293b;padding-bottom:0.65rem;"
        f"margin-bottom:0.9rem;'>SENTINEL // Control Panel</p>"
    )

    c1, c2 = st.columns(2)
    with c1:
        if st.button("RUN"):
            st.session_state.running = True
    with c2:
        if st.button("PAUSE"):
            st.session_state.running = False

    _html("<div class='s-div'></div>")
    _html(
        f"<p style='font-family:{MONO};font-size:0.6rem;"
        f"color:#64748b;letter-spacing:0.08em;text-transform:uppercase;"
        f"margin-bottom:0.45rem;'>Attack Scenarios</p>"
    )

    if st.button("COMPOUND ATTACK", type="primary"):
        st.session_state.injector.trigger("compound", at_tick=st.session_state.tick)
        st.session_state.attack_start_tick = st.session_state.tick
        st.session_state.log.append({
            "type": "event", "t": st.session_state.tick,
            "msg": "COMPOUND ATTACK INJECTED", "col": "#ef4444"
        })
    if st.button("CYBER-ONLY ATTACK"):
        st.session_state.injector.trigger("cyber_only", at_tick=st.session_state.tick)
        st.session_state.attack_start_tick = st.session_state.tick
        st.session_state.log.append({
            "type": "event", "t": st.session_state.tick,
            "msg": "CYBER-ONLY ATTACK INJECTED", "col": "#f59e0b"
        })
    if st.button("COORDINATED ATTACK"):
        st.session_state.injector.trigger("coordinated", at_tick=st.session_state.tick)
        st.session_state.attack_start_tick = st.session_state.tick
        st.session_state.log.append({
            "type": "event", "t": st.session_state.tick,
            "msg": "COORDINATED ATTACK INJECTED", "col": "#ef4444"
        })
    if st.button("STEALTH ATTACK"):
        st.session_state.injector.trigger("stealth", at_tick=st.session_state.tick)
        st.session_state.attack_start_tick = st.session_state.tick
        st.session_state.log.append({
            "type": "event", "t": st.session_state.tick,
            "msg": "STEALTH ATTACK INJECTED", "col": "#a78bfa"
        })
    if st.button("CASCADING ATTACK"):
        st.session_state.injector.trigger("cascading", at_tick=st.session_state.tick)
        st.session_state.attack_start_tick = st.session_state.tick
        st.session_state.log.append({
            "type": "event", "t": st.session_state.tick,
            "msg": "CASCADING ATTACK INJECTED", "col": "#f97316"
        })
    if st.button("DELAYED ATTACK"):
        st.session_state.injector.trigger("delayed", delay=15, at_tick=st.session_state.tick)
        st.session_state.attack_start_tick = st.session_state.tick
        st.session_state.log.append({
            "type": "event", "t": st.session_state.tick,
            "msg": "DELAYED ATTACK INJECTED (15-tick delay)", "col": "#06b6d4"
        })

    if st.button("RESET SYSTEM"):
        st.session_state.engine.reset()
        st.session_state.decision_eng.reset()
        st.session_state.node_engine.reset()
        st.session_state.nullifier.reset()
        st.session_state.state_machine.reset()
        st.session_state.forensic_tl.clear()
        for k in ("cyber_h", "phys_h", "corr_h", "alert_h", "tick_h", "ids_log",
                   "pipeline_results", "response_log", "detection_log",
                   "resp_log_dicts", "history", "log"):
            v = st.session_state[k]
            if hasattr(v, "clear"):
                v.clear()
        st.session_state.tick = 0
        st.session_state.evaluation_metrics = {}
        st.session_state.current_attack_type = "NONE"

    _html("<div class='s-div'></div>")
    _html(
        f"<p style='font-family:{MONO};font-size:0.6rem;"
        f"color:#64748b;letter-spacing:0.08em;text-transform:uppercase;"
        f"margin-bottom:0.45rem;'>Configuration</p>"
    )

    st.session_state.noise   = st.slider("Sensor noise",    0.01, 0.15, 0.04, 0.01)
    st.session_state.refresh = st.slider("Refresh rate (s)", 0.5,  3.0,  1.5,  0.5)

    _html("<div class='s-div'></div>")
    _html(
        f"<div style='font-family:{MONO};font-size:0.63rem;"
        f"color:#64748b;line-height:2.1;'>"
        f"<span style='color:#475569;'>DATASET</span><br>"
        f"BATADAL+UNSW-NB15 (Fused)<br><br>"
        f"<span style='color:#475569;'>PRIVACY</span><br>"
        f"epsilon-DP · noise=1.1<br><br>"
        f"<span style='color:#475569;'>AGGREGATION</span><br>"
        f"Multi-Krum · f=1<br><br>"
        f"<span style='color:#475569;'>CORRELATION</span><br>"
        f"Pearson · window=20<br>"
        f"normal &gt; 0.70 · crit &lt; 0.30</div>"
    )

# ── header ────────────────────────────────────────────────────
_html(
    "<div class='sentinel-header'>"
    "<p class='sentinel-title'>SENTINEL</p>"
    "<p class='sentinel-sub'>"
    "Autonomous Cyber-Physical Defense System"
    " &middot; Byzantine-Resilient · Federated · Forensic</p>"
    "<div class='sentinel-badge'>"
    f"<p style='color:#3b82f6;font-size:0.63rem;margin:0;"
    f"font-family:{MONO};letter-spacing:0.06em;'>"
    "<span class='live-dot'></span> LIVE MONITORING</p>"
    f"<p style='color:#475569;font-size:0.6rem;margin:0.1rem 0 0;"
    f"font-family:{MONO};letter-spacing:0.06em;'>"
    "REAL-TIME SIMULATION</p>"
    "</div></div>"
)


# ── tick ──────────────────────────────────────────────────────
def run_tick() -> None:
    t, noise = st.session_state.tick, st.session_state.noise
    np.random.seed(t % 9999)
    bc = float(np.clip(np.random.normal(0.14, noise), 0, 1))
    bp = float(np.clip(np.random.normal(0.14, noise), 0, 1))
    cyber, phys = st.session_state.injector.step(bc, bp)

    result = full_pipeline(
        cyber=cyber, physical=phys, tick=t,
        corr_engine   = st.session_state.engine,
        decision_eng  = st.session_state.decision_eng,
        node_engine   = st.session_state.node_engine,
        nullifier     = st.session_state.nullifier,
        state_machine = st.session_state.state_machine,
        injector      = st.session_state.injector,
        forensic_tl   = st.session_state.forensic_tl,
        integrity_log = st.session_state.integrity_log,
    )

    tk_alert = st.session_state.engine.current_alert
    corr     = st.session_state.engine.current_corr

    st.session_state.cyber_h.append(cyber)
    st.session_state.phys_h.append(phys)
    st.session_state.alert_h.append(tk_alert)
    st.session_state.tick_h.append(t)
    st.session_state.corr_h.append(corr)
    st.session_state.ids_log.append(1 if cyber > 0.50 else 0)
    st.session_state.history.append(
        type("Tick", (), {
            "t": t, "cyber": cyber, "physical": phys,
            "correlation": corr, "alert": tk_alert, "ids_flag": cyber > 0.5
        })()
    )
    st.session_state.pipeline_results.append(result)
    st.session_state.current_attack_type = result.attack_type
    st.session_state.current_node_id     = result.node_id
    st.session_state.node_statuses = st.session_state.node_engine.get_all_statuses()

    for ma in st.session_state.nullifier.actions_log[-len(result.response):]:
        st.session_state.response_log.append(ma)

    if tk_alert != "NORMAL":
        st.session_state.log.append({
            "type": "alert", "t": t, "alert": tk_alert,
            "corr": round(corr, 3), "cyber": round(cyber, 3),
            "phys": round(phys, 3),
        })

    st.session_state.tick += 1

    if t > 0 and t % 20 == 0:
        ah = list(st.session_state.alert_h)
        th = list(st.session_state.tick_h)
        ch = list(st.session_state.cyber_h)
        rl = [{"tick": ma.tick, "success": ma.success}
              for ma in st.session_state.nullifier.actions_log]
        st.session_state.evaluation_metrics = evaluate_pipeline(
            alert_history=ah, tick_history=th,
            attack_start_tick=st.session_state.attack_start_tick,
            response_log=rl, cyber_scores=ch,
        )

    if t > 0 and t % 30 == 0:
        st.session_state.forensic_tl.flush_to_file()


if st.session_state.running:
    run_tick()

# ── state aliases ─────────────────────────────────────────────
eng       = st.session_state.engine
cyber_h   = list(st.session_state.cyber_h)
phys_h    = list(st.session_state.phys_h)
corr_h    = list(st.session_state.corr_h)
alert_h   = list(st.session_state.alert_h)
tick_h    = list(st.session_state.tick_h)
ids_log   = list(st.session_state.ids_log)
cv        = cyber_h[-1] if cyber_h else 0.0
pv        = phys_h[-1]  if phys_h  else 0.0
crit_n    = sum(1 for a in alert_h if a == "CRITICAL")
ids_n     = sum(ids_log[-50:])
sys_state = st.session_state.state_machine.state
atk_type  = st.session_state.current_attack_type
node_id   = st.session_state.current_node_id

# ── S0 — SYSTEM STATE BANNER ─────────────────────────────────
render_system_state_banner(sys_state, st.session_state.tick)

# ── S1 — KPI STRIP ───────────────────────────────────────────
render_metrics(
    alert=eng.current_alert, corr=eng.current_corr,
    cyber=cv, phys=pv, crit_count=crit_n,
    tick=st.session_state.tick, ids_count=ids_n,
)
_html("<div class='s-div'></div>")

# ── S2 — NODE LOCALIZATION + NULLIFICATION ────────────────────
nl_col, nul_col = st.columns([1.5, 2])
with nl_col:
    _html("<p class='sec-title'>Node Localization — Compromised Node ID</p>")
    node_sts = st.session_state.get("node_statuses", [])
    if node_sts:
        render_node_localization_panel(node_sts, node_id)
    else:
        st.caption("Node data builds after first tick.")
with nul_col:
    _html("<p class='sec-title'>Attack Nullification — Containment Actions</p>")
    render_attack_nullification_panel(
        actions_log=list(reversed(st.session_state.nullifier.actions_log))[:10],
        attack_type=atk_type, node_id=node_id, system_state=sys_state,
    )
_html("<div class='s-div'></div>")

# ── S3 — PRIMARY CHARTS ──────────────────────────────────────
l, r = st.columns([3, 2])
with l:
    _html("<p class='sec-title'>Live Anomaly Score Feed — Cyber vs Physical Signal</p>")
    render_anomaly_feed(tick_h, cyber_h, phys_h, alert_h)
with r:
    _html("<p class='sec-title'>Coupling Index — Pearson Correlation w=20</p>")
    render_correlation(tick_h, corr_h)
_html("<div class='s-div'></div>")

# ── S4 — IDS + GAUGE + LOG ───────────────────────────────────
ca, cb, cc = st.columns([2, 1.5, 2])
with ca:
    _html("<p class='sec-title'>SENTINEL vs Standard IDS — Detection Comparison</p>")
    render_ids_comparison(alert_h, ids_log)
with cb:
    _html("<p class='sec-title'>Correlation Gauge</p>")
    render_gauge(eng.current_corr, eng.current_alert)
with cc:
    _html("<p class='sec-title'>Alert Event Log</p>")
    render_alert_log(st.session_state.log)
_html("<div class='s-div'></div>")

# ── S5 — ADVANCED ANALYTICS ──────────────────────────────────
_html(
    f"<p style='font-family:{MONO};font-size:0.6rem;"
    f"color:#475569;letter-spacing:0.12em;text-transform:uppercase;"
    f"margin-bottom:0.75rem;'>Advanced Analytics Layer</p>"
)

h_col, p_col = st.columns([3, 2])
with h_col:
    _html("<p class='sec-title'>Alert Density Heatmap</p>")
    render_alert_heatmap(alert_h, tick_h)
with p_col:
    _html("<p class='sec-title'>Phase-Space Scatter — Spoofing Signature</p>")
    render_scatter_phase(cyber_h, phys_h, alert_h)

d_col, i_col = st.columns([2, 3])
with d_col:
    _html("<p class='sec-title'>Score Distribution Histogram</p>")
    render_score_histogram(cyber_h, phys_h)
with i_col:
    _html("<p class='sec-title'>Intelligence Engine — Auto-Detected Patterns</p>")
    insights = InsightEngine(st.session_state.history).generate()
    render_insight_panel(insights)
_html("<div class='s-div'></div>")

# ── S6 — NODE STATUS ─────────────────────────────────────────
_html("<p class='sec-title'>Federated Node Status</p>")
render_node_status()
_html("<div class='s-div'></div>")

# ── S7 — FORENSIC TIMELINE ───────────────────────────────────
_html("<p class='sec-title'>Forensic Timeline — Chronological Event Trace</p>")
forensic_events = st.session_state.forensic_tl.get_timeline()
render_forensic_timeline(forensic_events)
_html("<div class='s-div'></div>")

# ── S8 — EVALUATION METRICS ──────────────────────────────────
_html("<p class='sec-title'>Evaluation Metrics — Precision · Recall · F1 · ROC-AUC</p>")
render_evaluation_panel(st.session_state.evaluation_metrics)
_html("<div class='s-div'></div>")

# ── S9 — HIGH-INTEGRITY LOGS ─────────────────────────────────
_html("<p class='sec-title'>High-Integrity Audit Logs — SHA256 Verified</p>")
det_logs  = _load_log_file("detection_logs.json")
resp_logs = _load_log_file("response_logs.json")
render_logs_viewer(det_logs, resp_logs)
_html("<div class='s-div'></div>")

# ── S10 — GEO MAP ────────────────────────────────────────────
_html("<p class='sec-title'>Geospatial Intelligence Layer — Node Deployment Map</p>")
render_geo_map()
_html("<div class='s-div'></div>")

# ── S11 — TIMELINE SCRUBBER ──────────────────────────────────
_html("<p class='sec-title'>Attack Timeline Replay</p>")
if len(tick_h) > 1:
    max_t = len(tick_h) - 1
    scrub = st.slider("Rewind to tick", 0, max_t, max_t, key="scrubber",
                      help="Drag left to inspect any past tick")
    ra  = alert_h[scrub]
    rc  = corr_h[scrub] if corr_h else 1.0
    col = {"CRITICAL": "#ef4444", "ELEVATED": "#f59e0b", "NORMAL": "#22c55e"}[ra]
    _html(
        f"<div style='font-family:{MONO};font-size:0.72rem;"
        f"background:#111827;border:1px solid #1e293b;"
        f"border-left:3px solid {col};border-radius:8px;"
        f"padding:0.85rem 1.3rem;display:flex;gap:2rem;flex-wrap:wrap;"
        f"box-shadow:0 2px 8px rgba(0,0,0,0.3);'>"
        f"<span style='color:#475569;'>tick={tick_h[scrub]}</span>"
        f"<span style='color:{col};font-weight:700;'>{ra}</span>"
        f"<span style='color:#64748b;'>corr={rc:.3f}</span>"
        f"<span style='color:#3b82f6;'>cyber={cyber_h[scrub]:.3f}</span>"
        f"<span style='color:#10b981;'>physical={phys_h[scrub]:.3f}</span>"
        f"</div>"
    )
else:
    _html(
        f"<div style='font-family:{MONO};font-size:0.7rem;"
        f"color:#475569;padding:0.75rem;border:1px dashed #1e293b;"
        f"border-radius:8px;'>Timeline builds after 10+ ticks.</div>"
    )

# ── auto-refresh ──────────────────────────────────────────────
if st.session_state.running:
    time.sleep(st.session_state.refresh)
    safe_rerun()

"""
SENTINEL — Production Cyber-Physical Intelligence Platform
Run: streamlit run app.py   (from sentinel/ project root)
"""
from __future__ import annotations
import streamlit as st
import numpy as np
import time

st.set_page_config(
    page_title="SENTINEL",
    layout="wide",
    initial_sidebar_state="expanded"
)

from utils.style        import inject_css, init_state, safe_rerun
from engine.core        import InsightEngine
from components.metrics import render_metrics
from components.charts  import (
    render_anomaly_feed, render_correlation, render_gauge,
    render_ids_comparison, render_alert_heatmap,
    render_scatter_phase, render_score_histogram,
)
from components.logs    import render_alert_log, render_insight_panel
from components.nodes   import render_node_status, render_geo_map

inject_css()
init_state()

# ── sidebar ───────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <p style='font-family:JetBrains Mono,monospace;font-size:0.62rem;
    color:#1e40af;letter-spacing:0.12em;text-transform:uppercase;
    border-bottom:1px solid #0f172a;padding-bottom:0.65rem;
    margin-bottom:0.9rem;'>SENTINEL // Control Panel</p>
    """, unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    with c1:
        if st.button("RUN"):
            st.session_state.running = True
    with c2:
        if st.button("PAUSE"):
            st.session_state.running = False

    st.markdown("<div class='s-div'></div>", unsafe_allow_html=True)
    st.markdown("""
    <p style='font-family:JetBrains Mono,monospace;font-size:0.6rem;
    color:#1e293b;letter-spacing:0.08em;text-transform:uppercase;
    margin-bottom:0.45rem;'>Attack Scenarios</p>
    """, unsafe_allow_html=True)

    if st.button("COMPOUND ATTACK", type="primary"):
        st.session_state.injector.trigger("compound")
        st.session_state.log.append({
            "type": "event", "t": st.session_state.tick,
            "msg": "COMPOUND ATTACK INJECTED", "col": "#ef4444"
        })
    if st.button("CYBER-ONLY ATTACK"):
        st.session_state.injector.trigger("cyber_only")
        st.session_state.log.append({
            "type": "event", "t": st.session_state.tick,
            "msg": "CYBER-ONLY ATTACK INJECTED", "col": "#f59e0b"
        })
    if st.button("RESET SYSTEM"):
        st.session_state.engine.reset()
        for k in ("cyber_h","phys_h","corr_h","alert_h","tick_h","ids_log"):
            st.session_state[k].clear()
        st.session_state.history.clear()
        st.session_state.log.clear()
        st.session_state.tick = 0

    st.markdown("<div class='s-div'></div>", unsafe_allow_html=True)
    st.markdown("""
    <p style='font-family:JetBrains Mono,monospace;font-size:0.6rem;
    color:#1e293b;letter-spacing:0.08em;text-transform:uppercase;
    margin-bottom:0.45rem;'>Configuration</p>
    """, unsafe_allow_html=True)

    st.session_state.noise   = st.slider("Sensor noise",    0.01, 0.15, 0.04, 0.01)
    st.session_state.refresh = st.slider("Refresh rate (s)", 0.5,  3.0,  1.5,  0.5)

    st.markdown("<div class='s-div'></div>", unsafe_allow_html=True)
    st.markdown("""
    <div style='font-family:JetBrains Mono,monospace;font-size:0.63rem;
    color:#94a3b8;line-height:2.1;'>
    <span style='color:#64748b;'>DATASET</span><br>
    BATADAL_dataset03.csv<br>8761 rows · 45 cols<br><br>
    <span style='color:#64748b;'>PRIVACY</span><br>
    epsilon-DP · noise=1.1<br>epsilon=0.5 · delta=1e-5<br><br>
    <span style='color:#64748b;'>AGGREGATION</span><br>
    Multi-Krum · f=1<br><br>
    <span style='color:#64748b;'>CORRELATION</span><br>
    Pearson · window=20<br>normal &gt; 0.70 · crit &lt; 0.30
    </div>
    """, unsafe_allow_html=True)

# ── header ────────────────────────────────────────────────────
st.markdown("""
<div class="sentinel-header">
    <p class="sentinel-title">SENTINEL</p>
    <p class="sentinel-sub">
    Byzantine-Resilient Federated Anomaly Detection
    &nbsp;&middot;&nbsp;
    Cyber-Physical Critical Infrastructure Protection
    </p>
    <div class="sentinel-badge">
        <p style="color:#2563eb;font-size:0.63rem;margin:0;
        font-family:JetBrains Mono,monospace;letter-spacing:0.06em;">
        <span class='live-dot'></span> LIVE MONITORING</p>
        <p style="color:#94a3b8;font-size:0.6rem;margin:0.1rem 0 0;
        font-family:JetBrains Mono,monospace;letter-spacing:0.06em;">
        LIVE SIMULATION</p>
    </div>
</div>
""", unsafe_allow_html=True)
# ── tick ──────────────────────────────────────────────────────
def run_tick() -> None:
    t, noise = st.session_state.tick, st.session_state.noise
    np.random.seed(t % 9999)
    bc = float(np.clip(np.random.normal(0.14, noise), 0, 1))
    bp = float(np.clip(np.random.normal(0.14, noise), 0, 1))
    cyber, phys = st.session_state.injector.step(bc, bp)
    tk = st.session_state.engine.update(cyber, phys, t)
    st.session_state.cyber_h.append(cyber)
    st.session_state.phys_h.append(phys)
    st.session_state.alert_h.append(tk.alert)
    st.session_state.tick_h.append(t)
    corr = tk.correlation if tk.correlation is not None \
           else st.session_state.engine.current_corr
    st.session_state.corr_h.append(corr)
    st.session_state.ids_log.append(1 if tk.ids_flag else 0)
    st.session_state.history.append(tk)
    if tk.alert != "NORMAL":
        st.session_state.log.append({
            "type": "alert", "t": t, "alert": tk.alert,
            "corr": round(corr, 3), "cyber": round(cyber, 3),
            "phys": round(phys, 3),
        })
    st.session_state.tick += 1

if st.session_state.running:
    run_tick()

# ── state aliases ─────────────────────────────────────────────
eng     = st.session_state.engine
cyber_h = list(st.session_state.cyber_h)
phys_h  = list(st.session_state.phys_h)
corr_h  = list(st.session_state.corr_h)
alert_h = list(st.session_state.alert_h)
tick_h  = list(st.session_state.tick_h)
ids_log = list(st.session_state.ids_log)
cv      = cyber_h[-1] if cyber_h else 0.0
pv      = phys_h[-1]  if phys_h  else 0.0
crit_n  = sum(1 for a in alert_h if a == "CRITICAL")
ids_n   = sum(ids_log[-50:])

# ─────────────────────────────────────────────────────────────
# S1 — KPI STRIP
# ─────────────────────────────────────────────────────────────
render_metrics(
    alert=eng.current_alert, corr=eng.current_corr,
    cyber=cv, phys=pv, crit_count=crit_n,
    tick=st.session_state.tick, ids_count=ids_n,
)
st.markdown("<div class='s-div'></div>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# S2 — PRIMARY CHARTS
# ─────────────────────────────────────────────────────────────
l, r = st.columns([3, 2])
with l:
    st.markdown("<p class='sec-title'>Live Anomaly Score Feed — Cyber vs Physical Signal</p>",
                unsafe_allow_html=True)
    render_anomaly_feed(tick_h, cyber_h, phys_h, alert_h)
with r:
    st.markdown("<p class='sec-title'>Coupling Index — Pearson Correlation w=20</p>",
                unsafe_allow_html=True)
    render_correlation(tick_h, corr_h)
st.markdown("<div class='s-div'></div>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# S3 — IDS + GAUGE + LOG
# ─────────────────────────────────────────────────────────────
ca, cb, cc = st.columns([2, 1.5, 2])
with ca:
    st.markdown("<p class='sec-title'>SENTINEL vs Standard IDS — Detection Comparison</p>",
                unsafe_allow_html=True)
    render_ids_comparison(alert_h, ids_log)
with cb:
    st.markdown("<p class='sec-title'>Correlation Gauge</p>",
                unsafe_allow_html=True)
    render_gauge(eng.current_corr, eng.current_alert)
with cc:
    st.markdown("<p class='sec-title'>Alert Event Log</p>",
                unsafe_allow_html=True)
    render_alert_log(st.session_state.log)
st.markdown("<div class='s-div'></div>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# S4 — ADVANCED ANALYTICS
# ─────────────────────────────────────────────────────────────
st.markdown("""
<p style='font-family:JetBrains Mono,monospace;font-size:0.6rem;
color:#94a3b8;letter-spacing:0.12em;text-transform:uppercase;
margin-bottom:0.75rem;'>Advanced Analytics Layer</p>
""", unsafe_allow_html=True)

h_col, p_col = st.columns([3, 2])
with h_col:
    st.markdown("<p class='sec-title'>Alert Density Heatmap</p>",
                unsafe_allow_html=True)
    render_alert_heatmap(alert_h, tick_h)
with p_col:
    st.markdown("<p class='sec-title'>Phase-Space Scatter — Spoofing Signature</p>",
                unsafe_allow_html=True)
    render_scatter_phase(cyber_h, phys_h, alert_h)

d_col, i_col = st.columns([2, 3])
with d_col:
    st.markdown("<p class='sec-title'>Score Distribution Histogram</p>",
                unsafe_allow_html=True)
    render_score_histogram(cyber_h, phys_h)
with i_col:
    st.markdown("<p class='sec-title'>Intelligence Engine — Auto-Detected Patterns</p>",
                unsafe_allow_html=True)
    insights = InsightEngine(st.session_state.history).generate()
    render_insight_panel(insights)
st.markdown("<div class='s-div'></div>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# S5 — NODE STATUS
# ─────────────────────────────────────────────────────────────
st.markdown("<p class='sec-title'>Federated Node Status</p>",
            unsafe_allow_html=True)
render_node_status()
st.markdown("<div class='s-div'></div>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# S6 — GEOSPATIAL MAP
# ─────────────────────────────────────────────────────────────
st.markdown("<p class='sec-title'>Geospatial Intelligence Layer — Node Deployment Map</p>",
            unsafe_allow_html=True)
render_geo_map()
st.markdown("<div class='s-div'></div>", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────
# S7 — TIMELINE SCRUBBER
# ─────────────────────────────────────────────────────────────
st.markdown("<p class='sec-title'>Attack Timeline Replay</p>",
            unsafe_allow_html=True)
if len(tick_h) > 1:
    max_t = len(tick_h) - 1
    scrub = st.slider("Rewind to tick", 0, max_t, max_t, key="scrubber",
                      help="Drag left to inspect any past tick")
    ra = alert_h[scrub]
    rc = corr_h[scrub] if corr_h else 1.0
    col = {"CRITICAL":"#ef4444","ELEVATED":"#f59e0b","NORMAL":"#22c55e"}[ra]
    st.markdown(f"""
    <div style='font-family:JetBrains Mono,monospace;font-size:0.72rem;
    background:#111827;border:1px solid #1e293b;
    border-left:3px solid {col};border-radius:8px;
    padding:0.85rem 1.3rem;display:flex;gap:2rem;flex-wrap:wrap;
    box-shadow:0 1px 4px rgba(0,0,0,0.04);'>
        <span style='color:#94a3b8;'>tick={tick_h[scrub]}</span>
        <span style='color:{col};font-weight:700;'>{ra}</span>
        <span style='color:#64748b;'>corr={rc:.3f}</span>
        <span style='color:#2563eb;'>cyber={cyber_h[scrub]:.3f}</span>
        <span style='color:#059669;'>physical={phys_h[scrub]:.3f}</span>
    </div>""", unsafe_allow_html=True)
else:
    st.markdown("""
    <div style='font-family:JetBrains Mono,monospace;font-size:0.7rem;
    color:#1e293b;padding:0.75rem;border:1px dashed #0f172a;
    border-radius:8px;'>Timeline builds after 10+ ticks.</div>
    """, unsafe_allow_html=True)

# ── auto-refresh ──────────────────────────────────────────────
if st.session_state.running:
    time.sleep(st.session_state.refresh)
    safe_rerun()

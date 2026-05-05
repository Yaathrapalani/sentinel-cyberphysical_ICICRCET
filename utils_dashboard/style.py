"""utils/style.py — CSS injection + session state bootstrap. Dark SOC theme."""
from __future__ import annotations
import streamlit as st
from collections import deque
from engine.core import CorrelationEngine, AttackInjector

CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Inter:wght@300;400;500;600&display=swap');

html, body, [class*="css"], .stApp {
    font-family: 'Inter', sans-serif;
    background: #0a0f1e;
    color: #e2e8f0;
}
.block-container { padding: 1.1rem 1.8rem 2rem; }

::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-track { background: #0f172a; }
::-webkit-scrollbar-thumb { background: #334155; border-radius: 2px; }

.sec-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.63rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.13em;
    border-left: 2px solid #3b82f6;
    padding-left: 0.6rem;
    margin: 0 0 0.65rem;
    line-height: 1;
}

.sentinel-header {
    background: linear-gradient(135deg, #0f172a 0%, #111827 100%);
    border: 1px solid #1e293b;
    border-radius: 12px;
    padding: 1.35rem 1.8rem;
    margin-bottom: 1.2rem;
    position: relative;
    overflow: hidden;
    box-shadow: 0 2px 12px rgba(0,0,0,0.4), 0 0 1px rgba(59,130,246,0.15);
}
.sentinel-header::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0; height: 2px;
    background: linear-gradient(90deg,
        transparent 0%, #3b82f6 30%,
        #60a5fa 50%, #3b82f6 70%, transparent 100%);
    animation: headerGlow 3s ease-in-out infinite;
}
@keyframes headerGlow {
    0%,100% { opacity: 0.7; }
    50% { opacity: 1; }
}
.sentinel-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 1.75rem;
    font-weight: 700;
    color: #60a5fa;
    margin: 0;
    letter-spacing: 0.08em;
}
.sentinel-sub {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    color: #64748b;
    margin: 0.25rem 0 0;
    letter-spacing: 0.05em;
}
.sentinel-badge {
    position: absolute;
    right: 1.6rem; top: 50%;
    transform: translateY(-50%);
    text-align: right;
    font-family: 'JetBrains Mono', monospace;
}

.s-div {
    height: 1px;
    background: linear-gradient(90deg,
        transparent, #1e293b 25%, #1e293b 75%, transparent);
    margin: 1.1rem 0;
}

[data-testid="stSidebar"] {
    background: #0f172a;
    border-right: 1px solid #1e293b;
}
[data-testid="stSidebar"] .block-container {
    padding: 1.2rem 1rem;
}
[data-testid="stSidebar"] p,
[data-testid="stSidebar"] span,
[data-testid="stSidebar"] div,
[data-testid="stSidebar"] label {
    color: #94a3b8 !important;
}

.stButton > button {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.72rem !important;
    letter-spacing: 0.05em !important;
    border-radius: 7px !important;
    transition: all 0.2s ease !important;
    width: 100% !important;
    background: #111827 !important;
    color: #94a3b8 !important;
    border: 1px solid #1e293b !important;
}
.stButton > button:hover {
    background: #1e293b !important;
    border-color: #3b82f6 !important;
    color: #60a5fa !important;
    box-shadow: 0 0 12px rgba(59,130,246,0.15) !important;
}

.js-plotly-plot .plotly .bg { fill: transparent !important; }

/* Pulse animation for live indicators */
@keyframes livePulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}
.live-dot {
    display: inline-block;
    width: 6px; height: 6px;
    background: #22c55e;
    border-radius: 50%;
    animation: livePulse 2s ease-in-out infinite;
    margin-right: 6px;
    vertical-align: middle;
}

/* Tabs styling */
.stTabs [data-baseweb="tab-list"] {
    background: #0f172a;
    border-bottom: 1px solid #1e293b;
}
.stTabs [data-baseweb="tab"] {
    color: #64748b !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.7rem !important;
}
.stTabs [aria-selected="true"] {
    color: #60a5fa !important;
    border-bottom-color: #3b82f6 !important;
}

/* Dataframe styling */
.stDataFrame {
    border: 1px solid #1e293b !important;
    border-radius: 8px !important;
}
</style>
"""

def inject_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def init_state() -> None:
    if "ready" in st.session_state:
        return
    st.session_state.engine   = CorrelationEngine()
    st.session_state.injector = AttackInjector()
    st.session_state.cyber_h  = deque(maxlen=160)
    st.session_state.phys_h   = deque(maxlen=160)
    st.session_state.corr_h   = deque(maxlen=160)
    st.session_state.alert_h  = deque(maxlen=160)
    st.session_state.tick_h   = deque(maxlen=160)
    st.session_state.ids_log  = deque(maxlen=160)
    st.session_state.history  = []
    st.session_state.log      = []
    st.session_state.tick     = 0
    st.session_state.running  = True
    st.session_state.noise    = 0.04
    st.session_state.refresh  = 1.5
    st.session_state.ready    = True


def safe_rerun() -> None:
    try:
        st.rerun()
    except AttributeError:
        st.experimental_rerun()

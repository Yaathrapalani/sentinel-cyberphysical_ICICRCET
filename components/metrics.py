"""components/metrics.py — KPI strip. Dark SOC theme.
All HTML built via parenthesized f-strings (zero indentation)."""
from __future__ import annotations
import streamlit as st

MONO = "JetBrains Mono, monospace"
AC   = {"CRITICAL": "#dc2626", "ELEVATED": "#d97706", "NORMAL": "#16a34a"}


def _card(value: str, label: str, color: str,
          border: str, sub: str = "") -> str:
    sub_html = ""
    if sub:
        sub_html = (
            f"<p style='font-size:0.58rem;color:#64748b;"
            f"margin:0.2rem 0 0;letter-spacing:0.04em;'>{sub}</p>"
        )
    return (
        f"<div style='background:#0f172a;border:1px solid #1e293b;"
        f"border-top:2px solid {border};border-radius:10px;"
        f"padding:1.1rem 1rem;text-align:center;"
        f"box-shadow:0 2px 8px rgba(0,0,0,0.3),0 0 1px {border}25;'>"
        f"<p style='font-family:{MONO};font-size:1.5rem;font-weight:700;"
        f"color:{color};margin:0;letter-spacing:0.03em;'>{value}</p>"
        f"<p style='font-size:0.6rem;color:#64748b;text-transform:uppercase;"
        f"letter-spacing:0.1em;margin:0.25rem 0 0;"
        f"font-family:{MONO};'>{label}</p>"
        f"{sub_html}</div>"
    )


def render_metrics(alert: str, corr: float, cyber: float, phys: float,
                   crit_count: int, tick: int, ids_count: int) -> None:
    cols = st.columns(6)
    cc = "#ef4444" if corr < 0.3 else "#f59e0b" if corr < 0.7 else "#22c55e"
    cb = "#7f1d1d" if corr < 0.3 else "#78350f" if corr < 0.7 else "#14532d"
    data = [
        (alert, "Alert State", AC[alert], AC[alert], ""),
        (f"{corr:.3f}", "Correlation Index", cc, cb, ""),
        (f"{cyber:.3f}", "Cyber Score",
         "#ef4444" if cyber > 0.6 else "#94a3b8", "#334155", ""),
        (f"{phys:.3f}", "Physical Score",
         "#ef4444" if phys > 0.6 else "#94a3b8", "#334155", ""),
        (str(crit_count), "Critical Alerts",
         "#ef4444" if crit_count > 0 else "#94a3b8",
         "#7f1d1d" if crit_count > 0 else "#334155", "session total"),
        (str(ids_count), "IDS Detections", "#94a3b8", "#334155", "standard · last 50"),
    ]
    for col, (v, l, c, b, s) in zip(cols, data):
        with col:
            st.markdown(_card(v, l, c, b, s), unsafe_allow_html=True)

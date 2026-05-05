"""components/logs.py — alert log + insight panel."""
from __future__ import annotations
import streamlit as st

MONO = "JetBrains Mono, monospace"
AC   = {"CRITICAL": "#ef4444", "ELEVATED": "#f59e0b", "NORMAL": "#22c55e"}


def render_alert_log(log: list) -> None:
    if not log:
        st.markdown(f"""
        <div style='font-family:{MONO};font-size:0.7rem;color:#1e293b;
        padding:1.1rem;text-align:center;border:1px dashed #1e293b;
        border-radius:8px;line-height:2;'>
            No alerts detected<br>
            <span style='color:#14532d;font-size:0.65rem;'>
            System operating normally</span>
        </div>""", unsafe_allow_html=True)
        return

    for e in list(reversed(log))[:8]:
        if e.get("type") == "alert":
            a   = e["alert"]
            col = AC.get(a, "#22c55e")
            st.markdown(f"""
            <div style='font-family:{MONO};font-size:0.69rem;
            padding:0.52rem 0.85rem;border-radius:6px;
            margin-bottom:0.28rem;background:#070c18;
            border:1px solid #0f172a;border-left:3px solid {col};'>
                <span style='color:{col};font-weight:700;
                min-width:68px;display:inline-block;'>{a}</span>
                <span style='color:#334155;'>t={e["t"]}</span>
                <span style='color:#1e293b;'>
                &nbsp;·&nbsp;corr={e["corr"]}
                &nbsp;·&nbsp;cy={e["cyber"]}
                &nbsp;·&nbsp;ph={e["phys"]}</span>
            </div>""", unsafe_allow_html=True)
        elif e.get("type") == "event":
            col = e.get("col", "#64748b")
            st.markdown(f"""
            <div style='font-family:{MONO};font-size:0.69rem;
            padding:0.52rem 0.85rem;border-radius:6px;
            margin-bottom:0.28rem;background:#070c18;
            border:1px solid #0f172a;border-left:3px solid {col};'>
                <span style='color:{col};font-weight:700;'>{e["msg"]}</span>
                <span style='color:#334155;'>&nbsp;·&nbsp;t={e["t"]}</span>
            </div>""", unsafe_allow_html=True)


def render_insight_panel(insights: list) -> None:
    if not insights:
        st.markdown(f"""
        <div style='font-family:{MONO};font-size:0.7rem;
        color:#1e293b;padding:1rem 1.1rem;
        border:1px dashed #1e293b;border-radius:8px;line-height:1.8;'>
            Intelligence engine monitoring...<br>
            <span style='color:#0f172a;'>
            No anomalous patterns detected.</span>
        </div>""", unsafe_allow_html=True)
        return

    for ins in insights:
        col = AC.get(ins.severity, "#22c55e")
        delta_html = (
            f"<span style='color:{col};'>delta={ins.corr_delta:+.3f}</span>&nbsp;"
            if ins.corr_delta else ""
        )
        st.markdown(f"""
        <div style='font-family:{MONO};
        background:linear-gradient(135deg,#070c18 0%,#0a0f1e 100%);
        border:1px solid {col}28;border-left:3px solid {col};
        border-radius:8px;padding:0.9rem 1.1rem;margin-bottom:0.5rem;
        box-shadow:0 0 22px {col}0e;'>
            <p style='color:{col};font-size:0.75rem;font-weight:700;
            margin:0 0 0.35rem;'>{ins.label}</p>
            <p style='color:#475569;font-size:0.68rem;
            line-height:1.6;margin:0;'>{ins.description}</p>
            <p style='color:#1e293b;font-size:0.62rem;margin:0.45rem 0 0;'>
            {delta_html}t={ins.tick}</p>
        </div>""", unsafe_allow_html=True)

"""
components/charts.py
=====================
Dark SOC theme — all chart backgrounds are transparent/dark.
_base() NEVER contains 'height'.
Every chart does: layout = _base(...); layout["height"] = N; fig.update_layout(**layout)
All st.plotly_chart calls use key= for dedup. No use_container_width.
"""
from __future__ import annotations
import numpy as np
import plotly.graph_objects as go
import streamlit as st
from typing import Optional

BG   = "rgba(0,0,0,0)"
GRID = "#1e293b"
FC   = "#64748b"
MONO = "JetBrains Mono, monospace"

AC = {"CRITICAL": "#dc2626", "ELEVATED": "#d97706", "NORMAL": "#16a34a"}


# ─────────────────────────────────────────────────────────────
# BASE LAYOUT  —  NO HEIGHT HERE. EVER.
# ─────────────────────────────────────────────────────────────
def _base(title: str, yr: Optional[list] = None) -> dict:
    return dict(
        title=dict(
            text=title,
            font=dict(family=MONO, size=10, color="#64748b"),
            x=0, xanchor="left", pad=dict(l=0, t=4)
        ),
        paper_bgcolor=BG,
        plot_bgcolor="rgba(10,15,30,0.4)",
        margin=dict(l=48, r=16, t=42, b=32),
        font=dict(family=MONO, size=9, color=FC),
        xaxis=dict(
            showgrid=True, gridcolor=GRID, gridwidth=1,
            zeroline=False, showline=False,
            tickfont=dict(size=8, color="#475569"),
            tickcolor="#334155",
        ),
        yaxis=dict(
            showgrid=True, gridcolor=GRID, gridwidth=1,
            zeroline=False, showline=False,
            tickfont=dict(size=8, color="#475569"),
            range=yr,
        ),
        legend=dict(
            bgcolor="rgba(15,23,42,0.92)",
            font=dict(size=8, family=MONO, color="#94a3b8"),
            x=0.01, y=0.99,
            bordercolor="#1e293b",
            borderwidth=1,
        ),
        hovermode="x unified",
        hoverlabel=dict(
            bgcolor="#0f172a",
            font=dict(family=MONO, size=9, color="#e2e8f0"),
            bordercolor="#334155",
        ),
    )


# ─────────────────────────────────────────────────────────────
# 1. LIVE ANOMALY FEED
# ─────────────────────────────────────────────────────────────
def render_anomaly_feed(tick_h: list, cyber_h: list,
                        phys_h: list, alert_h: list) -> None:
    fig = go.Figure()

    # attack shading
    if tick_h and alert_h:
        in_atk, start = False, None
        for i, a in enumerate(alert_h):
            if a == "CRITICAL" and not in_atk:
                start, in_atk = tick_h[i], True
            elif a != "CRITICAL" and in_atk and start is not None:
                fig.add_vrect(x0=start, x1=tick_h[i - 1],
                              fillcolor="rgba(220,38,38,0.08)",
                              layer="below", line_width=0)
                in_atk = False
        if in_atk and start is not None and tick_h:
            fig.add_vrect(x0=start, x1=tick_h[-1],
                          fillcolor="rgba(59,130,246,0.10)",
                          layer="below", line_width=0)

    # moving average
    if len(cyber_h) >= 10:
        ma   = np.convolve(cyber_h, np.ones(10) / 10, mode="valid")
        ma_x = tick_h[9: 9 + len(ma)]
        if len(ma_x) == len(ma):
            fig.add_trace(go.Scatter(
                x=ma_x, y=list(ma), name="MA(10)",
                line=dict(color="#1d4ed8", width=1, dash="dot"),
                opacity=0.5, hoverinfo="skip"
            ))

    fig.add_trace(go.Scatter(
        x=tick_h, y=cyber_h, name="Cyber",
        line=dict(color="#3b82f6", width=2),
        fill="tozeroy", fillcolor="rgba(59,130,246,0.08)",
        hovertemplate="cyber=%{y:.4f}<extra></extra>"
    ))
    fig.add_trace(go.Scatter(
        x=tick_h, y=phys_h, name="Physical",
        line=dict(color="#10b981", width=2),
        fill="tozeroy", fillcolor="rgba(16,185,129,0.06)",
        hovertemplate="phys=%{y:.4f}<extra></extra>"
    ))

    fig.add_hline(y=0.5,
                  line=dict(color="#f59e0b", width=1, dash="dot"),
                  annotation_text="IDS 0.5",
                  annotation_font=dict(size=8, color="#f59e0b"),
                  annotation_position="bottom right")
    fig.add_hrect(y0=0.75, y1=1.0,
                  fillcolor="rgba(239,68,68,0.06)",
                  layer="below", line_width=0)

    layout = _base("anomaly_scores.live", yr=[0, 1.05])
    layout["height"] = 268
    fig.update_layout(**layout)
    st.plotly_chart(fig, key="chart_anomaly_feed",
                    config={"displayModeBar": False})


# ─────────────────────────────────────────────────────────────
# 2. CORRELATION INDEX
# ─────────────────────────────────────────────────────────────
def render_correlation(tick_h: list, corr_h: list) -> None:
    fig = go.Figure()

    if corr_h and tick_h:
        dot_colors = [
            "#ef4444" if c < 0.3 else "#f59e0b" if c < 0.7 else "#22c55e"
            for c in corr_h
        ]
        fig.add_trace(go.Scatter(
            x=tick_h, y=corr_h, mode="markers",
            marker=dict(color=dot_colors, size=4, opacity=0.4),
            showlegend=False, hoverinfo="skip"
        ))

    fig.add_trace(go.Scatter(
        x=tick_h, y=corr_h, name="Correlation",
        line=dict(color="#a78bfa", width=2.5),
        fill="tozeroy", fillcolor="rgba(167,139,250,0.06)",
        hovertemplate="corr=%{y:.4f}<extra></extra>"
    ))

    fig.add_hrect(y0=0, y1=0.3,
                  fillcolor="rgba(239,68,68,0.06)",
                  layer="below", line_width=0,
                  annotation_text="CRITICAL ZONE",
                  annotation_font=dict(size=7, color="#ef4444"),
                  annotation_position="top left")
    fig.add_hline(y=0.7,
                  line=dict(color="#22c55e", width=1, dash="dash"),
                  annotation_text="normal",
                  annotation_font=dict(size=8, color="#22c55e"),
                  annotation_position="bottom right")
    fig.add_hline(y=0.3,
                  line=dict(color="#ef4444", width=1, dash="dash"),
                  annotation_text="critical",
                  annotation_font=dict(size=8, color="#ef4444"),
                  annotation_position="top right")

    layout = _base("coupling_correlation.live", yr=[-0.15, 1.15])
    layout["height"] = 268
    fig.update_layout(**layout)
    st.plotly_chart(fig, key="chart_correlation",
                    config={"displayModeBar": False})


# ─────────────────────────────────────────────────────────────
# 3. GAUGE
# ─────────────────────────────────────────────────────────────
def render_gauge(corr: float, alert: str) -> None:
    bar_c = AC.get(alert, "#22c55e")
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=round(corr, 3),
        delta=dict(reference=0.7,
                   font=dict(family=MONO, size=11),
                   decreasing=dict(color="#ef4444"),
                   increasing=dict(color="#22c55e")),
        number=dict(font=dict(family=MONO, size=22, color="#e2e8f0"),
                    valueformat=".3f"),
        gauge=dict(
            axis=dict(range=[0, 1], tickwidth=1,
                      tickcolor="#334155",
                      tickfont=dict(size=8, family=MONO, color="#475569")),
            bar=dict(color=bar_c, thickness=0.22),
            bgcolor="#0a0f1e",
            borderwidth=1, bordercolor="#1e293b",
            steps=[
                dict(range=[0.0, 0.3], color="rgba(239,68,68,0.13)"),
                dict(range=[0.3, 0.7], color="rgba(245,158,11,0.07)"),
                dict(range=[0.7, 1.0], color="rgba(34,197,94,0.07)")
            ],
            threshold=dict(
                line=dict(color="#ef4444", width=2),
                thickness=0.75, value=0.3)
        )
    ))
    fig.update_layout(
        paper_bgcolor=BG,
        plot_bgcolor="rgba(10,15,30,0)",
        font=dict(family=MONO, color="#475569"),
        margin=dict(l=16, r=16, t=20, b=8),
        height=238
    )
    st.plotly_chart(fig, key="chart_gauge",
                    config={"displayModeBar": False})


# ─────────────────────────────────────────────────────────────
# 4. IDS COMPARISON BAR
# ─────────────────────────────────────────────────────────────
def render_ids_comparison(alert_h: list, ids_log: list) -> None:
    last  = min(50, len(alert_h))
    s_det = sum(1 for a in alert_h[-last:] if a == "CRITICAL")
    i_det = sum(ids_log[-last:])

    fig = go.Figure()
    fig.add_trace(go.Bar(
        x=["Standard IDS", "SENTINEL"],
        y=[i_det, s_det],
        marker=dict(color=["#1e293b", "#1d4ed8"],
                    line=dict(color=["#334155", "#3b82f6"], width=1),
                    cornerradius=6),
        text=[str(i_det), str(s_det)],
        textposition="outside",
        textfont=dict(family=MONO, size=14, color="#e2e8f0"),
        width=0.48
    ))
    if s_det > i_det:
        fig.add_annotation(
            x="SENTINEL", y=s_det,
            text=f"+{s_det - i_det} compound",
            showarrow=True, arrowhead=2,
            arrowcolor="#a78bfa",
            font=dict(size=8, color="#a78bfa", family=MONO),
            yshift=16
        )

    layout = _base("critical_detections.last_50_ticks")
    layout["height"]     = 242
    layout["showlegend"] = False
    layout["yaxis"]      = dict(showgrid=True, gridcolor=GRID,
                                 range=[0, max(i_det, s_det, 1) + 5],
                                 tickfont=dict(size=8, color="#475569"))
    fig.update_layout(**layout)
    st.plotly_chart(fig, key="chart_ids_comparison",
                    config={"displayModeBar": False})


# ─────────────────────────────────────────────────────────────
# 5. ALERT HEATMAP
# ─────────────────────────────────────────────────────────────
def render_alert_heatmap(alert_h: list, tick_h: list) -> None:
    if len(alert_h) < 20:
        return
    encoded = [2 if a == "CRITICAL" else 1 if a == "ELEVATED" else 0
               for a in alert_h]
    n = (len(encoded) // 20) * 20
    if n == 0:
        return
    mat = np.array(encoded[:n]).reshape(-1, 20)

    fig = go.Figure(go.Heatmap(
        z=mat,
        colorscale=[[0.0, "#070c18"], [0.5, "#7c2d12"], [1.0, "#dc2626"]],
        showscale=False,
        hovertemplate="row=%{y} col=%{x}<br>severity=%{z}<extra></extra>"
    ))

    layout = _base("alert_density.heatmap")
    layout["height"] = 145
    layout["margin"] = dict(l=10, r=10, t=36, b=8)
    layout["xaxis"]  = dict(showgrid=False, zeroline=False,
                             showticklabels=False)
    layout["yaxis"]  = dict(showgrid=False, zeroline=False,
                             showticklabels=False)
    fig.update_layout(**layout)
    st.plotly_chart(fig, key="chart_heatmap",
                    config={"displayModeBar": False})


# ─────────────────────────────────────────────────────────────
# 6. PHASE-SPACE SCATTER
# ─────────────────────────────────────────────────────────────
def render_scatter_phase(cyber_h: list, phys_h: list,
                         alert_h: list) -> None:
    if len(cyber_h) < 5:
        return
    colors = [AC.get(a, "#22c55e") for a in alert_h]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=cyber_h, y=phys_h, mode="markers",
        marker=dict(color=colors, size=5, opacity=0.72,
                    line=dict(width=0)),
        hovertemplate="cy=%{x:.3f}<br>ph=%{y:.3f}<extra></extra>"
    ))

    fig.add_shape(type="rect", x0=0.6, y0=0.0, x1=1.0, y1=0.25,
                  fillcolor="rgba(239,68,68,0.07)",
                  line=dict(color="#ef4444", width=1, dash="dot"))
    fig.add_annotation(x=0.8, y=0.12, text="COMPOUND<br>ZONE",
                       showarrow=False,
                       font=dict(size=7, color="#ef4444", family=MONO))

    fig.add_shape(type="rect", x0=0.0, y0=0.0, x1=0.35, y1=0.35,
                  fillcolor="rgba(34,197,94,0.05)",
                  line=dict(color="#22c55e", width=1, dash="dot"))
    fig.add_annotation(x=0.17, y=0.17, text="NORMAL<br>ZONE",
                       showarrow=False,
                       font=dict(size=7, color="#22c55e", family=MONO))

    layout = _base("phase_space.cyber_vs_physical", yr=[-0.05, 1.05])
    layout["height"]     = 252
    layout["showlegend"] = False
    layout["xaxis"]      = dict(
        showgrid=True, gridcolor=GRID, zeroline=False,
        tickfont=dict(size=8, color="#475569"), range=[-0.05, 1.05],
        title=dict(text="Cyber Score",
                   font=dict(size=8, family=MONO, color=FC)))
    layout["yaxis"]      = dict(
        showgrid=True, gridcolor=GRID, zeroline=False,
        tickfont=dict(size=8, color="#475569"), range=[-0.05, 1.05],
        title=dict(text="Physical Score",
                   font=dict(size=8, family=MONO, color=FC)))
    fig.update_layout(**layout)
    st.plotly_chart(fig, key="chart_phase_scatter",
                    config={"displayModeBar": False})


# ─────────────────────────────────────────────────────────────
# 7. SCORE HISTOGRAM
# ─────────────────────────────────────────────────────────────
def render_score_histogram(cyber_h: list, phys_h: list) -> None:
    if len(cyber_h) < 20:
        return

    fig = go.Figure()
    fig.add_trace(go.Histogram(
        x=cyber_h, name="Cyber",
        marker_color="rgba(59,130,246,0.75)",
        xbins=dict(start=0, end=1, size=0.05),
        opacity=0.8
    ))
    fig.add_trace(go.Histogram(
        x=phys_h, name="Physical",
        marker_color="rgba(16,185,129,0.75)",
        xbins=dict(start=0, end=1, size=0.05),
        opacity=0.8
    ))

    layout = _base("score_distribution.session")
    layout["height"]  = 202
    layout["barmode"] = "overlay"
    layout["bargap"]  = 0.04
    layout["xaxis"]   = dict(
        showgrid=True, gridcolor=GRID, zeroline=False,
        tickfont=dict(size=8, color="#475569"),
        title=dict(text="Score", font=dict(size=8, family=MONO, color=FC))
    )
    fig.update_layout(**layout)
    st.plotly_chart(fig, key="chart_score_histogram",
                    config={"displayModeBar": False})

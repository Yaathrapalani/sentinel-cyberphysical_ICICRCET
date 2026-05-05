"""components/defense.py — Attack nullification, forensic timeline,
system state banner, node localization, evaluation, logs viewer.
All HTML strings are left-aligned (no indentation) to prevent
Streamlit markdown parser from treating them as code blocks."""
from __future__ import annotations
import streamlit as st
import pandas as pd

MONO = "JetBrains Mono, monospace"

STATE_COLORS = {
    "NORMAL":       ("#22c55e", "#052e16", "✅"),
    "ALERT":        ("#f59e0b", "#451a03", "⚠️"),
    "DEFENSE_MODE": ("#ef4444", "#450a0a", "🛡️"),
    "SECURE_MODE":  ("#06b6d4", "#083344", "🔒"),
}

SEVERITY_COLOR = {
    "LOW": "#22c55e", "MEDIUM": "#f59e0b", "HIGH": "#ef4444", "CRITICAL": "#ef4444"
}

ACTION_ICONS = {
    "isolate_node":       "🔌 ISOLATE",
    "block_traffic":      "🚫 BLOCK",
    "freeze_actuator":    "❄️ FREEZE",
    "emergency_shutdown": "🔴 SHUTDOWN",
}


def _html(s: str) -> None:
    """Render HTML via st.markdown, stripping leading whitespace."""
    st.markdown(s, unsafe_allow_html=True)


def render_system_state_banner(state: str, tick: int) -> None:
    col, bg, icon = STATE_COLORS.get(state, ("#94a3b8", "#1e293b", "ℹ️"))
    pulse = "animation:pulse 1.2s infinite;" if state in ("ALERT", "DEFENSE_MODE") else ""
    html = (
        "<style>@keyframes pulse{0%,100%{opacity:1;}50%{opacity:0.6;}}</style>"
        f"<div style='background:{bg};border:2px solid {col};border-radius:10px;"
        f"padding:0.9rem 1.4rem;margin-bottom:0.6rem;display:flex;"
        f"align-items:center;justify-content:space-between;{pulse}'>"
        f"<div>"
        f"<span style='font-family:{MONO};font-size:1.3rem;"
        f"font-weight:700;color:{col};letter-spacing:0.08em;'>"
        f"{icon} SYSTEM STATE: {state}</span><br>"
        f"<span style='font-family:{MONO};font-size:0.62rem;"
        f"color:#94a3b8;'>tick={tick} &nbsp;|&nbsp; SENTINEL Autonomous Defense</span>"
        f"</div>"
        f"<div style='text-align:right;'>"
        f"<span style='font-family:{MONO};font-size:0.58rem;"
        f"color:{col};letter-spacing:0.1em;text-transform:uppercase;'>"
        f"<span class='live-dot'></span> ACTIVE</span>"
        f"</div></div>"
    )
    _html(html)


def render_attack_nullification_panel(actions_log: list,
                                      attack_type: str,
                                      node_id: str,
                                      system_state: str) -> None:
    col, _, icon = STATE_COLORS.get(system_state, ("#94a3b8", "#1e293b", "ℹ️"))
    if not actions_log:
        _html(
            f"<div style='font-family:{MONO};font-size:0.7rem;color:#475569;"
            f"padding:1rem;border:1px dashed #334155;border-radius:8px;"
            f"text-align:center;'>No containment actions executed yet.</div>"
        )
        return

    _html(
        f"<div style='font-family:{MONO};font-size:0.62rem;color:#94a3b8;"
        f"letter-spacing:0.1em;text-transform:uppercase;margin-bottom:0.5rem;'>"
        f"⚡ Active Mitigation: <span style='color:{col};'>{attack_type}</span>"
        f" → <span style='color:#f59e0b;'>{node_id}</span></div>"
    )

    for action in list(reversed(actions_log))[:6]:
        a_label = action.action if hasattr(action, 'action') else action.get('action', '')
        n_id    = action.node_id if hasattr(action, 'node_id') else action.get('node_id', '')
        ts      = action.timestamp if hasattr(action, 'timestamp') else action.get('timestamp', '')
        detail  = action.detail if hasattr(action, 'detail') else action.get('detail', '')
        icon_s  = ACTION_ICONS.get(a_label, "⚙️ ACTION")
        a_col   = ("#ef4444" if "shutdown" in a_label else
                   "#f59e0b" if "freeze" in a_label else
                   "#06b6d4" if "block" in a_label else "#a78bfa")
        _html(
            f"<div style='background:#0a0f1e;border:1px solid #1e293b;"
            f"border-left:3px solid {a_col};border-radius:7px;"
            f"padding:0.5rem 0.85rem;margin-bottom:0.3rem;"
            f"font-family:{MONO};font-size:0.69rem;'>"
            f"<span style='color:{a_col};font-weight:700;'>{icon_s}</span>"
            f" &nbsp; <span style='color:#94a3b8;'>node={n_id}</span>"
            f" · <span style='color:#475569;'>{ts}</span><br>"
            f"<span style='color:#334155;font-size:0.62rem;'>{detail}</span>"
            f"</div>"
        )


def render_node_localization_panel(node_statuses: list,
                                   primary_node: str) -> None:
    risk_colors = {
        "ONLINE":      "#22c55e",
        "ALERT":       "#f59e0b",
        "COMPROMISED": "#ef4444",
        "ISOLATED":    "#a78bfa",
    }
    cols = st.columns(3)
    for cel, ns in zip(cols, node_statuses):
        with cel:
            rc = risk_colors.get(ns.state, "#94a3b8")
            is_primary = ns.node_id == primary_node
            bdr = f"2px solid {rc}" if is_primary else f"1px solid {rc}22"
            bar_w = int(ns.risk_score * 100)
            comps = ", ".join(ns.affected_components) if ns.affected_components else "—"
            badge = ""
            if is_primary and ns.state in ("COMPROMISED", "ALERT"):
                badge = (
                    f"<span style='background:#7c2d12;color:#fca5a5;"
                    f"font-size:0.55rem;padding:0.1rem 0.35rem;"
                    f"border-radius:3px;'>PRIMARY TARGET</span>"
                )
            html = (
                f"<div style='background:#070c18;border:{bdr};border-radius:9px;"
                f"padding:0.85rem;font-family:{MONO};font-size:0.68rem;line-height:1.9;'>"
                f"<div style='display:flex;justify-content:space-between;align-items:center;margin-bottom:0.3rem;'>"
                f"<span style='color:{rc};font-weight:700;font-size:0.78rem;'>{ns.node_id}</span>"
                f"{badge}</div>"
                f"<span style='color:#475569;'>{ns.state}</span><br>"
                f"<span style='color:#334155;font-size:0.6rem;'>risk: </span>"
                f"<span style='color:{rc};font-weight:700;'>{ns.risk_score:.3f}</span><br>"
                f"<div style='background:#1e293b;border-radius:3px;height:4px;margin:0.3rem 0;'>"
                f"<div class='risk-bar-fill' style='background:{rc};width:{bar_w}%;height:4px;border-radius:3px;'></div>"
                f"</div>"
                f"<span style='color:#475569;font-size:0.6rem;'>affected: {comps}</span>"
                f"</div>"
            )
            _html(html)


def render_forensic_timeline(events: list) -> None:
    if not events:
        _html(
            f"<div style='font-family:{MONO};font-size:0.7rem;color:#475569;"
            f"padding:1rem;border:1px dashed #334155;border-radius:8px;"
            f"text-align:center;'>Forensic timeline builds when events occur.</div>"
        )
        return

    for e in list(reversed(events))[:20]:
        sev = e.get("severity", "INFO")
        sc  = SEVERITY_COLOR.get(sev, "#94a3b8")
        sha_short = e.get("sha256", "")[:16] + "..."
        ts = e.get("timestamp", "")
        evt = e.get("event_type", "")
        nid = e.get("node_id", "")
        det = e.get("detail", "")[:70]
        _html(
            f"<div style='background:#070c18;border:1px solid #0f172a;"
            f"border-left:3px solid {sc};border-radius:6px;"
            f"padding:0.4rem 0.8rem;margin-bottom:0.2rem;"
            f"font-family:{MONO};font-size:0.62rem;line-height:1.7;'>"
            f"<span style='color:{sc};font-weight:700;'>[{sev}]</span>"
            f" <span style='color:#475569;'>{ts}</span>"
            f" · <span style='color:#94a3b8;'>{evt}</span>"
            f" · <span style='color:#64748b;'>node={nid}</span><br>"
            f"<span style='color:#334155;'>{det}</span><br>"
            f"<span style='color:#1e293b;font-size:0.56rem;'>sha256: {sha_short}</span>"
            f"</div>"
        )


def render_evaluation_panel(metrics: dict) -> None:
    if not metrics:
        _html(
            f"<div style='font-family:{MONO};font-size:0.7rem;color:#475569;"
            f"padding:1rem;border:1px dashed #334155;border-radius:8px;"
            f"text-align:center;'>Run demo or inject attack to compute metrics.</div>"
        )
        return

    kpis = [
        ("Precision", metrics.get("precision", 0), "#3b82f6"),
        ("Recall",    metrics.get("recall", 0),    "#10b981"),
        ("F1 Score",  metrics.get("f1", 0),        "#a78bfa"),
        ("ROC-AUC",   metrics.get("roc_auc", 0),   "#f59e0b"),
    ]
    kcols = st.columns(4)
    for kcol, (label, val, color) in zip(kcols, kpis):
        with kcol:
            pct = int(val * 100)
            _html(
                f"<div style='background:#070c18;border:1px solid {color}33;"
                f"border-top:2px solid {color};border-radius:8px;"
                f"padding:0.7rem;text-align:center;font-family:{MONO};'>"
                f"<div style='font-size:1.4rem;font-weight:700;color:{color};'>{val:.3f}</div>"
                f"<div style='font-size:0.6rem;color:#475569;"
                f"text-transform:uppercase;letter-spacing:0.1em;'>{label}</div>"
                f"<div style='background:#1e293b;border-radius:3px;height:3px;margin:0.35rem 0 0;'>"
                f"<div class='risk-bar-fill' style='background:{color};width:{pct}%;height:3px;border-radius:3px;'></div>"
                f"</div></div>"
            )

    det_lat  = metrics.get("detection_latency_sec")
    resp_lat = metrics.get("response_latency_sec")
    mit_rate = metrics.get("mitigation_success_rate", 0)
    dl = f"{det_lat:.1f}s" if det_lat is not None else "—"
    rl = f"{resp_lat:.1f}s" if resp_lat is not None else "—"
    mr = f"{mit_rate:.1%}"
    _html(
        f"<div style='background:#070c18;border:1px solid #1e293b;"
        f"border-radius:8px;padding:0.65rem 1rem;margin-top:0.5rem;"
        f"font-family:{MONO};font-size:0.68rem;display:flex;gap:2rem;flex-wrap:wrap;'>"
        f"<span style='color:#94a3b8;'>Det. Latency: <b style='color:#f59e0b;'>{dl}</b></span>"
        f"<span style='color:#94a3b8;'>Resp. Latency: <b style='color:#ef4444;'>{rl}</b></span>"
        f"<span style='color:#94a3b8;'>Mitigation Rate: <b style='color:#22c55e;'>{mr}</b></span>"
        f"</div>"
    )


def render_logs_viewer(detection_log: list, response_log: list) -> None:
    tab1, tab2 = st.tabs(["🔍 Detection Logs", "⚡ Response Logs"])
    with tab1:
        if not detection_log:
            st.caption("No detection logs yet.")
        for e in list(reversed(detection_log))[:8]:
            col = SEVERITY_COLOR.get(e.get("severity", "LOW"), "#94a3b8")
            sev = e.get("severity", "?")
            ts = e.get("timestamp", "")[:19]
            nid = e.get("node_id", "")
            at = e.get("attack_type", "")
            cy = e.get("anomaly_scores", {}).get("cyber", "?")
            ph = e.get("anomaly_scores", {}).get("physical", "?")
            cr = e.get("correlation_value", "?")
            sha = e.get("sha256", "")[:32]
            _html(
                f"<div style='background:#070c18;border:1px solid #0f172a;"
                f"border-left:3px solid {col};border-radius:6px;"
                f"padding:0.45rem 0.8rem;margin-bottom:0.25rem;"
                f"font-family:{MONO};font-size:0.62rem;line-height:1.7;'>"
                f"<span style='color:{col};font-weight:700;'>[{sev}]</span>"
                f" <span style='color:#475569;'>{ts}</span>"
                f" · <span style='color:#94a3b8;'>node={nid}</span>"
                f" · <span style='color:#3b82f6;'>{at}</span><br>"
                f"<span style='color:#334155;'>cyber={cy} phys={ph} corr={cr}</span><br>"
                f"<span style='color:#1e293b;font-size:0.58rem;'>sha256: {sha}...</span>"
                f"</div>"
            )
    with tab2:
        if not response_log:
            st.caption("No response logs yet.")
        for e in list(reversed(response_log))[:8]:
            act = e.get("action_taken", "")
            a_col = "#ef4444" if "shutdown" in act else "#06b6d4"
            icon = ACTION_ICONS.get(act, "⚙️")
            ts = e.get("timestamp", "")[:19]
            nid = e.get("node_id", "")
            ss = e.get("system_state", "")
            suc = e.get("success", "?")
            sha = e.get("sha256", "")[:32]
            _html(
                f"<div style='background:#070c18;border:1px solid #0f172a;"
                f"border-left:3px solid {a_col};border-radius:6px;"
                f"padding:0.45rem 0.8rem;margin-bottom:0.25rem;"
                f"font-family:{MONO};font-size:0.62rem;line-height:1.7;'>"
                f"<span style='color:{a_col};font-weight:700;'>{icon}</span>"
                f" <span style='color:#475569;'>{ts}</span>"
                f" · <span style='color:#94a3b8;'>node={nid}</span><br>"
                f"<span style='color:#334155;'>state={ss} success={suc}</span><br>"
                f"<span style='color:#1e293b;font-size:0.58rem;'>sha256: {sha}...</span>"
                f"</div>"
            )

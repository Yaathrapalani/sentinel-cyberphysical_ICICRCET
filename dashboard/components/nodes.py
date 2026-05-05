"""components/nodes.py — node status cards + geospatial map."""
from __future__ import annotations
import streamlit as st
import streamlit.components.v1 as stc

MONO = "JetBrains Mono, monospace"
NODES = [
    ("node_a", "Power Grid",       13.0827, 80.2707, "#3b82f6", False),
    ("node_b", "Water Treatment",  12.9716, 77.5946, "#10b981", False),
    ("node_c", "Transport",        17.3850, 78.4867, "#ef4444", True),
]


def render_node_status() -> None:
    cols = st.columns(4)
    for cel, (nid, lbl, lat, lng, color, mali) in zip(cols[:3], NODES):
        with cel:
            sc    = "#ef4444" if mali else "#22c55e"
            bc    = "#7f1d1d" if mali else "#14532d"
            badge = "MALICIOUS" if mali else "ACTIVE"
            dp    = "POISONING" if mali else "epsilon-DP"
            kc    = "#ef4444" if mali else "#22c55e"
            kr    = "REJECTED" if mali else "ACCEPTED"
            st.markdown(f"""
            <div style='background:linear-gradient(160deg,
            #0a0f1e 0%,#070c18 100%);
            border:1px solid {color}22;border-left:3px solid {color};
            border-radius:9px;padding:1rem;
            font-family:{MONO};font-size:0.7rem;line-height:1.95;'>
                <div style='display:flex;justify-content:space-between;
                align-items:center;margin-bottom:0.4rem;'>
                    <span style='color:{color};font-weight:700;
                    font-size:0.78rem;'>{nid}</span>
                    <span style='background:{bc};color:{sc};
                    font-size:0.57rem;padding:0.1rem 0.4rem;
                    border-radius:4px;letter-spacing:0.06em;'>
                    {badge}</span>
                </div>
                <span style='color:#475569;'>{lbl}</span><br>
                <span style='color:#1e293b;font-size:0.62rem;'>
                {lat:.4f} · {lng:.4f}</span><br>
                <span style='color:{sc};'>● {("BYZANTINE" if mali else "ONLINE")}</span><br>
                <span style='color:#334155;'>{dp}</span><br>
                <span style='color:{kc};'>KRUM: {kr}</span>
            </div>""", unsafe_allow_html=True)

    with cols[3]:
        st.markdown(f"""
        <div style='background:linear-gradient(160deg,#0a0f1e,#070c18);
        border:1px solid #0f172a;border-radius:9px;padding:1rem;
        font-family:{MONO};font-size:0.68rem;line-height:2.1;'>
            <span style='color:#3b82f6;'>L1</span>&nbsp;BATADAL 8761r<br>
            <span style='color:#10b981;'>L2</span>&nbsp;IsolationForest<br>
            <span style='color:#8b5cf6;'>L3</span>&nbsp;Flower FL 5 rounds<br>
            <span style='color:#f59e0b;'>L4</span>&nbsp;epsilon-DP+Krum<br>
            <span style='color:#ef4444;'>L5</span>&nbsp;Pearson w=20<br>
            <span style='color:#06b6d4;'>L6</span>&nbsp;Streamlit live<br>
            <span style='color:#1e293b;font-size:0.6rem;'>
            SDG 9·11·16·7</span>
        </div>""", unsafe_allow_html=True)


def render_geo_map() -> None:
    try:
        import folium
        _folium_map()
    except ImportError:
        _svg_map()


def _folium_map() -> None:
    import folium

    m = folium.Map(
        location=[15.0, 79.0], zoom_start=6,
        tiles="CartoDB dark_matter", prefer_canvas=True
    )

    for nid, lbl, lat, lng, color, mali in NODES:
        popup_html = f"""
        <div style='font-family:monospace;font-size:11px;
        background:#0f172a;color:#e2e8f0;
        padding:8px 10px;border-left:3px solid {color};min-width:160px;'>
        <b style='color:{color};'>{nid}</b><br>
        {lbl}<br>{lat:.4f} · {lng:.4f}<br>
        {"BYZANTINE" if mali else "ONLINE"} · KRUM: {"REJECTED" if mali else "ACCEPTED"}
        </div>"""

        folium.CircleMarker(
            location=[lat, lng], radius=13 if mali else 9,
            color=color, fill=True, fill_color=color,
            fill_opacity=0.85, weight=2,
            popup=folium.Popup(popup_html, max_width=210),
            tooltip=f"{nid} — {lbl}"
        ).add_to(m)

        if mali:
            for r in [22, 38, 56]:
                folium.CircleMarker(
                    location=[lat, lng], radius=r,
                    color="#ef4444", fill=False, weight=1,
                    opacity=max(0.04, 0.22 - r * 0.003)
                ).add_to(m)

        folium.Marker(
            location=[lat + 0.2, lng],
            icon=folium.DivIcon(
                html=f"""<div style='font-family:monospace;font-size:10px;
                color:{color};font-weight:700;white-space:nowrap;
                text-shadow:0 0 6px #000;'>{nid}</div>""",
                icon_size=(80, 20), icon_anchor=(0, 0)
            )
        ).add_to(m)

    coords = [(d[2], d[3]) for d in NODES]
    folium.PolyLine(coords, color="#1e40af", weight=1,
                    opacity=0.4, dash_array="5 4").add_to(m)

    stc.html(
        f"<div style='border:1px solid #1e293b;border-radius:10px;"
        f"overflow:hidden;'>{m._repr_html_()}</div>",
        height=395, scrolling=False
    )


def _svg_map() -> None:
    stc.html("""
    <div style='background:#070c18;border:1px solid #1e293b;
    border-radius:10px;padding:1rem;'>
    <p style='font-family:monospace;font-size:10px;color:#334155;
    letter-spacing:2px;margin:0 0 0.5rem;'>
    SENTINEL · NODE DEPLOYMENT · INDIA
    — install folium for interactive map: pip install folium</p>
    <svg viewBox="0 0 560 300" xmlns="http://www.w3.org/2000/svg"
         style="width:100%;height:270px;">
      <rect width="560" height="300" fill="#070c18"/>
      <path d="M190,28 L235,18 L285,22 L335,38 L365,78
               L385,128 L375,178 L355,218 L315,258
               L285,288 L265,298 L245,283 L215,248
               L195,208 L180,168 L175,128 L185,78 Z"
            fill="#0a0f1e" stroke="#1e293b" stroke-width="1.5"/>
      <!-- node_a Chennai -->
      <circle cx="360" cy="235" r="9" fill="#3b82f6" opacity="0.88"/>
      <circle cx="360" cy="235" r="17" fill="none" stroke="#3b82f6"
              stroke-width="1" opacity="0.3"/>
      <text x="374" y="239" fill="#3b82f6" font-size="9"
            font-family="monospace">node_a · Power Grid</text>
      <!-- node_b Bangalore -->
      <circle cx="312" cy="250" r="9" fill="#10b981" opacity="0.88"/>
      <circle cx="312" cy="250" r="17" fill="none" stroke="#10b981"
              stroke-width="1" opacity="0.3"/>
      <text x="326" y="254" fill="#10b981" font-size="9"
            font-family="monospace">node_b · Water Treatment</text>
      <!-- node_c Hyderabad MALI -->
      <circle cx="338" cy="190" r="11" fill="#ef4444" opacity="0.88"/>
      <circle cx="338" cy="190" r="21" fill="none" stroke="#ef4444"
              stroke-width="1" opacity="0.35"/>
      <circle cx="338" cy="190" r="33" fill="none" stroke="#ef4444"
              stroke-width="0.5" opacity="0.15"/>
      <text x="354" y="194" fill="#ef4444" font-size="9"
            font-family="monospace">node_c · BYZANTINE</text>
      <!-- lines -->
      <line x1="360" y1="235" x2="312" y2="250"
            stroke="#1e40af" stroke-width="1" stroke-dasharray="4 3" opacity="0.5"/>
      <line x1="360" y1="235" x2="338" y2="190"
            stroke="#1e40af" stroke-width="1" stroke-dasharray="4 3" opacity="0.5"/>
      <line x1="312" y1="250" x2="338" y2="190"
            stroke="#1e40af" stroke-width="1" stroke-dasharray="4 3" opacity="0.5"/>
    </svg></div>
    """, height=340, scrolling=False)

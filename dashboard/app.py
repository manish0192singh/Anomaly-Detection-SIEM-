import streamlit as st
import pandas as pd
import datetime
import altair as alt
import json
import os

from logs_page import logs_page
from anomalies_page import anomalies_page
from alerts_page import alerts_page
from user_behaviour_page import user_behaviour_page
from data_loader import data_loader_page
from settings_page import settings_page

# ── App config ────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AI SIEM — Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS — dark professional SOC aesthetic ──────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;600;700;800&display=swap');

.stApp { background-color: #080c14; color: #e2e8f0; }

[data-testid="stSidebar"] {
    background-color: #0d1321 !important;
    border-right: 1px solid #1e2d45;
}
[data-testid="stSidebar"] * { color: #94a3b8 !important; }
[data-testid="stSidebar"] .stRadio label {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 13px !important;
    padding: 6px 0 !important;
}

.main .block-container {
    padding-top: 1.5rem;
    padding-bottom: 2rem;
    max-width: 1400px;
}

header[data-testid="stHeader"] { background: transparent; }

[data-testid="metric-container"] {
    background: linear-gradient(135deg, #0f1923 0%, #0d1a2e 100%);
    border: 1px solid #1e3a5f;
    border-radius: 12px;
    padding: 16px 20px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.05);
    transition: all 0.2s ease;
}
[data-testid="metric-container"]:hover {
    border-color: #2563eb;
    box-shadow: 0 4px 32px rgba(37,99,235,0.15);
}
[data-testid="stMetricLabel"] {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 11px !important;
    text-transform: uppercase;
    letter-spacing: 0.1em;
    color: #64748b !important;
}
[data-testid="stMetricValue"] {
    font-family: 'Syne', sans-serif !important;
    font-weight: 800 !important;
    font-size: 2rem !important;
    color: #f1f5f9 !important;
}

[data-testid="stDataFrame"] {
    border: 1px solid #1e3a5f !important;
    border-radius: 10px;
    overflow: hidden;
}

hr { border-color: #1e2d45 !important; margin: 1.5rem 0; }

.stTabs [data-baseweb="tab-list"] {
    background: #0d1321;
    border-radius: 10px;
    padding: 4px;
    gap: 4px;
    border: 1px solid #1e2d45;
}
.stTabs [data-baseweb="tab"] {
    background: transparent;
    color: #64748b;
    border-radius: 8px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
}
.stTabs [aria-selected="true"] {
    background: #1e3a5f !important;
    color: #60a5fa !important;
}

.stButton button {
    background: linear-gradient(135deg, #1d4ed8, #2563eb);
    color: white;
    border: none;
    border-radius: 8px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    letter-spacing: 0.05em;
    box-shadow: 0 4px 12px rgba(37,99,235,0.3);
}
.stButton button:hover {
    background: linear-gradient(135deg, #2563eb, #3b82f6);
    box-shadow: 0 4px 20px rgba(37,99,235,0.5);
}

.stSelectbox > div > div,
.stTextInput > div > div {
    background: #0d1321 !important;
    border-color: #1e3a5f !important;
    color: #e2e8f0 !important;
    border-radius: 8px !important;
}

::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0d1321; }
::-webkit-scrollbar-thumb { background: #1e3a5f; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #2563eb; }
</style>
""", unsafe_allow_html=True)


# ── Sidebar ───────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style='padding: 8px 0 20px 0;'>
        <div style='font-family: Syne, sans-serif; font-size: 22px; font-weight: 800;
                    color: #f1f5f9; letter-spacing: -0.5px;'>🛡️ AI SIEM</div>
        <div style='font-family: JetBrains Mono, monospace; font-size: 10px;
                    color: #475569; letter-spacing: 0.15em; text-transform: uppercase;
                    margin-top: 2px;'>Security Operations Center</div>
    </div>
    """, unsafe_allow_html=True)

    menu = st.radio(
        "Navigation",
        ["Dashboard", "Logs", "Anomalies", "Alerts",
         "User Behaviour", "Data Loader", "Settings"],
        format_func=lambda x: {
            "Dashboard":      "  📊  Overview",
            "Logs":           "  📄  Logs",
            "Anomalies":      "  🔍  Anomalies",
            "Alerts":         "  🚨  Alerts",
            "User Behaviour": "  👤  User Behaviour",
            "Data Loader":    "  📥  Data Loader",
            "Settings":       "  ⚙️  Settings",
        }.get(x, x),
        label_visibility="collapsed"
    )

    st.divider()
    st.markdown("""
    <div style='font-family: JetBrains Mono, monospace; font-size: 10px;
                color: #475569; text-transform: uppercase; letter-spacing: 0.1em;
                margin-bottom: 10px;'>Data Status</div>
    """, unsafe_allow_html=True)

    for label, path in {
        "Structured Logs": "data/structured_logs.csv",
        "Anomalies":       "data/anomalies.csv",
        "Alerts":          "data/final_alerts.json",
    }.items():
        exists = os.path.exists(path)
        color  = "#22c55e" if exists else "#ef4444"
        dot    = "●" if exists else "○"
        st.markdown(
            f"<div style='font-family:JetBrains Mono,monospace; font-size:11px;"
            f"color:{color}; margin:4px 0;'>{dot} {label}</div>",
            unsafe_allow_html=True
        )

    st.divider()
    st.markdown(
        "<div style='font-family:JetBrains Mono,monospace; font-size:10px;"
        "color:#334155; text-align:center;'>v1.0.0 · AI-Powered SIEM</div>",
        unsafe_allow_html=True
    )


# ── Helpers ───────────────────────────────────────────────────────────
def load_csv(path):
    return pd.read_csv(path) if os.path.exists(path) else None

def load_json(path):
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return json.load(f)

def section_header(title, subtitle=""):
    st.markdown(
        f"<div style='margin:8px 0 16px 0;'>"
        f"<div style='font-family:Syne,sans-serif; font-size:18px; font-weight:700;"
        f"color:#f1f5f9; letter-spacing:-0.3px;'>{title}</div>"
        + (f"<div style='font-family:JetBrains Mono,monospace; font-size:11px;"
           f"color:#475569; margin-top:2px;'>{subtitle}</div>" if subtitle else "")
        + "</div>",
        unsafe_allow_html=True
    )

def chart_label(text):
    st.markdown(
        f"<div style='font-family:JetBrains Mono,monospace; font-size:11px;"
        f"color:#64748b; text-transform:uppercase; letter-spacing:0.1em;"
        f"margin-bottom:8px;'>{text}</div>",
        unsafe_allow_html=True
    )

CHART_CFG = {
    "background": "#0d1321",
    "view":       {"stroke": "transparent"},
    "axis": {
        "gridColor":     "#1e2d45",
        "domainColor":   "#1e2d45",
        "tickColor":     "#1e2d45",
        "labelColor":    "#64748b",
        "titleColor":    "#64748b",
        "labelFont":     "JetBrains Mono",
        "titleFont":     "JetBrains Mono",
        "labelFontSize": 11,
        "titleFontSize": 11,
    },
    "legend": {
        "labelColor": "#94a3b8",
        "titleColor": "#94a3b8",
        "labelFont":  "JetBrains Mono",
        "titleFont":  "JetBrains Mono",
    },
    "title": {
        "color":      "#e2e8f0",
        "font":       "Syne",
        "fontSize":   13,
        "fontWeight": 600,
    }
}


# ── DASHBOARD ─────────────────────────────────────────────────────────
if menu == "Dashboard":

    now = datetime.datetime.now()
    st.markdown(
        f"<div style='display:flex; justify-content:space-between; align-items:flex-start;"
        f"margin-bottom:24px;'>"
        f"<div>"
        f"<div style='font-family:Syne,sans-serif; font-size:28px; font-weight:800;"
        f"color:#f1f5f9; letter-spacing:-0.5px;'>Security Overview</div>"
        f"<div style='font-family:JetBrains Mono,monospace; font-size:12px;"
        f"color:#475569; margin-top:4px;'>"
        f"Real-time threat intelligence · {now.strftime('%d %b %Y, %H:%M:%S')}</div>"
        f"</div>"
        f"<div style='background:#0d1321; border:1px solid #1e3a5f; border-radius:10px;"
        f"padding:10px 18px; text-align:right;'>"
        f"<div style='font-family:JetBrains Mono,monospace; font-size:10px;"
        f"color:#475569; text-transform:uppercase; letter-spacing:0.1em;'>System Status</div>"
        f"<div style='font-family:Syne,sans-serif; font-size:16px; font-weight:700;"
        f"color:#22c55e; margin-top:2px;'>● OPERATIONAL</div>"
        f"</div></div>",
        unsafe_allow_html=True
    )

    # Load data
    logs      = load_csv("data/structured_logs.csv")
    anomalies = load_csv("data/anomalies.csv")
    alerts    = load_json("data/final_alerts.json")

    if logs is not None:
        logs["timestamp"] = pd.to_datetime(logs["timestamp"], errors="coerce")
    if anomalies is not None:
        anomalies["timestamp"] = pd.to_datetime(anomalies["timestamp"], errors="coerce")

    # KPIs
    total_logs   = len(logs) if logs is not None else 0
    total_anom   = int((anomalies["anomaly"] == -1).sum()) if anomalies is not None else 0
    total_alerts = len(alerts)
    crit_alerts  = sum(1 for a in alerts if a.get("severity") == "Critical")
    high_alerts  = sum(1 for a in alerts if a.get("severity") == "High")
    uniq_users   = int(logs["username"].nunique()) if logs is not None else 0

    c1, c2, c3, c4, c5, c6 = st.columns(6)
    c1.metric("Total Logs",    f"{total_logs:,}")
    c2.metric("Unique Users",  uniq_users)
    c3.metric("ML Anomalies",  total_anom)
    c4.metric("Total Alerts",  total_alerts)
    c5.metric("🔴 Critical",   crit_alerts)
    c6.metric("🟠 High",       high_alerts)

    # Alert severity banner
    if alerts:
        from collections import Counter
        sc = Counter(a.get("severity") for a in alerts)
        colors = {"Critical":"#ef4444","High":"#f97316","Medium":"#eab308","Low":"#22c55e"}
        bgs    = {"Critical":"#2d1515","High":"#2d1a0e","Medium":"#2a2108","Low":"#0f2318"}
        badges = "".join([
            f"<span style='background:{bgs.get(s,'#1e293b')};color:{colors.get(s,'#94a3b8')};"
            f"border:1px solid {colors.get(s,'#94a3b8')}33;border-radius:6px;"
            f"padding:3px 12px;font-family:JetBrains Mono,monospace;font-size:12px;"
            f"font-weight:600;margin-right:8px;'>{s}: {sc.get(s,0)}</span>"
            for s in ["Critical","High","Medium","Low"]
        ])
        st.markdown(
            f"<div style='background:#0d1321;border:1px solid #1e2d45;border-radius:10px;"
            f"padding:14px 20px;margin:16px 0;'>"
            f"<span style='font-family:JetBrains Mono,monospace;font-size:10px;"
            f"color:#475569;text-transform:uppercase;letter-spacing:0.1em;"
            f"margin-right:16px;'>Alert Summary</span>{badges}</div>",
            unsafe_allow_html=True
        )

    st.divider()

    # Today snapshot
    today = datetime.date.today()
    section_header(
        "Today's Activity",
        f"Events recorded on {today.strftime('%A, %d %B %Y')}"
    )

    today_logs = len(logs[logs["timestamp"].dt.date == today]) if logs is not None else 0
    today_anom = len(anomalies[
        (anomalies["timestamp"].dt.date == today) & (anomalies["anomaly"] == -1)
    ]) if anomalies is not None else 0
    today_alts = sum(
        1 for a in alerts
        if pd.to_datetime(a.get("timestamp",""), errors="coerce").date() == today
    )

    t1, t2, t3, t4 = st.columns(4)
    t1.metric("Logs Today",      f"{today_logs:,}")
    t2.metric("Anomalies Today", today_anom)
    t3.metric("Alerts Today",    today_alts)
    t4.metric("Date",            today.strftime("%d %b %Y"))

    st.divider()

    # Charts row 1
    section_header("Threat Intelligence", "Visual breakdown of system activity and alerts")
    ch1, ch2 = st.columns([3, 2])

    with ch1:
        chart_label("Log Volume · By Hour of Day")
        if logs is not None:
            logs["hour"] = logs["timestamp"].dt.hour
            hourly = logs.groupby("hour").size().reset_index(name="count")
            area = alt.Chart(hourly).mark_area(
                line={"color": "#3b82f6", "strokeWidth": 2},
                color=alt.Gradient(
                    gradient="linear",
                    stops=[
                        alt.GradientStop(color="rgba(59,130,246,0.35)", offset=0),
                        alt.GradientStop(color="rgba(59,130,246,0.0)",  offset=1),
                    ],
                    x1=1, x2=1, y1=1, y2=0
                )
            ).encode(
                x=alt.X("hour:O", title="Hour",
                         axis=alt.Axis(labelAngle=0)),
                y=alt.Y("count:Q", title="Logs"),
                tooltip=[alt.Tooltip("hour:O", title="Hour"),
                         alt.Tooltip("count:Q", title="Logs")]
            ).properties(height=230).configure(**CHART_CFG)
            st.altair_chart(area, use_container_width=True)
        else:
            st.info("No log data. Run the pipeline first.")

    with ch2:
        chart_label("Alert Severity Distribution")
        if alerts:
            adf  = pd.DataFrame(alerts)
            scnt = adf["severity"].value_counts().reset_index()
            scnt.columns = ["Severity", "Count"]
            donut = alt.Chart(scnt).mark_arc(
                innerRadius=55, outerRadius=95,
                padAngle=0.03, cornerRadius=4
            ).encode(
                theta=alt.Theta("Count:Q"),
                color=alt.Color("Severity:N", scale=alt.Scale(
                    domain=["Critical","High","Medium","Low"],
                    range=["#ef4444","#f97316","#eab308","#22c55e"]
                )),
                tooltip=["Severity","Count"]
            ).properties(height=230).configure(**CHART_CFG)
            st.altair_chart(donut, use_container_width=True)
        else:
            st.info("No alert data yet.")

    # Charts row 2
    ch3, ch4 = st.columns(2)

    with ch3:
        chart_label("Event Type Breakdown")
        if logs is not None and "event_type_clean" in logs.columns:
            et = logs["event_type_clean"].value_counts().head(8).reset_index()
            et.columns = ["Event Type", "Count"]
            hbar = alt.Chart(et).mark_bar(
                cornerRadiusTopRight=4, cornerRadiusBottomRight=4
            ).encode(
                x=alt.X("Count:Q", title=""),
                y=alt.Y("Event Type:N", sort="-x", title=""),
                color=alt.condition(
                    alt.FieldOneOfPredicate(
                        field="Event Type",
                        oneOf=["Failed Login","Privilege Escalation","Account Locked Out"]
                    ),
                    alt.value("#ef4444"),
                    alt.value("#3b82f6")
                ),
                tooltip=["Event Type","Count"]
            ).properties(height=260).configure(**CHART_CFG)
            st.altair_chart(hbar, use_container_width=True)

    with ch4:
        chart_label("Top Alert Types")
        if alerts:
            at   = pd.DataFrame(alerts)
            atc  = at["type"].value_counts().head(8).reset_index()
            atc.columns = ["Alert Type","Count"]
            atb  = alt.Chart(atc).mark_bar(
                cornerRadiusTopRight=4, cornerRadiusBottomRight=4, color="#8b5cf6"
            ).encode(
                x=alt.X("Count:Q", title=""),
                y=alt.Y("Alert Type:N", sort="-x", title=""),
                tooltip=["Alert Type","Count"]
            ).properties(height=260).configure(**CHART_CFG)
            st.altair_chart(atb, use_container_width=True)

    st.divider()

    # Recent critical alerts
    section_header("Recent Critical Alerts",
                   "Highest priority threats requiring immediate attention")

    crit_list = [a for a in alerts if a.get("severity") == "Critical"]
    if crit_list:
        cdf  = pd.DataFrame(crit_list[:10])
        show = [c for c in ["timestamp","type","username",
                             "ip_address","message","mitre_tactic"]
                if c in cdf.columns]
        st.dataframe(
            cdf[show].sort_values("timestamp", ascending=False),
            use_container_width=True,
            height=320,
        )
    else:
        st.markdown(
            "<div style='background:rgba(34,197,94,0.08);border:1px solid rgba(34,197,94,0.25);"
            "border-radius:10px;padding:24px;text-align:center;'>"
            "<div style='font-family:Syne,sans-serif;font-size:20px;font-weight:700;"
            "color:#22c55e;'>✓ No Critical Alerts</div>"
            "<div style='font-family:JetBrains Mono,monospace;font-size:12px;"
            "color:#475569;margin-top:6px;'>System is operating normally</div>"
            "</div>",
            unsafe_allow_html=True
        )

    # MITRE coverage
    if alerts:
        mitre_a = [a for a in alerts if a.get("mitre_tactic","") not in ("","Unknown")]
        if mitre_a:
            st.divider()
            section_header("MITRE ATT&CK Coverage",
                           "Detected attack techniques mapped to the MITRE framework")
            mdf  = pd.DataFrame(mitre_a)
            mcnt = mdf["mitre_tactic"].value_counts().head(10).reset_index()
            mcnt.columns = ["Tactic","Count"]
            mb   = alt.Chart(mcnt).mark_bar(
                cornerRadiusTopRight=4, cornerRadiusBottomRight=4, color="#7c3aed"
            ).encode(
                x=alt.X("Count:Q", title=""),
                y=alt.Y("Tactic:N", sort="-x", title=""),
                tooltip=["Tactic","Count"]
            ).properties(height=280).configure(**CHART_CFG)
            st.altair_chart(mb, use_container_width=True)

# ── Other pages ───────────────────────────────────────────────────────
elif menu == "Logs":           logs_page()
elif menu == "Anomalies":      anomalies_page()
elif menu == "Alerts":         alerts_page()
elif menu == "User Behaviour": user_behaviour_page()
elif menu == "Data Loader":    data_loader_page()
elif menu == "Settings":       settings_page()
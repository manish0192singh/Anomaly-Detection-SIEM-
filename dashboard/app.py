import streamlit as st
import pandas as pd
import datetime
import altair as alt
import json
import os
import requests
from collections import Counter

# ── Config ────────────────────────────────────────────────────────────
SERVER_URL = os.getenv("SERVER_URL", "http://localhost:8000")

st.set_page_config(
    page_title="AI SIEM — Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Syne:wght@400;600;700;800&display=swap');
.stApp { background-color: #080c14; color: #e2e8f0; }
[data-testid="stSidebar"] { background-color: #0d1321 !important; border-right: 1px solid #1e2d45; }
[data-testid="stSidebar"] * { color: #94a3b8 !important; }
.main .block-container { padding-top: 1.5rem; max-width: 1400px; }
header[data-testid="stHeader"] { background: transparent; }
[data-testid="metric-container"] {
    background: linear-gradient(135deg, #0f1923 0%, #0d1a2e 100%);
    border: 1px solid #1e3a5f; border-radius: 12px; padding: 16px 20px;
    box-shadow: 0 4px 24px rgba(0,0,0,0.4); transition: all 0.2s ease;
}
[data-testid="metric-container"]:hover { border-color: #2563eb; }
[data-testid="stMetricLabel"] {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 11px !important; text-transform: uppercase;
    letter-spacing: 0.1em; color: #64748b !important;
}
[data-testid="stMetricValue"] {
    font-family: 'Syne', sans-serif !important;
    font-weight: 800 !important; font-size: 2rem !important; color: #f1f5f9 !important;
}
[data-testid="stDataFrame"] { border: 1px solid #1e3a5f !important; border-radius: 10px; }
hr { border-color: #1e2d45 !important; margin: 1.5rem 0; }
.stTabs [data-baseweb="tab-list"] {
    background: #0d1321; border-radius: 10px;
    padding: 4px; border: 1px solid #1e2d45;
}
.stTabs [data-baseweb="tab"] {
    background: transparent; color: #64748b;
    border-radius: 8px; font-family: 'JetBrains Mono', monospace; font-size: 12px;
}
.stTabs [aria-selected="true"] { background: #1e3a5f !important; color: #60a5fa !important; }
.stButton button {
    background: linear-gradient(135deg, #1d4ed8, #2563eb);
    color: white; border: none; border-radius: 8px;
    font-family: 'JetBrains Mono', monospace; font-size: 13px;
    box-shadow: 0 4px 12px rgba(37,99,235,0.3);
}
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: #0d1321; }
::-webkit-scrollbar-thumb { background: #1e3a5f; border-radius: 3px; }
</style>
""", unsafe_allow_html=True)


# ── Read user_id from URL ─────────────────────────────────────────────
query_params = st.query_params
user_id      = query_params.get("user_id", None)


# ── Data fetchers (with error handling) ───────────────────────────────
@st.cache_data(ttl=30)
def fetch_stats(uid):
    try:
        r = requests.get(f"{SERVER_URL}/data/{uid}/stats", timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}

@st.cache_data(ttl=30)
def fetch_logs(uid):
    try:
        r = requests.get(f"{SERVER_URL}/data/{uid}/logs", timeout=30)
        if r.status_code == 200:
            data = r.json().get("logs", [])
            return pd.DataFrame(data) if data else pd.DataFrame()
    except Exception:
        pass
    return pd.DataFrame()

@st.cache_data(ttl=30)
def fetch_anomalies(uid):
    try:
        r = requests.get(f"{SERVER_URL}/data/{uid}/anomalies", timeout=30)
        if r.status_code == 200:
            data = r.json().get("anomalies", [])
            return pd.DataFrame(data) if data else pd.DataFrame()
    except Exception:
        pass
    return pd.DataFrame()

@st.cache_data(ttl=30)
def fetch_alerts(uid):
    try:
        r = requests.get(f"{SERVER_URL}/data/{uid}/alerts", timeout=30)
        if r.status_code == 200:
            return r.json().get("alerts", [])
    except Exception:
        pass
    return []

def save_locally(logs_df, anom_df, alerts_list):
    """Save fetched data to local CSV/JSON so existing pages can read them."""
    os.makedirs("data", exist_ok=True)
    try:
        if not logs_df.empty:
            logs_df.to_csv("data/structured_logs.csv", index=False)
        if not anom_df.empty:
            anom_df.to_csv("data/anomalies.csv", index=False)
        if alerts_list:
            with open("data/final_alerts.json", "w") as f:
                json.dump(alerts_list, f)
    except Exception:
        pass


# ── Chart config ──────────────────────────────────────────────────────
CHART_CFG = {
    "background": "#0d1321",
    "view":       {"stroke": "transparent"},
    "axis": {
        "gridColor": "#1e2d45", "domainColor": "#1e2d45", "tickColor": "#1e2d45",
        "labelColor": "#64748b", "titleColor": "#64748b",
        "labelFont": "JetBrains Mono", "titleFont": "JetBrains Mono",
        "labelFontSize": 11, "titleFontSize": 11,
    },
    "legend": {
        "labelColor": "#94a3b8", "titleColor": "#94a3b8",
        "labelFont": "JetBrains Mono", "titleFont": "JetBrains Mono",
    },
    "title": {"color": "#e2e8f0", "font": "Syne", "fontSize": 13, "fontWeight": 600}
}

def chart_label(text):
    st.markdown(
        f"<div style='font-family:JetBrains Mono,monospace;font-size:11px;"
        f"color:#64748b;text-transform:uppercase;letter-spacing:0.1em;"
        f"margin-bottom:8px;'>{text}</div>",
        unsafe_allow_html=True
    )

def section_header(title, subtitle=""):
    st.markdown(
        f"<div style='margin:8px 0 16px 0;'>"
        f"<div style='font-family:Syne,sans-serif;font-size:18px;font-weight:700;"
        f"color:#f1f5f9;'>{title}</div>"
        + (f"<div style='font-family:JetBrains Mono,monospace;font-size:11px;"
           f"color:#475569;margin-top:2px;'>{subtitle}</div>" if subtitle else "")
        + "</div>",
        unsafe_allow_html=True
    )


# ══════════════════════════════════════════════════════════════════════
# LANDING PAGE — shown when no user_id in URL
# ══════════════════════════════════════════════════════════════════════
if not user_id:

    # Hero section
    st.markdown("""
    <div style='text-align:center; padding:60px 0 40px 0;'>
        <div style='font-size:56px; margin-bottom:16px;'>🛡️</div>
        <div style='font-family:Syne,sans-serif; font-size:40px; font-weight:800;
                    color:#f1f5f9; letter-spacing:-1px;'>AI-Powered SIEM</div>
        <div style='font-family:JetBrains Mono,monospace; font-size:13px;
                    color:#475569; margin-top:8px; letter-spacing:0.1em;'>
            SECURITY INFORMATION & EVENT MANAGEMENT
        </div>
        <div style='font-family:JetBrains Mono,monospace; font-size:13px;
                    color:#64748b; margin-top:12px; max-width:600px; margin-left:auto;
                    margin-right:auto; line-height:1.8;'>
            Monitor your Windows PC for threats using AI anomaly detection,
            11 security rules, and MITRE ATT&CK mapping.
            No account needed.
        </div>
    </div>
    """, unsafe_allow_html=True)

    # Feature cards
    c1, c2, c3 = st.columns(3)
    features = [
        (c1, "🤖", "AI Detection",
         "Dual ML models detect unknown threats with risk scoring 0–100"),
        (c2, "📏", "11 Security Rules",
         "Brute force, privilege escalation, odd-hour logins & more"),
        (c3, "🛡️", "MITRE ATT&CK",
         "Every alert mapped to the industry-standard framework"),
    ]
    for col, icon, title, desc in features:
        col.markdown(
            f"<div style='background:#0d1321;border:1px solid #1e3a5f;"
            f"border-radius:12px;padding:24px;text-align:center;height:155px;'>"
            f"<div style='font-size:28px;margin-bottom:10px;'>{icon}</div>"
            f"<div style='font-family:Syne,sans-serif;font-size:15px;font-weight:700;"
            f"color:#f1f5f9;margin-bottom:8px;'>{title}</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:11px;"
            f"color:#475569;line-height:1.6;'>{desc}</div>"
            f"</div>",
            unsafe_allow_html=True
        )

    st.markdown("<div style='height:40px'></div>", unsafe_allow_html=True)
    st.divider()

    # How it works
    st.markdown("""
    <div style='text-align:center;margin-bottom:24px;'>
        <div style='font-family:Syne,sans-serif;font-size:24px;font-weight:700;
                    color:#f1f5f9;'>Monitor Your Windows PC in 3 Steps</div>
        <div style='font-family:JetBrains Mono,monospace;font-size:12px;
                    color:#475569;margin-top:6px;'>
            No account needed · Your data stays private · Takes under 2 minutes
        </div>
    </div>
    """, unsafe_allow_html=True)

    s1, s2, s3 = st.columns(3)
    steps = [
        (s1, "1", "Click Download",
         "Get your personal run_pipeline.py with your unique ID baked in"),
        (s2, "2", "Run on Your PC",
         "Run it on Windows. It collects logs, runs AI detection, uploads data"),
        (s3, "3", "View Dashboard",
         "Your personal dashboard opens automatically in your browser"),
    ]
    for col, num, title, desc in steps:
        col.markdown(
            f"<div style='background:#0d1321;border:1px solid #1e3a5f;"
            f"border-radius:12px;padding:20px;text-align:center;'>"
            f"<div style='font-family:Syne,sans-serif;font-size:36px;"
            f"font-weight:800;color:#2563eb;margin-bottom:8px;'>{num}</div>"
            f"<div style='font-family:Syne,sans-serif;font-size:14px;"
            f"font-weight:700;color:#f1f5f9;margin-bottom:6px;'>{title}</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:11px;"
            f"color:#475569;line-height:1.6;'>{desc}</div>"
            f"</div>",
            unsafe_allow_html=True
        )

    st.markdown("<div style='height:32px'></div>", unsafe_allow_html=True)

    # ── GET MY AGENT BUTTON ───────────────────────────────────────────
    _, mid, _ = st.columns([1, 2, 1])
    with mid:
        st.markdown(
            "<div style='text-align:center;margin-bottom:16px;"
            "font-family:JetBrains Mono,monospace;font-size:12px;"
            "color:#475569;'>Click the button below to get started</div>",
            unsafe_allow_html=True
        )
        if st.button("⬇️  Get My Personal Agent", use_container_width=True):
            try:
                r = requests.get(
                    f"{SERVER_URL}/register",
                    params={"machine": "web"},
                    timeout=15
                )
                if r.status_code == 200:
                    data     = r.json()
                    new_uid  = data["user_id"]
                    dl_url   = data["download_url"]
                    dash_url = data["dashboard_url"]

                    st.success("✅ Your personal agent is ready!")
                    st.markdown(
                        f"<div style='background:#0d1321;border:1px solid #1e3a5f;"
                        f"border-radius:12px;padding:20px;margin-top:12px;'>"
                        f"<div style='font-family:JetBrains Mono,monospace;font-size:11px;"
                        f"color:#475569;margin-bottom:12px;'>YOUR UNIQUE ID</div>"
                        f"<div style='font-family:JetBrains Mono,monospace;font-size:18px;"
                        f"color:#60a5fa;font-weight:600;margin-bottom:16px;'>{new_uid}</div>"
                        f"</div>",
                        unsafe_allow_html=True
                    )

                    st.markdown(f"**Step 1** — [⬇️ Download your run_pipeline.py]({dl_url})")
                    st.markdown("**Step 2** — Run it on your Windows PC")
                    st.markdown(
                        f"**Step 3** — Your dashboard: "
                        f"[{dash_url}]({dash_url})"
                    )
                    st.warning(
                        "💾 **Bookmark your dashboard link!** "
                        "It is unique to you and won't change."
                    )
                else:
                    st.error(
                        f"Server error ({r.status_code}). "
                        "Please try again in a moment."
                    )
            except requests.exceptions.ConnectionError:
                st.error(
                    "❌ Cannot reach the server. "
                    "Make sure the FastAPI service is running on Render."
                )
            except Exception as e:
                st.error(f"Unexpected error: {e}")

    st.divider()

    # Already have ID section
    st.markdown(
        "<div style='text-align:center;font-family:JetBrains Mono,monospace;"
        "font-size:12px;color:#475569;margin-bottom:12px;'>"
        "Already have a dashboard? Enter your ID below</div>",
        unsafe_allow_html=True
    )
    _, mid2, _ = st.columns([1, 2, 1])
    with mid2:
        existing_id = st.text_input(
            "Your User ID",
            placeholder="e.g. abc123xyz456",
            label_visibility="collapsed"
        )
        if st.button("→  Go to My Dashboard", use_container_width=True):
            if existing_id.strip():
                st.query_params["user_id"] = existing_id.strip()
                st.rerun()
            else:
                st.warning("Please enter your User ID first.")


# ══════════════════════════════════════════════════════════════════════
# PERSONAL DASHBOARD — shown when user_id is in URL
# ══════════════════════════════════════════════════════════════════════
else:
    # Import pages
    try:
        from logs_page          import logs_page
        from anomalies_page     import anomalies_page
        from alerts_page        import alerts_page
        from user_behaviour_page import user_behaviour_page
        from data_loader        import data_loader_page
        from settings_page      import settings_page
        pages_loaded = True
    except Exception as e:
        pages_loaded = False
        st.error(f"Could not load page modules: {e}")

    # Sidebar
    with st.sidebar:
        st.markdown(
            f"<div style='padding:8px 0 20px 0;'>"
            f"<div style='font-family:Syne,sans-serif;font-size:22px;"
            f"font-weight:800;color:#f1f5f9;'>🛡️ AI SIEM</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:10px;"
            f"color:#475569;letter-spacing:0.15em;text-transform:uppercase;"
            f"margin-top:2px;'>Security Operations Center</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:10px;"
            f"color:#334155;margin-top:6px;border-top:1px solid #1e2d45;"
            f"padding-top:6px;'>ID: {user_id}</div>"
            f"</div>",
            unsafe_allow_html=True
        )

        menu = st.radio(
            "Navigation",
            ["Dashboard","Logs","Anomalies","Alerts","User Behaviour","Settings"],
            format_func=lambda x: {
                "Dashboard":      "  📊  Overview",
                "Logs":           "  📄  Logs",
                "Anomalies":      "  🔍  Anomalies",
                "Alerts":         "  🚨  Alerts",
                "User Behaviour": "  👤  User Behaviour",
                "Settings":       "  ⚙️  Settings",
            }.get(x, x),
            label_visibility="collapsed"
        )

        st.divider()

        stats = fetch_stats(user_id)
        if stats:
            machine   = stats.get("machine", "Unknown")
            last_seen = str(stats.get("last_seen", ""))[:16]
            st.markdown(
                f"<div style='font-family:JetBrains Mono,monospace;font-size:11px;"
                f"color:#475569;margin-bottom:4px;'>🖥️ {machine}</div>"
                f"<div style='font-family:JetBrains Mono,monospace;font-size:10px;"
                f"color:#334155;'>Last sync: {last_seen}</div>",
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                "<div style='font-family:JetBrains Mono,monospace;font-size:11px;"
                "color:#ef4444;'>⚠️ No data yet.<br/>Run your pipeline file first.</div>",
                unsafe_allow_html=True
            )

        st.divider()
        if st.button("🔄 Refresh Data", use_container_width=True):
            st.cache_data.clear()
            st.rerun()

        st.markdown(
            "<div style='font-family:JetBrains Mono,monospace;font-size:10px;"
            "color:#334155;text-align:center;margin-top:12px;'>v1.0.0 · AI SIEM</div>",
            unsafe_allow_html=True
        )

    # ── Fetch all data and save locally so subpages can read it ───────
    logs_df   = fetch_logs(user_id)
    anom_df   = fetch_anomalies(user_id)
    alerts_list = fetch_alerts(user_id)

    if not logs_df.empty:
        logs_df["timestamp"] = pd.to_datetime(logs_df["timestamp"], errors="coerce")
    if not anom_df.empty:
        anom_df["timestamp"] = pd.to_datetime(anom_df["timestamp"], errors="coerce")

    # Save to local files so subpages (logs_page, anomalies_page etc.) work
    save_locally(logs_df, anom_df, alerts_list)

    # ── No data yet warning ───────────────────────────────────────────
    if logs_df.empty and not stats:
        st.markdown(
            "<div style='background:rgba(234,179,8,0.08);border:1px solid "
            "rgba(234,179,8,0.3);border-radius:12px;padding:24px;"
            "text-align:center;margin:40px 0;'>"
            "<div style='font-size:40px;margin-bottom:12px;'>⏳</div>"
            "<div style='font-family:Syne,sans-serif;font-size:20px;"
            "font-weight:700;color:#eab308;margin-bottom:8px;'>"
            "No Data Yet</div>"
            "<div style='font-family:JetBrains Mono,monospace;font-size:12px;"
            "color:#475569;line-height:1.8;'>"
            "Your dashboard is ready but no data has been uploaded yet.<br/>"
            "Run your <b>run_pipeline.py</b> file on your Windows PC to get started."
            "</div></div>",
            unsafe_allow_html=True
        )
        st.stop()

    # ── DASHBOARD PAGE ────────────────────────────────────────────────
    if menu == "Dashboard":
        now = datetime.datetime.now()

        st.markdown(
            f"<div style='display:flex;justify-content:space-between;"
            f"align-items:flex-start;margin-bottom:24px;'>"
            f"<div>"
            f"<div style='font-family:Syne,sans-serif;font-size:28px;"
            f"font-weight:800;color:#f1f5f9;'>Security Overview</div>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:12px;"
            f"color:#475569;margin-top:4px;'>"
            f"Real-time threat intelligence · {now.strftime('%d %b %Y, %H:%M:%S')}"
            f"</div></div>"
            f"<div style='background:#0d1321;border:1px solid #1e3a5f;"
            f"border-radius:10px;padding:10px 18px;text-align:right;'>"
            f"<div style='font-family:JetBrains Mono,monospace;font-size:10px;"
            f"color:#475569;text-transform:uppercase;'>System Status</div>"
            f"<div style='font-family:Syne,sans-serif;font-size:16px;"
            f"font-weight:700;color:#22c55e;margin-top:2px;'>● OPERATIONAL</div>"
            f"</div></div>",
            unsafe_allow_html=True
        )

        # KPIs
        total_logs   = stats.get("total_logs", 0)
        total_anom   = stats.get("anomalies", 0)
        total_alerts = stats.get("alerts", 0)
        crit_alerts  = stats.get("critical", 0)
        high_alerts  = sum(1 for a in alerts_list if a.get("severity") == "High")
        uniq_users   = int(logs_df["username"].nunique()) if not logs_df.empty else 0

        c1,c2,c3,c4,c5,c6 = st.columns(6)
        c1.metric("Total Logs",    f"{total_logs:,}")
        c2.metric("Unique Users",  uniq_users)
        c3.metric("ML Anomalies",  total_anom)
        c4.metric("Total Alerts",  total_alerts)
        c5.metric("🔴 Critical",   crit_alerts)
        c6.metric("🟠 High",       high_alerts)

        # Alert severity banner
        if alerts_list:
            sc = Counter(a.get("severity") for a in alerts_list)
            colors = {"Critical":"#ef4444","High":"#f97316",
                      "Medium":"#eab308","Low":"#22c55e"}
            bgs    = {"Critical":"#2d1515","High":"#2d1a0e",
                      "Medium":"#2a2108","Low":"#0f2318"}
            badges = "".join([
                f"<span style='background:{bgs.get(s,'#1e293b')};"
                f"color:{colors.get(s,'#94a3b8')};"
                f"border:1px solid {colors.get(s,'#94a3b8')}33;"
                f"border-radius:6px;padding:3px 12px;"
                f"font-family:JetBrains Mono,monospace;font-size:12px;"
                f"font-weight:600;margin-right:8px;'>{s}: {sc.get(s,0)}</span>"
                for s in ["Critical","High","Medium","Low"]
            ])
            st.markdown(
                f"<div style='background:#0d1321;border:1px solid #1e2d45;"
                f"border-radius:10px;padding:14px 20px;margin:16px 0;'>"
                f"<span style='font-family:JetBrains Mono,monospace;font-size:10px;"
                f"color:#475569;text-transform:uppercase;letter-spacing:0.1em;"
                f"margin-right:16px;'>Alert Summary</span>{badges}</div>",
                unsafe_allow_html=True
            )

        st.divider()

        # Charts
        section_header("Threat Intelligence",
                       "Visual breakdown of your system activity and alerts")

        ch1, ch2 = st.columns([3, 2])

        with ch1:
            chart_label("Log Volume · By Hour of Day")
            if not logs_df.empty:
                logs_df["hour"] = logs_df["timestamp"].dt.hour
                hourly = logs_df.groupby("hour").size().reset_index(name="count")
                area = alt.Chart(hourly).mark_area(
                    line={"color":"#3b82f6","strokeWidth":2},
                    color=alt.Gradient(
                        gradient="linear",
                        stops=[
                            alt.GradientStop(color="rgba(59,130,246,0.35)",offset=0),
                            alt.GradientStop(color="rgba(59,130,246,0.0)", offset=1),
                        ],
                        x1=1,x2=1,y1=1,y2=0
                    )
                ).encode(
                    x=alt.X("hour:O",title="Hour",axis=alt.Axis(labelAngle=0)),
                    y=alt.Y("count:Q",title="Logs"),
                    tooltip=[alt.Tooltip("hour:O",title="Hour"),
                             alt.Tooltip("count:Q",title="Logs")]
                ).properties(height=230).configure(**CHART_CFG)
                st.altair_chart(area, use_container_width=True)

        with ch2:
            chart_label("Alert Severity Distribution")
            if alerts_list:
                adf  = pd.DataFrame(alerts_list)
                scnt = adf["severity"].value_counts().reset_index()
                scnt.columns = ["Severity","Count"]
                donut = alt.Chart(scnt).mark_arc(
                    innerRadius=55,outerRadius=95,padAngle=0.03,cornerRadius=4
                ).encode(
                    theta=alt.Theta("Count:Q"),
                    color=alt.Color("Severity:N",scale=alt.Scale(
                        domain=["Critical","High","Medium","Low"],
                        range=["#ef4444","#f97316","#eab308","#22c55e"])),
                    tooltip=["Severity","Count"]
                ).properties(height=230).configure(**CHART_CFG)
                st.altair_chart(donut, use_container_width=True)

        ch3, ch4 = st.columns(2)

        with ch3:
            chart_label("Event Type Breakdown")
            if not logs_df.empty and "event_type_clean" in logs_df.columns:
                et = logs_df["event_type_clean"].value_counts().head(8).reset_index()
                et.columns = ["Event Type","Count"]
                hbar = alt.Chart(et).mark_bar(
                    cornerRadiusTopRight=4,cornerRadiusBottomRight=4
                ).encode(
                    x=alt.X("Count:Q",title=""),
                    y=alt.Y("Event Type:N",sort="-x",title=""),
                    color=alt.condition(
                        alt.FieldOneOfPredicate(field="Event Type",
                            oneOf=["Failed Login","Privilege Escalation",
                                   "Account Locked Out"]),
                        alt.value("#ef4444"),alt.value("#3b82f6")),
                    tooltip=["Event Type","Count"]
                ).properties(height=260).configure(**CHART_CFG)
                st.altair_chart(hbar, use_container_width=True)

        with ch4:
            chart_label("Top Alert Types")
            if alerts_list:
                at  = pd.DataFrame(alerts_list)
                atc = at["type"].value_counts().head(8).reset_index()
                atc.columns = ["Alert Type","Count"]
                atb = alt.Chart(atc).mark_bar(
                    cornerRadiusTopRight=4,cornerRadiusBottomRight=4,
                    color="#8b5cf6"
                ).encode(
                    x=alt.X("Count:Q",title=""),
                    y=alt.Y("Alert Type:N",sort="-x",title=""),
                    tooltip=["Alert Type","Count"]
                ).properties(height=260).configure(**CHART_CFG)
                st.altair_chart(atb, use_container_width=True)

        st.divider()
        section_header("Recent Critical Alerts",
                       "Highest priority threats requiring immediate attention")

        crit = [a for a in alerts_list if a.get("severity") == "Critical"]
        if crit:
            cdf  = pd.DataFrame(crit[:10])
            show = [c for c in ["timestamp","type","username",
                                 "ip_address","message","mitre_tactic"]
                    if c in cdf.columns]
            st.dataframe(
                cdf[show].sort_values("timestamp",ascending=False),
                use_container_width=True, height=300
            )
        else:
            st.markdown(
                "<div style='background:rgba(34,197,94,0.08);"
                "border:1px solid rgba(34,197,94,0.25);border-radius:10px;"
                "padding:24px;text-align:center;'>"
                "<div style='font-family:Syne,sans-serif;font-size:20px;"
                "font-weight:700;color:#22c55e;'>✓ No Critical Alerts</div>"
                "<div style='font-family:JetBrains Mono,monospace;font-size:12px;"
                "color:#475569;margin-top:6px;'>System is operating normally</div>"
                "</div>",
                unsafe_allow_html=True
            )

    elif menu == "Logs"           and pages_loaded: logs_page(logs_df)
    elif menu == "Anomalies"      and pages_loaded: anomalies_page(anom_df)
    elif menu == "Alerts"         and pages_loaded: alerts_page(alerts_list)
    elif menu == "User Behaviour" and pages_loaded: user_behaviour_page(logs_df, alerts_list)
    elif menu == "Settings"       and pages_loaded: settings_page()
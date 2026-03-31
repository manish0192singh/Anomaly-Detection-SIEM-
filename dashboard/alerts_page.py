import streamlit as st
import json
import pandas as pd
import datetime
import altair as alt


SEV_COLOR = {
    "Critical": "🔴",
    "High":     "🟠",
    "Medium":   "🟡",
    "Low":      "🟢",
}


def alerts_page():
    st.title("🚨 Security Alerts")

    try:
        with open("data/final_alerts.json") as f:
            alerts = json.load(f)
    except Exception:
        st.warning("No alerts found. Run the pipeline first.")
        return

    if not alerts:
        st.success("No alerts — system looks clean!")
        return

    df = pd.DataFrame(alerts)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    # ── Summary metrics ───────────────────────────────────────────────
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Alerts",    len(df))
    c2.metric("🔴 Critical",     len(df[df["severity"] == "Critical"]))
    c3.metric("🟠 High",         len(df[df["severity"] == "High"]))
    c4.metric("🟡 Medium",       len(df[df["severity"] == "Medium"]))
    c5.metric("🟢 Low",          len(df[df["severity"] == "Low"]))

    st.divider()

    # ── Filters ──────────────────────────────────────────────────────
    with st.expander("🔧 Filters", expanded=True):
        col1, col2, col3, col4 = st.columns(4)

        date_filter   = col1.selectbox("Date", ["All", "Today", "Yesterday", "Custom Range"])
        sev_filter    = col2.selectbox("Severity", ["All", "Critical", "High", "Medium", "Low"])
        source_filter = col3.selectbox("Source", ["All", "rule", "ml"])
        type_opts     = ["All"] + sorted(df["type"].dropna().unique().tolist())
        type_filter   = col4.selectbox("Alert Type", type_opts)

    filtered = df.copy()

    # Date filter
    today = datetime.date.today()
    if date_filter == "Today":
        filtered = filtered[filtered["timestamp"].dt.date == today]
    elif date_filter == "Yesterday":
        filtered = filtered[filtered["timestamp"].dt.date == today - datetime.timedelta(days=1)]
    elif date_filter == "Custom Range":
        ca, cb = st.columns(2)
        s = ca.date_input("Start")
        e = cb.date_input("End")
        filtered = filtered[(filtered["timestamp"].dt.date >= s) & (filtered["timestamp"].dt.date <= e)]

    if sev_filter != "All":
        filtered = filtered[filtered["severity"] == sev_filter]
    if source_filter != "All" and "source" in filtered.columns:
        filtered = filtered[filtered["source"] == source_filter]
    if type_filter != "All":
        filtered = filtered[filtered["type"] == type_filter]

    st.write(f"Showing **{len(filtered)}** alerts")

    # ── Alert type breakdown chart ────────────────────────────────────
    st.subheader("📊 Alert Type Breakdown")
    type_counts = filtered["type"].value_counts().head(12).reset_index()
    type_counts.columns = ["Type", "Count"]
    bar = alt.Chart(type_counts).mark_bar(color="#6366f1").encode(
        x=alt.X("Count:Q"),
        y=alt.Y("Type:N", sort="-x"),
        tooltip=["Type", "Count"]
    ).properties(height=300)
    st.altair_chart(bar, use_container_width=True)

    # ── Alerts over time ──────────────────────────────────────────────
    st.subheader("⏱️ Alerts Over Time")
    time_df = filtered.dropna(subset=["timestamp"]).copy()
    if not time_df.empty:
        time_df["hour"] = time_df["timestamp"].dt.floor("H")
        tc = time_df.groupby(["hour", "severity"]).size().reset_index(name="count")
        line = alt.Chart(tc).mark_line(point=True).encode(
            x="hour:T",
            y="count:Q",
            color=alt.Color("severity:N", scale=alt.Scale(
                domain=["Critical", "High", "Medium", "Low"],
                range=["#ef4444", "#f97316", "#eab308", "#22c55e"]
            )),
            tooltip=["hour:T", "severity:N", "count:Q"]
        ).properties(height=220)
        st.altair_chart(line, use_container_width=True)

    # ── Alert cards ───────────────────────────────────────────────────
    st.subheader("📋 Alert Details")

    display_cols = [c for c in
        ["timestamp", "severity", "type", "username", "ip_address",
         "message", "mitre_tactic", "source", "risk_score"]
        if c in filtered.columns]

    # Colour-coded severity column
    def color_severity(val):
        colors = {
            "Critical": "background-color:#fecaca;color:#991b1b",
            "High":     "background-color:#fed7aa;color:#9a3412",
            "Medium":   "background-color:#fef08a;color:#713f12",
            "Low":      "background-color:#bbf7d0;color:#14532d",
        }
        return colors.get(val, "")

    styled = filtered[display_cols].sort_values("timestamp", ascending=False)
    if "severity" in styled.columns:
        st.dataframe(
            styled.style.applymap(color_severity, subset=["severity"]),
            use_container_width=True,
            height=450,
        )
    else:
        st.dataframe(styled, use_container_width=True, height=450)

    # ── MITRE breakdown ───────────────────────────────────────────────
    if "mitre_tactic" in filtered.columns:
        st.subheader("🛡️ MITRE ATT&CK Tactic Coverage")
        mitre = filtered["mitre_tactic"].value_counts().reset_index()
        mitre.columns = ["Tactic", "Count"]
        mb = alt.Chart(mitre).mark_bar(color="#8b5cf6").encode(
            x=alt.X("Count:Q"),
            y=alt.Y("Tactic:N", sort="-x"),
            tooltip=["Tactic", "Count"]
        ).properties(height=250)
        st.altair_chart(mb, use_container_width=True)

    # ── Export ────────────────────────────────────────────────────────
    csv = filtered.to_csv(index=False).encode("utf-8")
    st.download_button("⬇️ Export Alerts CSV", csv, "alerts_export.csv", "text/csv")
import streamlit as st
import json
import pandas as pd
import datetime
import altair as alt
import os


def alerts_page(alerts=None):
    st.title("🚨 Security Alerts")

    if alerts is None:
        try:
            with open("data/final_alerts.json") as f:
                alerts = json.load(f)
        except Exception:
            st.warning("No alerts found. Run your pipeline file first.")
            st.info("Download your personal agent from the home page and run it on your Windows PC.")
            return

    if not alerts:
        st.success("No alerts — system looks clean!")
        return

    df = pd.DataFrame(alerts)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Alerts",  len(df))
    c2.metric("🔴 Critical",   len(df[df["severity"]=="Critical"]))
    c3.metric("🟠 High",       len(df[df["severity"]=="High"]))
    c4.metric("🟡 Medium",     len(df[df["severity"]=="Medium"]))
    c5.metric("🟢 Low",        len(df[df["severity"]=="Low"]))

    st.divider()

    with st.expander("🔧 Filters", expanded=True):
        col1, col2, col3, col4 = st.columns(4)
        date_filter   = col1.selectbox("Date", ["All","Today","Yesterday","Custom Range"])
        sev_filter    = col2.selectbox("Severity", ["All","Critical","High","Medium","Low"])
        source_filter = col3.selectbox("Source", ["All","rule","ml"])
        type_opts     = ["All"] + sorted(df["type"].dropna().unique().tolist()) if "type" in df.columns else ["All"]
        type_filter   = col4.selectbox("Alert Type", type_opts)

    filtered = df.copy()
    today    = datetime.date.today()

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
    if type_filter != "All" and "type" in filtered.columns:
        filtered = filtered[filtered["type"] == type_filter]

    st.write(f"Showing **{len(filtered)}** alerts")

    if "type" in filtered.columns:
        st.subheader("📊 Alert Type Breakdown")
        tc = filtered["type"].value_counts().head(12).reset_index()
        tc.columns = ["Type","Count"]
        bar = alt.Chart(tc).mark_bar(color="#6366f1").encode(
            x=alt.X("Count:Q"), y=alt.Y("Type:N", sort="-x"), tooltip=["Type","Count"]
        ).properties(height=300)
        st.altair_chart(bar, use_container_width=True)

    st.subheader("📋 Alert Details")
    display_cols = [c for c in ["timestamp","severity","type","username","ip_address","message","mitre_tactic","source","risk_score"] if c in filtered.columns]

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
        st.dataframe(styled.style.map(color_severity, subset=["severity"]), use_container_width=True, height=450)
    else:
        st.dataframe(styled, use_container_width=True, height=450)

    if "mitre_tactic" in filtered.columns:
        st.subheader("🛡️ MITRE ATT&CK Coverage")
        mt = filtered["mitre_tactic"].value_counts().reset_index()
        mt.columns = ["Tactic","Count"]
        mb = alt.Chart(mt).mark_bar(color="#8b5cf6").encode(
            x=alt.X("Count:Q"), y=alt.Y("Tactic:N", sort="-x"), tooltip=["Tactic","Count"]
        ).properties(height=250)
        st.altair_chart(mb, use_container_width=True)

    csv = filtered.to_csv(index=False).encode("utf-8")
    st.download_button("⬇️ Export Alerts CSV", csv, "alerts_export.csv", "text/csv")
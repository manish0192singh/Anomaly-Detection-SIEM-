import streamlit as st
import pandas as pd
import datetime
import altair as alt
import os

# Import pages
from logs_page import logs_page
# from anomalies_page import anomalies_page
from alerts_page import alerts_page
from user_behaviour_page import user_behaviour_page
from data_loader import data_loader_page

# App Config
st.set_page_config(page_title="AI-Powered SIEM", layout="wide")

# Sidebar Navigation
st.sidebar.title("⚡ SIEM Dashboard")

menu = st.sidebar.radio(
    "Navigation",
    [
        "Dashboard",
        "Logs",
        "Anomalies",
        "Alerts",
        "User Behaviour",
        "Data Loader",
        "Settings"
    ]
)

# ----------------------------
# DASHBOARD (MAIN PAGE)
# ----------------------------
if menu == "Dashboard":
    st.title("📊 SIEM Overview Dashboard")

    # Quick loader
    def load(file):
        return pd.read_csv(file) if os.path.exists(file) else None

    logs = load("data/structured_logs.csv")
    anomalies = load("data/anomalies.csv")

    # ===== SUMMARY METRICS =====
    st.subheader("📌 Summary Metrics")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Logs", len(logs) if logs is not None else 0)
    col2.metric("Total Anomalies", len(anomalies) if anomalies is not None else 0)
    col3.metric("Unique Users", logs["username"].nunique() if logs is not None else 0)
    col4.metric("Alerts", "Shown on Alerts Page")

    # ===== TODAY'S ACTIVITY =====
    st.subheader("📅 Today’s Activity")

    today = datetime.date.today()

    if logs is not None:
        logs["timestamp"] = pd.to_datetime(logs["timestamp"], errors="coerce")
        today_logs = logs[logs["timestamp"].dt.date == today]
        st.write(f"🔹 Logs Today: **{len(today_logs)}**")

    if anomalies is not None:
        anomalies["timestamp"] = pd.to_datetime(anomalies["timestamp"], errors="coerce")
        today_anomalies = anomalies[anomalies["timestamp"].dt.date == today]
        st.write(f"🔹 Anomalies Today: **{len(today_anomalies)}**")

    # ===== LOGS PER HOUR CHART =====
    st.subheader("📈 Logs Per Hour")

    if logs is not None:
        logs["hour"] = logs["timestamp"].dt.hour
        hourly = logs.groupby("hour").size().reset_index(name="count")

        chart = alt.Chart(hourly).mark_bar().encode(
            x="hour:O",
            y="count:Q",
            tooltip=["hour", "count"]
        ).properties(title="Logs Per Hour")

        st.altair_chart(chart, width="stretch")

    st.success("Dashboard Loaded Successfully!")

# ----------------------------
# OTHER PAGES
# ----------------------------
elif menu == "Logs":
    logs_page()

elif menu == "Anomalies":
    anomalies_page()

elif menu == "Alerts":
    alerts_page()

elif menu == "User Behaviour":
    user_behaviour_page()

elif menu == "Data Loader":
    data_loader_page()

elif menu == "Settings":
    st.title("Settings")
    st.info("Settings will be added soon.")
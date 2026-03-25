import streamlit as st
import json
import pandas as pd
import datetime

def alerts_page():

    st.title("Security Alerts")

    try:
        # Load alerts JSON
        with open("data/final_alerts.json") as f:
            alerts = json.load(f)

        df = pd.DataFrame(alerts)

        # Convert timestamp → datetime format
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

        st.subheader("📅 Filter Alerts by Date")

        date_filter = st.selectbox(
            "Select Date Filter",
            ["All", "Today", "Yesterday", "Custom Range"]
        )

        # === DATE FILTERS ===
        if date_filter == "Today":
            today = datetime.date.today()
            df = df[df["timestamp"].dt.date == today]

        elif date_filter == "Yesterday":
            yesterday = datetime.date.today() - datetime.timedelta(days=1)
            df = df[df["timestamp"].dt.date == yesterday]

        elif date_filter == "Custom Range":
            col1, col2 = st.columns(2)
            start_date = col1.date_input("Start Date")
            end_date = col2.date_input("End Date")

            df = df[
                (df["timestamp"].dt.date >= start_date)
                & (df["timestamp"].dt.date <= end_date)
            ]

        # === HOUR FILTER ===
        st.subheader("⏰ Filter by Hour")

        hours = [f"{h:02d}:00" for h in range(24)]
        hour_selected = st.selectbox("Select Hour", ["All"] + hours)

        if hour_selected != "All":
            selected_hour = int(hour_selected.split(":")[0])
            df = df[df["timestamp"].dt.hour == selected_hour]

        # === SHOW RESULTS ===
        st.write(f"Showing {len(df)} alerts after filtering")

        st.dataframe(df)

    except Exception as e:
        st.warning("No alerts generated yet.")
        st.error(str(e))
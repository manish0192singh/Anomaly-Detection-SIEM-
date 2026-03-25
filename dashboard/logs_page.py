import streamlit as st
import pandas as pd
import datetime

def logs_page():

    st.title("System Logs")

    try:
        df = pd.read_csv("data/structured_logs.csv")

        # Convert timestamp to datetime
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

        st.subheader("📅 Date Filters")
        date_filter = st.selectbox(
            "Select Date Filter",
            ["All", "Today", "Yesterday", "Custom Range"]
        )

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
                (df["timestamp"].dt.date >= start_date) &
                (df["timestamp"].dt.date <= end_date)
            ]

        # Hour filter
        st.subheader("⏰ Hour Filter")
        hours = [f"{h:02d}:00" for h in range(24)]
        hour_selected = st.selectbox("Select Hour", ["All"] + hours)

        if hour_selected != "All":
            selected_hour = int(hour_selected.split(":")[0])
            df = df[df["timestamp"].dt.hour == selected_hour]

        st.write(f"Showing {len(df)} logs after filtering")

        st.dataframe(df)

    except Exception as e:
        st.warning("No logs found. Run log collector first.")
        st.error(str(e))
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt


def user_behaviour_page():

    st.title("User Behaviour Analytics")

    try:

        df = pd.read_csv("data/structured_logs.csv")

    except:
        st.error("Structured logs not found. Run preprocessing first.")
        return


   
    if "username" in df.columns:

        total_users = df["username"].nunique()

        st.metric("Total Unique Users", total_users)


    st.subheader("Most Active Users")

    if "username" in df.columns:

        user_counts = df["username"].value_counts().head(10)

        st.bar_chart(user_counts)


    # ------------------------------
    # Login Activity by Hour
    # ------------------------------

    st.subheader("Activity by Hour")

    if "timestamp" in df.columns:

        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

        df["hour"] = df["timestamp"].dt.hour

        hour_counts = df["hour"].value_counts().sort_index()

        st.line_chart(hour_counts)


    # ------------------------------
    # Failed Login Attempts
    # ------------------------------

    st.subheader("Failed Login Attempts")

    if "message" in df.columns:

        failed_logins = df[df["message"].str.contains("fail", case=False, na=False)]

        if "username" in failed_logins.columns:

            failed_counts = failed_logins["username"].value_counts()

            st.bar_chart(failed_counts)

        st.write("Total Failed Logins:", len(failed_logins))


    # ------------------------------
    # Suspicious Users
    # ------------------------------

    st.subheader("Potentially Suspicious Users")

    if "username" in df.columns:

        suspicious_users = df["username"].value_counts()

        suspicious_users = suspicious_users[suspicious_users > 10]

        if len(suspicious_users) > 0:

            st.dataframe(suspicious_users)

        else:

            st.success("No suspicious users detected")

import streamlit as st
from logs_page import logs_page
from anomalies_page import anomalies_page
from alerts_page import alerts_page
from user_behaviour_page import user_behaviour_page
from settings_page import settings_page

st.set_page_config(page_title="AI-Powered SIEM", layout="wide")

st.sidebar.title("⚡ SIEM Dashboard")

menu = st.sidebar.radio(
    "Navigation",
    ["Dashboard", "Logs", "Anomalies", "Alerts", "User Behaviour", "Settings"]
)

if menu == "Dashboard":
    st.title("Welcome to AI-Powered Anomaly Detection SIEM")
    st.write("Use the sidebar to navigate through the dashboard.")
elif menu == "Logs":
    logs_page()
elif menu == "Anomalies":
    anomalies_page()
elif menu == "Alerts":
    alerts_page()
elif menu == "User Behaviour":
    user_behaviour_page()
elif menu == "Settings":
    settings_page()
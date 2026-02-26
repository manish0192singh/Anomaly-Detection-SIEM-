import streamlit as st
from data_loader import load_alerts

def alerts_page():
    st.title("⚠️ Rule-Based Alerts")

    alerts = load_alerts()

    st.subheader("Generated Alerts")
    st.dataframe(alerts, use_container_width=True)
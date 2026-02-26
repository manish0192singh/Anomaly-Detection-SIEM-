import streamlit as st

def settings_page():
    st.title("⚙️ Settings")

    st.subheader("Anomaly Detection Threshold")
    st.slider("Set threshold", 0.0, 1.0, 0.5)

    st.subheader("Toggle Rule-Based Alerts")
    st.checkbox("Enable Rule-Based Alerts", True)

    st.subheader("Log Retention")
    st.number_input("Days to retain logs", min_value=1, max_value=365, value=30)

    st.success("Settings saved (not functional yet, backend required).")
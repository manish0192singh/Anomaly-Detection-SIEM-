import streamlit as st
from data_loader import load_anomalies

def anomalies_page():
    st.title("🚨 Anomaly Detection Results")

    anomalies = load_anomalies()

    st.subheader("Detected Anomalies")
    st.dataframe(anomalies, use_container_width=True)

    st.info("Higher anomaly score means higher risk.")
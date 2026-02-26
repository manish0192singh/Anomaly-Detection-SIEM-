import streamlit as st
from data_loader import load_logs

def logs_page():
    st.title("📄 System Logs")
    logs = load_logs()

    st.subheader("All Logs")
    st.dataframe(logs, use_container_width=True)
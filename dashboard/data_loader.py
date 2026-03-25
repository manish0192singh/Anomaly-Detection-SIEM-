import streamlit as st
import os
import pandas as pd
from datetime import datetime

DATA_FILES = {
    "Processed Logs": "data/processed_logs.csv",
    "Structured Logs": "data/structured_logs.csv",
    "Anomalies": "data/anomalies.csv"
}

def get_file_info(path):
    if not os.path.exists(path):
        return None

    size = os.path.getsize(path) / 1024  # KB
    modified = datetime.fromtimestamp(os.path.getmtime(path))

    return {
        "size": f"{size:.2f} KB",
        "modified": modified.strftime("%Y-%m-%d %H:%M:%S")
    }

def data_loader_page():
    st.title("📥 Data Loader")
    st.write("Check data status, reload datasets, and verify backend outputs.")

    st.subheader("📊 Data File Status")

    status_data = []

    for name, path in DATA_FILES.items():
        info = get_file_info(path)

        if info:
            status_data.append({
                "File": name,
                "Status": "Available ✅",
                "Last Updated": info["modified"],
                "Size": info["size"]
            })
        else:
            status_data.append({
                "File": name,
                "Status": "Missing ❌",
                "Last Updated": "-",
                "Size": "-"
            })

    st.table(status_data)

    st.subheader("🔄 Reload Data")

    selected_file = st.selectbox(
        "Choose file to load:",
        list(DATA_FILES.keys())
    )

    if st.button("Load Selected File"):
        path = DATA_FILES[selected_file]

        if os.path.exists(path):
            try:
                df = pd.read_csv(path)
                st.success(f"{selected_file} loaded successfully!")
                st.write(f"Showing first 20 rows of {selected_file}:")
                st.dataframe(df.head(20))
            except Exception as e:
                st.error(f"Error loading {selected_file}: {e}")
        else:
            st.error(f"{selected_file} does not exist.")
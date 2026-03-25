import streamlit as st
import pandas as pd

def anomalies_page():

    st.title("ML Anomaly Detection")

    try:
        df = pd.read_csv("data/anomalies.csv")

        anomalies = df[df["anomaly"] == -1]

        st.write("Total Anomalies:", len(anomalies))

        st.dataframe(anomalies)

    except:
        st.warning("No anomaly data found.")
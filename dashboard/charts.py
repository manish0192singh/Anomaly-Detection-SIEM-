import streamlit as st
import matplotlib.pyplot as plt

def behaviour_chart(df):
    plt.figure(figsize=(10, 4))
    plt.plot(df["timestamp"], df["login_count"])
    plt.xticks(rotation=45)
    plt.title("User Login Behaviour")
    st.pyplot(plt)
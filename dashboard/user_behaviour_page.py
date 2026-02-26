import streamlit as st
from data_loader import load_user_behaviour
from charts import behaviour_chart

def user_behaviour_page():
    st.title("👤 User Behaviour Analytics")

    df = load_user_behaviour()

    st.subheader("User Behaviour Summary")
    st.dataframe(df, use_container_width=True)

    st.subheader("Login Behaviour Chart")
    behaviour_chart(df)
import streamlit as st
import pandas as pd
import altair as alt
import json
import os
from datetime import datetime


def user_behaviour_page(df=None, alerts_list=None):
    st.title("👤 User Behaviour Analytics")
    st.caption("Analyse user activity patterns, detect suspicious behaviour, and investigate individual users.")

    if df is None or df.empty:
        try:
            df = pd.read_csv("data/structured_logs.csv")
        except Exception:
            st.warning("No log data found. Run your pipeline file first.")
            st.info("Download your personal agent from the home page and run it on your Windows PC.")
            return

    if df.empty:
        st.warning("No log data available.")
        return

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    if alerts_list is None:
        alerts_list = []
        if os.path.exists("data/final_alerts.json"):
            try:
                with open("data/final_alerts.json") as f:
                    alerts_list = json.load(f)
            except Exception:
                pass

    alerted_users = set(a.get("username","") for a in alerts_list if a.get("severity") in ("Critical","High"))

    total_users  = df["username"].nunique() if "username" in df.columns else 0
    total_events = len(df)
    failed_logins= len(df[df["event_type_clean"]=="Failed Login"]) if "event_type_clean" in df.columns else 0
    night_events = len(df[df["is_night"]==1]) if "is_night" in df.columns else 0

    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Total Users",    total_users)
    c2.metric("Total Events",   total_events)
    c3.metric("Failed Logins",  failed_logins)
    c4.metric("Night Activity", night_events)

    st.divider()

    tab1, tab2, tab3, tab4 = st.tabs(["📊 Activity Overview","🚨 Suspicious Users","🔍 User Deep Dive","⏰ Time Patterns"])

    with tab1:
        col_l, col_r = st.columns(2)
        with col_l:
            st.subheader("👥 Most Active Users")
            user_counts = df["username"].value_counts().head(10).reset_index()
            user_counts.columns = ["Username","Event Count"]
            bar = alt.Chart(user_counts).mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4).encode(
                x=alt.X("Event Count:Q"), y=alt.Y("Username:N", sort="-x"),
                color=alt.value("#6366f1"), tooltip=["Username","Event Count"]
            ).properties(height=300)
            st.altair_chart(bar, use_container_width=True)

        with col_r:
            st.subheader("📋 Event Type Breakdown")
            if "event_type_clean" in df.columns:
                et = df["event_type_clean"].value_counts().reset_index()
                et.columns = ["Event Type","Count"]
                donut = alt.Chart(et).mark_arc(innerRadius=55, outerRadius=110).encode(
                    theta=alt.Theta("Count:Q"),
                    color=alt.Color("Event Type:N"),
                    tooltip=["Event Type","Count"]
                ).properties(height=300)
                st.altair_chart(donut, use_container_width=True)

        st.subheader("❌ Failed Login Attempts Per User")
        if "event_type_clean" in df.columns:
            failed = df[df["event_type_clean"]=="Failed Login"]
            if not failed.empty:
                fc = failed["username"].value_counts().head(10).reset_index()
                fc.columns = ["Username","Failed Attempts"]
                fb = alt.Chart(fc).mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4).encode(
                    x=alt.X("Failed Attempts:Q"), y=alt.Y("Username:N", sort="-x"),
                    color=alt.Color("Failed Attempts:Q", scale=alt.Scale(scheme="reds"), legend=None),
                    tooltip=["Username","Failed Attempts"]
                ).properties(height=250)
                st.altair_chart(fb, use_container_width=True)

    with tab2:
        st.subheader("🚨 User Risk Summary")
        user_risk = []
        for user in df["username"].unique():
            if user in ("Unknown","-",""): continue
            u_df   = df[df["username"]==user]
            failed = len(u_df[u_df["event_type_clean"]=="Failed Login"]) if "event_type_clean" in u_df.columns else 0
            priv   = len(u_df[u_df["event_type_clean"]=="Privilege Escalation"]) if "event_type_clean" in u_df.columns else 0
            night  = len(u_df[u_df["is_night"]==1]) if "is_night" in u_df.columns else 0
            ips    = u_df["ip_address"].nunique() if "ip_address" in u_df.columns else 0
            risk   = (failed*3)+(priv*10)+(night*2)+(ips*5 if ips>2 else 0)+(20 if user in alerted_users else 0)
            user_risk.append({"Username":user,"Total Events":len(u_df),"Failed Logins":failed,
                              "Priv Escalations":priv,"Night Activity":night,"Unique IPs":ips,
                              "In Alerts":"⚠️ Yes" if user in alerted_users else "✅ No","Risk Score":risk})

        if user_risk:
            risk_df = pd.DataFrame(user_risk).sort_values("Risk Score", ascending=False)
            def highlight_risk(val):
                if isinstance(val,(int,float)):
                    if val>=30: return "background-color:#fecaca;color:#991b1b"
                    if val>=15: return "background-color:#fed7aa;color:#9a3412"
                    if val>=5:  return "background-color:#fef08a;color:#713f12"
                return ""
            st.dataframe(risk_df.style.applymap(highlight_risk, subset=["Risk Score"]), use_container_width=True, height=400)

    with tab3:
        st.subheader("🔍 Individual User Investigation")
        users_list    = sorted([u for u in df["username"].unique() if u not in ("Unknown","-","")])
        selected_user = st.selectbox("Select User", users_list)
        if selected_user:
            u_df = df[df["username"]==selected_user].copy().sort_values("timestamp", ascending=False)
            st.markdown(f"### Profile: `{selected_user}`")
            m1,m2,m3,m4 = st.columns(4)
            m1.metric("Total Events", len(u_df))
            m2.metric("Unique IPs",   u_df["ip_address"].nunique() if "ip_address" in u_df.columns else "N/A")
            m3.metric("First Seen",   str(u_df["timestamp"].min())[:10])
            m4.metric("Last Seen",    str(u_df["timestamp"].max())[:10])

            col1, col2 = st.columns(2)
            with col1:
                st.markdown("**Event Types**")
                if "event_type_clean" in u_df.columns:
                    etu = u_df["event_type_clean"].value_counts().reset_index()
                    etu.columns = ["Event Type","Count"]
                    ub = alt.Chart(etu).mark_bar(color="#6366f1").encode(
                        x=alt.X("Count:Q"), y=alt.Y("Event Type:N", sort="-x"), tooltip=["Event Type","Count"]
                    ).properties(height=220)
                    st.altair_chart(ub, use_container_width=True)
            with col2:
                st.markdown("**Activity by Hour**")
                u_df["hour"] = u_df["timestamp"].dt.hour
                hc = u_df.groupby("hour").size().reset_index(name="count")
                hchart = alt.Chart(hc).mark_bar().encode(
                    x=alt.X("hour:O"), y=alt.Y("count:Q"),
                    color=alt.condition((alt.datum.hour<=5)|(alt.datum.hour>=22), alt.value("#ef4444"), alt.value("#8b5cf6")),
                    tooltip=["hour:O","count:Q"]
                ).properties(height=220)
                st.altair_chart(hchart, use_container_width=True)

            user_alerts = [a for a in alerts_list if a.get("username")==selected_user]
            if user_alerts:
                st.markdown(f"**⚠️ Alerts ({len(user_alerts)})**")
                st.dataframe(pd.DataFrame(user_alerts)[["timestamp","severity","type","message"]], use_container_width=True, height=180)
            else:
                st.success(f"✅ No alerts for {selected_user}")

            show_cols = [c for c in ["timestamp","event_type_clean","ip_address","computer","message"] if c in u_df.columns]
            st.markdown("**Recent Activity (last 20)**")
            st.dataframe(u_df[show_cols].head(20), use_container_width=True, height=300)

    with tab4:
        st.subheader("⏰ Activity Time Patterns")
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Events by Hour**")
            df["hour"] = df["timestamp"].dt.hour
            hourly = df.groupby("hour").size().reset_index(name="count")
            hb = alt.Chart(hourly).mark_bar().encode(
                x=alt.X("hour:O"), y=alt.Y("count:Q"),
                color=alt.Color("count:Q", scale=alt.Scale(scheme="blues"), legend=None),
                tooltip=["hour:O","count:Q"]
            ).properties(height=250)
            st.altair_chart(hb, use_container_width=True)

        with col2:
            st.markdown("**Events by Day of Week**")
            df["day_name"] = df["timestamp"].dt.day_name()
            day_order = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
            daily = df.groupby("day_name").size().reset_index(name="count")
            daily["day_name"] = pd.Categorical(daily["day_name"], categories=day_order, ordered=True)
            daily = daily.sort_values("day_name")
            db = alt.Chart(daily).mark_bar().encode(
                x=alt.X("day_name:N", sort=day_order), y=alt.Y("count:Q"),
                color=alt.Color("count:Q", scale=alt.Scale(scheme="purples"), legend=None),
                tooltip=["day_name:N","count:Q"]
            ).properties(height=250)
            st.altair_chart(db, use_container_width=True)

        if "is_night" in df.columns:
            st.subheader("🌙 After-Hours Activity")
            night_df = df[df["is_night"]==1]
            if not night_df.empty:
                n1,n2,n3 = st.columns(3)
                n1.metric("Night Events",      len(night_df))
                n2.metric("Night Users",       night_df["username"].nunique())
                n3.metric("Top Night User",    night_df["username"].value_counts().index[0] if len(night_df)>0 else "N/A")
                nu = night_df["username"].value_counts().head(10).reset_index()
                nu.columns = ["Username","Night Events"]
                nb = alt.Chart(nu).mark_bar(color="#7c3aed").encode(
                    x=alt.X("Night Events:Q"), y=alt.Y("Username:N", sort="-x"), tooltip=["Username","Night Events"]
                ).properties(height=250)
                st.altair_chart(nb, use_container_width=True)
            else:
                st.success("No after-hours activity detected.")
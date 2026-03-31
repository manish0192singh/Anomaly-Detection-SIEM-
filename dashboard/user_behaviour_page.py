import streamlit as st
import pandas as pd
import altair as alt
import json
import os
from datetime import datetime, timedelta


def user_behaviour_page():
    st.title("👤 User Behaviour Analytics")
    st.caption("Analyse user activity patterns, detect suspicious behaviour, and investigate individual users.")

    # ── Load data ─────────────────────────────────────────────────────
    try:
        df = pd.read_csv("data/structured_logs.csv")
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    except Exception:
        st.error("Structured logs not found. Run the pipeline first.")
        return

    if df.empty:
        st.warning("No log data available.")
        return

    # Load alerts for cross-referencing
    alerts = []
    if os.path.exists("data/final_alerts.json"):
        with open("data/final_alerts.json") as f:
            alerts = json.load(f)
    alerted_users = set(a.get("username", "") for a in alerts if a.get("severity") in ("Critical", "High"))

    # ── Summary metrics ───────────────────────────────────────────────
    st.subheader("📌 Overview")

    total_users   = df["username"].nunique()
    total_events  = len(df)
    failed_logins = len(df[df["event_type_clean"] == "Failed Login"]) if "event_type_clean" in df.columns else 0
    locked_out    = len(df[df["event_type_clean"] == "Account Locked Out"]) if "event_type_clean" in df.columns else 0
    night_events  = len(df[df["is_night"] == 1]) if "is_night" in df.columns else 0

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Users",       total_users)
    c2.metric("Total Events",      total_events)
    c3.metric("Failed Logins",     failed_logins)
    c4.metric("Accounts Locked",   locked_out)
    c5.metric("Night Activity",    night_events)

    st.divider()

    # ── Tab layout ────────────────────────────────────────────────────
    tab1, tab2, tab3, tab4 = st.tabs([
        "📊 Activity Overview",
        "🚨 Suspicious Users",
        "🔍 User Deep Dive",
        "⏰ Time Patterns"
    ])

    # ==================================================================
    # TAB 1 — Activity Overview
    # ==================================================================
    with tab1:

        col_l, col_r = st.columns(2)

        # Most active users
        with col_l:
            st.subheader("👥 Most Active Users")
            st.caption("Users with the highest total event count")

            user_counts = df["username"].value_counts().head(10).reset_index()
            user_counts.columns = ["Username", "Event Count"]

            bar = alt.Chart(user_counts).mark_bar(
                cornerRadiusTopRight=4,
                cornerRadiusBottomRight=4
            ).encode(
                x=alt.X("Event Count:Q", title="Total Events"),
                y=alt.Y("Username:N", sort="-x", title=""),
                color=alt.condition(
                    alt.datum.Username == user_counts["Username"].iloc[0],
                    alt.value("#6366f1"),
                    alt.value("#a5b4fc")
                ),
                tooltip=["Username", "Event Count"]
            ).properties(height=300)
            st.altair_chart(bar, use_container_width=True)

        # Event type breakdown
        with col_r:
            st.subheader("📋 Event Type Breakdown")
            st.caption("What types of events are most common")

            if "event_type_clean" in df.columns:
                et = df["event_type_clean"].value_counts().reset_index()
                et.columns = ["Event Type", "Count"]

                color_map = {
                    "Successful Login":     "#22c55e",
                    "Failed Login":         "#ef4444",
                    "Logout":               "#6366f1",
                    "Privilege Escalation": "#f97316",
                    "Process Created":      "#8b5cf6",
                    "File Access":          "#06b6d4",
                    "Account Locked Out":   "#dc2626",
                    "Other":                "#94a3b8",
                }
                et["Color"] = et["Event Type"].map(color_map).fillna("#94a3b8")

                donut = alt.Chart(et).mark_arc(innerRadius=55, outerRadius=110).encode(
                    theta=alt.Theta("Count:Q"),
                    color=alt.Color("Event Type:N",
                        scale=alt.Scale(
                            domain=list(color_map.keys()),
                            range=list(color_map.values())
                        )
                    ),
                    tooltip=["Event Type", "Count"]
                ).properties(height=300)
                st.altair_chart(donut, use_container_width=True)

        st.divider()

        # Failed logins per user
        st.subheader("❌ Failed Login Attempts Per User")
        st.caption("Users with the most failed login attempts — potential brute force targets or attackers")

        if "event_type_clean" in df.columns:
            failed = df[df["event_type_clean"] == "Failed Login"]
            if not failed.empty:
                fail_counts = failed["username"].value_counts().head(10).reset_index()
                fail_counts.columns = ["Username", "Failed Attempts"]

                fail_bar = alt.Chart(fail_counts).mark_bar(
                    cornerRadiusTopRight=4,
                    cornerRadiusBottomRight=4
                ).encode(
                    x=alt.X("Failed Attempts:Q"),
                    y=alt.Y("Username:N", sort="-x", title=""),
                    color=alt.Color("Failed Attempts:Q",
                        scale=alt.Scale(scheme="reds"),
                        legend=None
                    ),
                    tooltip=["Username", "Failed Attempts"]
                ).properties(height=250)
                st.altair_chart(fail_bar, use_container_width=True)
            else:
                st.success("No failed login attempts found.")

    # ==================================================================
    # TAB 2 — Suspicious Users
    # ==================================================================
    with tab2:
        st.subheader("🚨 User Risk Summary")
        st.caption("Users ranked by suspicious activity indicators")

        # Build risk table
        user_risk = []
        for user in df["username"].unique():
            if user in ("Unknown", "-", ""):
                continue

            u_df     = df[df["username"] == user]
            failed   = len(u_df[u_df["event_type_clean"] == "Failed Login"]) \
                       if "event_type_clean" in u_df.columns else 0
            priv     = len(u_df[u_df["event_type_clean"] == "Privilege Escalation"]) \
                       if "event_type_clean" in u_df.columns else 0
            night    = len(u_df[u_df["is_night"] == 1]) if "is_night" in u_df.columns else 0
            total    = len(u_df)
            unique_ips = u_df["ip_address"].nunique() if "ip_address" in u_df.columns else 0
            in_alerts  = user in alerted_users

            # Simple risk score
            risk = (failed * 3) + (priv * 10) + (night * 2) + \
                   (unique_ips * 5 if unique_ips > 2 else 0) + \
                   (20 if in_alerts else 0)

            user_risk.append({
                "Username":         user,
                "Total Events":     total,
                "Failed Logins":    failed,
                "Priv Escalations": priv,
                "Night Activity":   night,
                "Unique IPs":       unique_ips,
                "In Alerts":        "⚠️ Yes" if in_alerts else "✅ No",
                "Risk Score":       risk,
            })

        if user_risk:
            risk_df = pd.DataFrame(user_risk).sort_values("Risk Score", ascending=False)

            # Colour code risk score
            def highlight_risk(val):
                if isinstance(val, (int, float)):
                    if val >= 30:
                        return "background-color:#fecaca;color:#991b1b"
                    if val >= 15:
                        return "background-color:#fed7aa;color:#9a3412"
                    if val >= 5:
                        return "background-color:#fef08a;color:#713f12"
                return ""

            st.dataframe(
                risk_df.style.applymap(highlight_risk, subset=["Risk Score"]),
                use_container_width=True,
                height=400,
            )

            st.caption("🔴 Risk ≥ 30 = High Risk   🟠 Risk ≥ 15 = Medium Risk   🟡 Risk ≥ 5 = Low Risk")

        st.divider()

        # Suspicious users bar chart
        st.subheader("📊 Top Risky Users")
        if user_risk:
            top_risk = risk_df.head(10)
            rb = alt.Chart(top_risk).mark_bar(color="#ef4444").encode(
                x=alt.X("Risk Score:Q"),
                y=alt.Y("Username:N", sort="-x", title=""),
                tooltip=["Username", "Risk Score", "Failed Logins", "Priv Escalations", "Night Activity"]
            ).properties(height=280)
            st.altair_chart(rb, use_container_width=True)

    # ==================================================================
    # TAB 3 — User Deep Dive
    # ==================================================================
    with tab3:
        st.subheader("🔍 Individual User Investigation")
        st.caption("Select a user to see their full activity profile")

        users_list = sorted([u for u in df["username"].unique()
                             if u not in ("Unknown", "-", "")])
        selected_user = st.selectbox("Select User", users_list)

        if selected_user:
            u_df = df[df["username"] == selected_user].copy()
            u_df = u_df.sort_values("timestamp", ascending=False)

            # User metrics
            st.markdown(f"### Profile: `{selected_user}`")

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("Total Events",  len(u_df))
            m2.metric("Unique IPs",    u_df["ip_address"].nunique() if "ip_address" in u_df.columns else "N/A")
            m3.metric("First Seen",    str(u_df["timestamp"].min())[:10])
            m4.metric("Last Seen",     str(u_df["timestamp"].max())[:10])

            col1, col2 = st.columns(2)

            # Event type breakdown for this user
            with col1:
                st.markdown("**Event Types**")
                if "event_type_clean" in u_df.columns:
                    et_user = u_df["event_type_clean"].value_counts().reset_index()
                    et_user.columns = ["Event Type", "Count"]
                    ub = alt.Chart(et_user).mark_bar(color="#6366f1").encode(
                        x=alt.X("Count:Q"),
                        y=alt.Y("Event Type:N", sort="-x", title=""),
                        tooltip=["Event Type", "Count"]
                    ).properties(height=220)
                    st.altair_chart(ub, use_container_width=True)

            # Activity by hour for this user
            with col2:
                st.markdown("**Activity by Hour of Day**")
                u_df["hour"] = u_df["timestamp"].dt.hour
                hour_counts = u_df.groupby("hour").size().reset_index(name="count")

                hc = alt.Chart(hour_counts).mark_bar(color="#8b5cf6").encode(
                    x=alt.X("hour:O", title="Hour"),
                    y=alt.Y("count:Q", title="Events"),
                    color=alt.condition(
                        (alt.datum.hour <= 5) | (alt.datum.hour >= 22),
                        alt.value("#ef4444"),   # red for night hours
                        alt.value("#8b5cf6")
                    ),
                    tooltip=["hour:O", "count:Q"]
                ).properties(height=220)
                st.altair_chart(hc, use_container_width=True)
                st.caption("🔴 Red bars = night hours (10pm–5am)")

            # IPs used
            if "ip_address" in u_df.columns:
                st.markdown("**IP Addresses Used**")
                ips_used = u_df["ip_address"].dropna().value_counts().reset_index()
                ips_used.columns = ["IP Address", "Times Used"]
                st.dataframe(ips_used, use_container_width=True, height=150)

            # Related alerts
            user_alerts = [a for a in alerts if a.get("username") == selected_user]
            if user_alerts:
                st.markdown(f"**⚠️ Alerts for this user ({len(user_alerts)})**")
                alert_df = pd.DataFrame(user_alerts)[
                    ["timestamp", "severity", "type", "message"]
                ]
                st.dataframe(alert_df, use_container_width=True, height=180)
            else:
                st.success(f"✅ No alerts found for {selected_user}")

            # Recent activity log
            st.markdown("**Recent Activity (last 20 events)**")
            show_cols = [c for c in ["timestamp", "event_type_clean", "ip_address",
                                      "computer", "message"] if c in u_df.columns]
            st.dataframe(u_df[show_cols].head(20), use_container_width=True, height=300)

    # ==================================================================
    # TAB 4 — Time Patterns
    # ==================================================================
    with tab4:
        st.subheader("⏰ Activity Time Patterns")
        st.caption("When are users most active? Spot after-hours anomalies.")

        col1, col2 = st.columns(2)

        # Activity heatmap by hour and day
        with col1:
            st.markdown("**Events by Hour of Day**")
            df["hour"] = df["timestamp"].dt.hour
            hourly = df.groupby("hour").size().reset_index(name="count")

            heatbar = alt.Chart(hourly).mark_bar().encode(
                x=alt.X("hour:O", title="Hour of Day"),
                y=alt.Y("count:Q", title="Event Count"),
                color=alt.Color("count:Q",
                    scale=alt.Scale(scheme="blues"),
                    legend=None
                ),
                tooltip=["hour:O", "count:Q"]
            ).properties(height=250)
            st.altair_chart(heatbar, use_container_width=True)

        with col2:
            st.markdown("**Events by Day of Week**")
            df["day_name"] = df["timestamp"].dt.day_name()
            day_order = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"]
            daily = df.groupby("day_name").size().reset_index(name="count")
            daily["day_name"] = pd.Categorical(daily["day_name"], categories=day_order, ordered=True)
            daily = daily.sort_values("day_name")

            daybar = alt.Chart(daily).mark_bar().encode(
                x=alt.X("day_name:N", sort=day_order, title="Day"),
                y=alt.Y("count:Q", title="Event Count"),
                color=alt.Color("count:Q",
                    scale=alt.Scale(scheme="purples"),
                    legend=None
                ),
                tooltip=["day_name:N", "count:Q"]
            ).properties(height=250)
            st.altair_chart(daybar, use_container_width=True)

        st.divider()

        # Night activity breakdown
        st.subheader("🌙 After-Hours Activity")
        st.caption("Events happening between 10 PM and 5 AM — these are worth investigating")

        if "is_night" in df.columns:
            night_df = df[df["is_night"] == 1].copy()

            if not night_df.empty:
                n1, n2, n3 = st.columns(3)
                n1.metric("Total Night Events", len(night_df))
                n2.metric("Unique Users Active at Night",
                          night_df["username"].nunique())
                n3.metric("Most Active Night User",
                          night_df["username"].value_counts().index[0]
                          if len(night_df) > 0 else "N/A")

                night_users = night_df["username"].value_counts().head(10).reset_index()
                night_users.columns = ["Username", "Night Events"]

                nb = alt.Chart(night_users).mark_bar(color="#7c3aed").encode(
                    x=alt.X("Night Events:Q"),
                    y=alt.Y("Username:N", sort="-x", title=""),
                    tooltip=["Username", "Night Events"]
                ).properties(height=250, title="Users Most Active at Night")
                st.altair_chart(nb, use_container_width=True)

                st.markdown("**Night Activity Log**")
                show_cols = [c for c in ["timestamp", "username", "event_type_clean",
                                          "ip_address", "message"] if c in night_df.columns]
                st.dataframe(
                    night_df[show_cols].sort_values("timestamp", ascending=False).head(50),
                    use_container_width=True,
                    height=300
                )
            else:
                st.success("No after-hours activity detected.")

        # Weekend activity
        st.divider()
        st.subheader("📅 Weekend Activity")
        st.caption("Events on Saturday and Sunday — unusual in a typical office environment")

        if "is_weekend" in df.columns:
            weekend_df = df[df["is_weekend"] == 1]
            if not weekend_df.empty:
                wc = weekend_df["username"].value_counts().head(10).reset_index()
                wc.columns = ["Username", "Weekend Events"]
                wb = alt.Chart(wc).mark_bar(color="#0891b2").encode(
                    x=alt.X("Weekend Events:Q"),
                    y=alt.Y("Username:N", sort="-x", title=""),
                    tooltip=["Username", "Weekend Events"]
                ).properties(height=220, title="Users Active on Weekends")
                st.altair_chart(wb, use_container_width=True)
            else:
                st.success("No weekend activity detected.")
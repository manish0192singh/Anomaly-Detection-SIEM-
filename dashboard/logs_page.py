import streamlit as st
import pandas as pd
import altair as alt
import datetime
import os


def logs_page(df=None):
    st.title("📄 System Logs")
    st.caption("View, filter, and analyse all collected Windows Event Log entries.")

    # ── Load data — accept passed dataframe or read from file ─────────
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

    # ── Summary metrics ───────────────────────────────────────────────
    st.subheader("📌 Log Overview")
    total        = len(df)
    unique_users = df["username"].nunique() if "username" in df.columns else 0
    unique_ips   = df["ip_address"].nunique() if "ip_address" in df.columns else 0
    failed       = len(df[df["event_type_clean"] == "Failed Login"]) if "event_type_clean" in df.columns else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Log Entries", f"{total:,}")
    c2.metric("Unique Users",      unique_users)
    c3.metric("Unique IPs",        unique_ips)
    c4.metric("Failed Logins",     failed)

    date_range = f"{str(df['timestamp'].min())[:10]}  →  {str(df['timestamp'].max())[:10]}"
    st.caption(f"📅 Log period: {date_range}")
    st.divider()

    tab1, tab2, tab3 = st.tabs(["🔎 Browse & Filter", "📊 Log Analytics", "⚡ Quick Search"])

    # ── Tab 1 — Browse & Filter ───────────────────────────────────────
    with tab1:
        st.subheader("🔧 Filters")
        col1, col2, col3 = st.columns(3)

        date_filter  = col1.selectbox("📅 Date Range", ["All Time","Today","Yesterday","Last 7 Days","Custom Range"])
        event_types  = ["All"] + sorted(df["event_type_clean"].dropna().unique().tolist()) if "event_type_clean" in df.columns else ["All"]
        event_filter = col2.selectbox("📋 Event Type", event_types)
        sources      = ["All"] + sorted(df["source"].dropna().unique().tolist()) if "source" in df.columns else ["All"]
        source_filter= col3.selectbox("🖥️ Log Source", sources)

        col4, col5 = st.columns(2)
        users       = ["All"] + sorted([u for u in df["username"].dropna().unique() if u not in ("Unknown","-","")]) if "username" in df.columns else ["All"]
        user_filter = col4.selectbox("👤 Username", users)
        hour_filter = col5.selectbox("⏰ Hour of Day", ["All"] + [f"{h:02d}:00" for h in range(24)])

        filtered = df.copy()
        today    = datetime.date.today()

        if date_filter == "Custom Range":
            cr1, cr2   = st.columns(2)
            start_date = cr1.date_input("Start Date", today - datetime.timedelta(days=7))
            end_date   = cr2.date_input("End Date", today)

        if date_filter == "Today":
            filtered = filtered[filtered["timestamp"].dt.date == today]
        elif date_filter == "Yesterday":
            filtered = filtered[filtered["timestamp"].dt.date == today - datetime.timedelta(days=1)]
        elif date_filter == "Last 7 Days":
            filtered = filtered[filtered["timestamp"].dt.date >= today - datetime.timedelta(days=7)]
        elif date_filter == "Custom Range":
            filtered = filtered[(filtered["timestamp"].dt.date >= start_date) & (filtered["timestamp"].dt.date <= end_date)]

        if event_filter != "All" and "event_type_clean" in filtered.columns:
            filtered = filtered[filtered["event_type_clean"] == event_filter]
        if source_filter != "All" and "source" in filtered.columns:
            filtered = filtered[filtered["source"] == source_filter]
        if user_filter != "All" and "username" in filtered.columns:
            filtered = filtered[filtered["username"] == user_filter]
        if hour_filter != "All":
            filtered = filtered[filtered["timestamp"].dt.hour == int(hour_filter.split(":")[0])]

        st.divider()
        rc, ec = st.columns([3,1])
        rc.markdown(f"**Showing {len(filtered):,} of {total:,} log entries**")
        csv = filtered.to_csv(index=False).encode("utf-8")
        ec.download_button("⬇️ Export CSV", csv, "logs_export.csv", "text/csv", use_container_width=True)

        display_cols = [c for c in ["timestamp","event_type_clean","username","ip_address","computer","source","message"] if c in filtered.columns]

        def color_event(val):
            colors = {
                "Failed Login":         "background-color:#fecaca;color:#991b1b",
                "Privilege Escalation": "background-color:#fed7aa;color:#9a3412",
                "Account Locked Out":   "background-color:#fef08a;color:#713f12",
                "Successful Login":     "background-color:#bbf7d0;color:#14532d",
                "Logout":               "background-color:#e0e7ff;color:#3730a3",
            }
            return colors.get(val, "")

        styled = filtered[display_cols].sort_values("timestamp", ascending=False)
        if "event_type_clean" in styled.columns:
            st.dataframe(styled.style.applymap(color_event, subset=["event_type_clean"]), use_container_width=True, height=500)
        else:
            st.dataframe(styled, use_container_width=True, height=500)

    # ── Tab 2 — Analytics ─────────────────────────────────────────────
    with tab2:
        col_l, col_r = st.columns(2)
        with col_l:
            st.subheader("📈 Logs Per Hour")
            df["hour"] = df["timestamp"].dt.hour
            hourly = df.groupby("hour").size().reset_index(name="count")
            hbar = alt.Chart(hourly).mark_bar().encode(
                x=alt.X("hour:O", title="Hour"),
                y=alt.Y("count:Q", title="Log Count"),
                color=alt.condition((alt.datum.hour <= 5) | (alt.datum.hour >= 22), alt.value("#ef4444"), alt.value("#6366f1")),
                tooltip=["hour:O","count:Q"]
            ).properties(height=250)
            st.altair_chart(hbar, use_container_width=True)

        with col_r:
            st.subheader("📋 Event Type Distribution")
            if "event_type_clean" in df.columns:
                et = df["event_type_clean"].value_counts().head(8).reset_index()
                et.columns = ["Event Type","Count"]
                eb = alt.Chart(et).mark_bar().encode(
                    x=alt.X("Count:Q"),
                    y=alt.Y("Event Type:N", sort="-x"),
                    tooltip=["Event Type","Count"]
                ).properties(height=250)
                st.altair_chart(eb, use_container_width=True)

    # ── Tab 3 — Quick Search ──────────────────────────────────────────
    with tab3:
        st.subheader("⚡ Quick Search")
        search_term = st.text_input("🔍 Search", placeholder="e.g. john.smith or 192.168.1.10 or failed...")
        if search_term:
            mask = pd.Series([False] * len(df))
            for col in ["message","username","ip_address","event_type_clean","computer"]:
                if col in df.columns:
                    mask = mask | df[col].astype(str).str.contains(search_term, case=False, na=False)
            results = df[mask].sort_values("timestamp", ascending=False)
            st.markdown(f"Found **{len(results):,}** results for `{search_term}`")
            if not results.empty:
                show_cols = [c for c in ["timestamp","event_type_clean","username","ip_address","computer","message"] if c in results.columns]
                st.dataframe(results[show_cols].head(200), use_container_width=True, height=450)
                csv = results.to_csv(index=False).encode("utf-8")
                st.download_button(f"⬇️ Export results", csv, f"search_{search_term}.csv", "text/csv")
        else:
            st.markdown("""
| What to search | Example |
|---|---|
| Find a specific user | `john.smith` |
| Find an IP address | `192.168.1.10` |
| Find failed logins | `Failed Login` |
| Find suspicious keywords | `mimikatz` or `powershell` |
            """)
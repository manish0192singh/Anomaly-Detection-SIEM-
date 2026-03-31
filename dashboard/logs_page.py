import streamlit as st
import pandas as pd
import altair as alt
import datetime
import os


def logs_page():
    st.title("📄 System Logs")
    st.caption("View, filter, and analyse all collected Windows Event Log entries.")

    # ── Load data ─────────────────────────────────────────────────────
    try:
        df = pd.read_csv("data/structured_logs.csv")
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    except Exception:
        st.error("No logs found. Run the pipeline first.")
        return

    if df.empty:
        st.warning("Log file is empty.")
        return

    # ── Summary metrics ───────────────────────────────────────────────
    st.subheader("📌 Log Overview")

    total        = len(df)
    unique_users = df["username"].nunique() if "username" in df.columns else 0
    unique_ips   = df["ip_address"].nunique() if "ip_address" in df.columns else 0
    failed       = len(df[df["event_type_clean"] == "Failed Login"]) \
                   if "event_type_clean" in df.columns else 0
    date_range   = f"{str(df['timestamp'].min())[:10]}  →  {str(df['timestamp'].max())[:10]}"

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Log Entries",  f"{total:,}")
    c2.metric("Unique Users",       unique_users)
    c3.metric("Unique IPs",         unique_ips)
    c4.metric("Failed Logins",      failed)

    st.caption(f"📅 Log period: {date_range}")
    st.divider()

    # ── Tabs ──────────────────────────────────────────────────────────
    tab1, tab2, tab3 = st.tabs([
        "🔎 Browse & Filter",
        "📊 Log Analytics",
        "⚡ Quick Search"
    ])

    # ==================================================================
    # TAB 1 — Browse & Filter
    # ==================================================================
    with tab1:
        st.subheader("🔧 Filters")

        col1, col2, col3 = st.columns(3)

        # Date filter
        date_filter = col1.selectbox(
            "📅 Date Range",
            ["All Time", "Today", "Yesterday", "Last 7 Days", "Custom Range"]
        )

        # Event type filter
        event_types = ["All"]
        if "event_type_clean" in df.columns:
            event_types += sorted(df["event_type_clean"].dropna().unique().tolist())
        event_filter = col2.selectbox("📋 Event Type", event_types)

        # Source filter
        sources = ["All"]
        if "source" in df.columns:
            sources += sorted(df["source"].dropna().unique().tolist())
        source_filter = col3.selectbox("🖥️ Log Source", sources)

        col4, col5 = st.columns(2)

        # Username filter
        users = ["All"]
        if "username" in df.columns:
            users += sorted([u for u in df["username"].dropna().unique()
                             if u not in ("Unknown", "-", "")])
        user_filter = col4.selectbox("👤 Username", users)

        # Hour filter
        hour_filter = col5.selectbox(
            "⏰ Hour of Day",
            ["All"] + [f"{h:02d}:00 - {h:02d}:59" for h in range(24)]
        )

        # Custom date range
        if date_filter == "Custom Range":
            cr1, cr2 = st.columns(2)
            start_date = cr1.date_input("Start Date", datetime.date.today() - datetime.timedelta(days=7))
            end_date   = cr2.date_input("End Date",   datetime.date.today())

        # ── Apply filters ─────────────────────────────────────────────
        filtered = df.copy()
        today    = datetime.date.today()

        if date_filter == "Today":
            filtered = filtered[filtered["timestamp"].dt.date == today]
        elif date_filter == "Yesterday":
            filtered = filtered[filtered["timestamp"].dt.date == today - datetime.timedelta(days=1)]
        elif date_filter == "Last 7 Days":
            filtered = filtered[filtered["timestamp"].dt.date >= today - datetime.timedelta(days=7)]
        elif date_filter == "Custom Range":
            filtered = filtered[
                (filtered["timestamp"].dt.date >= start_date) &
                (filtered["timestamp"].dt.date <= end_date)
            ]

        if event_filter != "All" and "event_type_clean" in filtered.columns:
            filtered = filtered[filtered["event_type_clean"] == event_filter]

        if source_filter != "All" and "source" in filtered.columns:
            filtered = filtered[filtered["source"] == source_filter]

        if user_filter != "All" and "username" in filtered.columns:
            filtered = filtered[filtered["username"] == user_filter]

        if hour_filter != "All":
            selected_hour = int(hour_filter.split(":")[0])
            filtered = filtered[filtered["timestamp"].dt.hour == selected_hour]

        # ── Results ───────────────────────────────────────────────────
        st.divider()

        result_col, export_col = st.columns([3, 1])
        result_col.markdown(f"**Showing {len(filtered):,} of {total:,} log entries**")

        csv = filtered.to_csv(index=False).encode("utf-8")
        export_col.download_button(
            "⬇️ Export CSV",
            csv,
            "logs_export.csv",
            "text/csv",
            use_container_width=True
        )

        # Colour-code event types in table
        display_cols = [c for c in [
            "timestamp", "event_type_clean", "username",
            "ip_address", "computer", "source", "message"
        ] if c in filtered.columns]

        def color_event(val):
            colors = {
                "Failed Login":          "background-color:#fecaca;color:#991b1b",
                "Privilege Escalation":  "background-color:#fed7aa;color:#9a3412",
                "Account Locked Out":    "background-color:#fef08a;color:#713f12",
                "Successful Login":      "background-color:#bbf7d0;color:#14532d",
                "Logout":                "background-color:#e0e7ff;color:#3730a3",
            }
            return colors.get(val, "")

        styled = filtered[display_cols].sort_values("timestamp", ascending=False)

        if "event_type_clean" in styled.columns:
            st.dataframe(
                styled.style.applymap(color_event, subset=["event_type_clean"]),
                use_container_width=True,
                height=500,
            )
        else:
            st.dataframe(styled, use_container_width=True, height=500)

        st.caption("🔴 Failed Login   🟠 Privilege Escalation   🟡 Account Locked   🟢 Successful Login   🔵 Logout")

    # ==================================================================
    # TAB 2 — Log Analytics
    # ==================================================================
    with tab2:

        col_l, col_r = st.columns(2)

        # Logs per hour
        with col_l:
            st.subheader("📈 Logs Per Hour of Day")
            df["hour"] = df["timestamp"].dt.hour
            hourly = df.groupby("hour").size().reset_index(name="count")

            hbar = alt.Chart(hourly).mark_bar(
                cornerRadiusTopLeft=3,
                cornerRadiusTopRight=3
            ).encode(
                x=alt.X("hour:O", title="Hour of Day"),
                y=alt.Y("count:Q", title="Log Count"),
                color=alt.condition(
                    (alt.datum.hour <= 5) | (alt.datum.hour >= 22),
                    alt.value("#ef4444"),
                    alt.value("#6366f1")
                ),
                tooltip=[
                    alt.Tooltip("hour:O", title="Hour"),
                    alt.Tooltip("count:Q", title="Log Count")
                ]
            ).properties(height=250)
            st.altair_chart(hbar, use_container_width=True)
            st.caption("🔴 Red = night hours (10pm–5am)")

        # Event type distribution
        with col_r:
            st.subheader("📋 Event Type Distribution")
            if "event_type_clean" in df.columns:
                et = df["event_type_clean"].value_counts().reset_index()
                et.columns = ["Event Type", "Count"]
                et_bar = alt.Chart(et).mark_bar(
                    cornerRadiusTopRight=3,
                    cornerRadiusBottomRight=3
                ).encode(
                    x=alt.X("Count:Q"),
                    y=alt.Y("Event Type:N", sort="-x", title=""),
                    color=alt.Color("Count:Q",
                        scale=alt.Scale(scheme="purples"),
                        legend=None
                    ),
                    tooltip=["Event Type", "Count"]
                ).properties(height=250)
                st.altair_chart(et_bar, use_container_width=True)

        st.divider()

        col_l2, col_r2 = st.columns(2)

        # Logs per day trend
        with col_l2:
            st.subheader("📅 Logs Per Day (Last 7 Days)")
            df["date"] = df["timestamp"].dt.date
            last7 = df[df["date"] >= (datetime.date.today() - datetime.timedelta(days=7))]
            daily = last7.groupby("date").size().reset_index(name="count")
            daily["date"] = daily["date"].astype(str)

            line = alt.Chart(daily).mark_line(
                point=True,
                color="#6366f1",
                strokeWidth=2
            ).encode(
                x=alt.X("date:T", title="Date"),
                y=alt.Y("count:Q", title="Log Count"),
                tooltip=["date:T", "count:Q"]
            ).properties(height=220)
            st.altair_chart(line, use_container_width=True)

        # Top computers
        with col_r2:
            st.subheader("🖥️ Top Computers by Event Count")
            if "computer" in df.columns:
                comp = df["computer"].value_counts().head(8).reset_index()
                comp.columns = ["Computer", "Count"]
                cb = alt.Chart(comp).mark_bar(
                    cornerRadiusTopRight=3,
                    cornerRadiusBottomRight=3,
                    color="#8b5cf6"
                ).encode(
                    x=alt.X("Count:Q"),
                    y=alt.Y("Computer:N", sort="-x", title=""),
                    tooltip=["Computer", "Count"]
                ).properties(height=220)
                st.altair_chart(cb, use_container_width=True)

        st.divider()

        # Log source breakdown
        st.subheader("📂 Logs by Source Channel")
        if "source" in df.columns:
            src = df["source"].value_counts().reset_index()
            src.columns = ["Source", "Count"]
            src_pie = alt.Chart(src).mark_arc(innerRadius=40).encode(
                theta=alt.Theta("Count:Q"),
                color=alt.Color("Source:N", scale=alt.Scale(
                    domain=["Security", "System", "Application"],
                    range=["#ef4444", "#6366f1", "#22c55e"]
                )),
                tooltip=["Source", "Count"]
            ).properties(height=220)
            st.altair_chart(src_pie, use_container_width=True)
            st.caption("Security = login/auth events | System = OS events | Application = app events")

    # ==================================================================
    # TAB 3 — Quick Search
    # ==================================================================
    with tab3:
        st.subheader("⚡ Quick Search")
        st.caption("Search across all log messages, usernames, IPs, and event types instantly")

        search_term = st.text_input(
            "🔍 Search",
            placeholder="e.g. 'john.smith' or '192.168.1.10' or 'failed' or 'privilege'..."
        )

        if search_term:
            mask = pd.Series([False] * len(df))

            # Search across multiple columns
            search_cols = ["message", "username", "ip_address",
                           "event_type_clean", "computer"]
            for col in search_cols:
                if col in df.columns:
                    mask = mask | df[col].astype(str).str.contains(
                        search_term, case=False, na=False
                    )

            results = df[mask].sort_values("timestamp", ascending=False)

            st.markdown(f"Found **{len(results):,}** results for `{search_term}`")

            if not results.empty:
                # Show event type breakdown of results
                if "event_type_clean" in results.columns:
                    et_results = results["event_type_clean"].value_counts()
                    cols = st.columns(min(len(et_results), 5))
                    for i, (etype, count) in enumerate(et_results.items()):
                        if i < 5:
                            cols[i].metric(etype, count)

                st.divider()

                show_cols = [c for c in [
                    "timestamp", "event_type_clean", "username",
                    "ip_address", "computer", "message"
                ] if c in results.columns]

                st.dataframe(
                    results[show_cols].head(200),
                    use_container_width=True,
                    height=450
                )

                csv = results.to_csv(index=False).encode("utf-8")
                st.download_button(
                    f"⬇️ Export {len(results)} results",
                    csv,
                    f"search_{search_term}_results.csv",
                    "text/csv"
                )
            else:
                st.info(f"No results found for '{search_term}'")

        else:
            # Show search tips when nothing is typed
            st.info("💡 **Search Tips:**")
            st.markdown("""
            | What to search | Example |
            |---|---|
            | Find a specific user | `john.smith` |
            | Find an IP address | `192.168.1.10` |
            | Find failed logins | `Failed Login` |
            | Find privilege events | `privilege` |
            | Find a specific computer | `SERVER-01` |
            | Find suspicious keywords | `mimikatz` or `powershell` |
            """)
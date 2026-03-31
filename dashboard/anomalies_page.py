import streamlit as st
import pandas as pd
import altair as alt


def anomalies_page():
    st.title("🔍 ML Anomaly Detection")

    try:
        df = pd.read_csv("data/anomalies.csv")
    except Exception:
        st.warning("No anomaly data found. Run the pipeline first.")
        return

    if df.empty:
        st.info("No data available.")
        return

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    anomalies = df[df["anomaly"] == -1].copy()
    normal    = df[df["anomaly"] != -1].copy()

    # ── Top metrics ──────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Records",   len(df))
    c2.metric("Anomalies",       len(anomalies), delta=f"{len(anomalies)/len(df)*100:.1f}%")
    c3.metric("Normal",          len(normal))
    avg_risk = round(anomalies["risk_score"].mean(), 1) if "risk_score" in anomalies.columns else "N/A"
    c4.metric("Avg Risk Score",  avg_risk)

    st.divider()

    # ── Filters ──────────────────────────────────────────────────────
    with st.expander("🔧 Filters", expanded=True):
        col1, col2, col3 = st.columns(3)

        severity_opts = ["All"]
        if "severity" in anomalies.columns:
            severity_opts += sorted(anomalies["severity"].dropna().unique().tolist())
        selected_sev = col1.selectbox("Severity", severity_opts)

        user_opts = ["All"] + sorted(anomalies["username"].dropna().unique().tolist()) \
                    if "username" in anomalies.columns else ["All"]
        selected_user = col2.selectbox("Username", user_opts)

        min_risk = col3.slider("Min Risk Score", 0, 100, 0) \
                   if "risk_score" in anomalies.columns else 0

    filtered = anomalies.copy()
    if selected_sev != "All" and "severity" in filtered.columns:
        filtered = filtered[filtered["severity"] == selected_sev]
    if selected_user != "All" and "username" in filtered.columns:
        filtered = filtered[filtered["username"] == selected_user]
    if "risk_score" in filtered.columns:
        filtered = filtered[filtered["risk_score"] >= min_risk]

    st.write(f"Showing **{len(filtered)}** anomalies after filtering")

    # ── Severity breakdown chart ──────────────────────────────────────
    if "severity" in anomalies.columns:
        st.subheader("📊 Severity Breakdown")
        sev_counts = anomalies["severity"].value_counts().reset_index()
        sev_counts.columns = ["Severity", "Count"]

        color_map = {
            "Critical": "#ef4444",
            "High":     "#f97316",
            "Medium":   "#eab308",
            "Low":      "#22c55e",
        }

        bar = alt.Chart(sev_counts).mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4).encode(
            x=alt.X("Severity:N", sort=["Critical", "High", "Medium", "Low"]),
            y=alt.Y("Count:Q"),
            color=alt.Color(
                "Severity:N",
                scale=alt.Scale(
                    domain=list(color_map.keys()),
                    range=list(color_map.values())
                ),
                legend=None
            ),
            tooltip=["Severity", "Count"]
        ).properties(height=250)

        st.altair_chart(bar, use_container_width=True)

    # ── Risk score distribution ───────────────────────────────────────
    if "risk_score" in anomalies.columns:
        st.subheader("📈 Risk Score Distribution")
        hist = alt.Chart(anomalies).mark_bar(color="#6366f1", opacity=0.8).encode(
            x=alt.X("risk_score:Q", bin=alt.Bin(maxbins=20), title="Risk Score"),
            y=alt.Y("count():Q", title="Count"),
            tooltip=["count()"]
        ).properties(height=200)
        st.altair_chart(hist, use_container_width=True)

    # ── Anomalies over time ───────────────────────────────────────────
    st.subheader("⏱️ Anomalies Over Time")
    time_df = anomalies.dropna(subset=["timestamp"]).copy()
    if not time_df.empty:
        time_df["hour"] = time_df["timestamp"].dt.floor("H")
        time_counts = time_df.groupby("hour").size().reset_index(name="count")
        line = alt.Chart(time_counts).mark_line(point=True, color="#6366f1").encode(
            x=alt.X("hour:T", title="Time"),
            y=alt.Y("count:Q", title="Anomalies"),
            tooltip=["hour:T", "count:Q"]
        ).properties(height=200)
        st.altair_chart(line, use_container_width=True)

    # ── Top anomalous users ───────────────────────────────────────────
    if "username" in anomalies.columns:
        st.subheader("👤 Top Anomalous Users")
        user_counts = anomalies["username"].value_counts().head(10).reset_index()
        user_counts.columns = ["Username", "Anomaly Count"]
        ub = alt.Chart(user_counts).mark_bar(color="#f97316").encode(
            x=alt.X("Anomaly Count:Q"),
            y=alt.Y("Username:N", sort="-x"),
            tooltip=["Username", "Anomaly Count"]
        ).properties(height=250)
        st.altair_chart(ub, use_container_width=True)

    # ── Anomaly table ─────────────────────────────────────────────────
    st.subheader("📋 Anomaly Records")

    display_cols = [c for c in
        ["timestamp", "username", "ip_address", "event_type_clean",
         "severity", "risk_score", "message", "mitre_tactic", "flags"]
        if c in filtered.columns]

    st.dataframe(
        filtered[display_cols].sort_values("risk_score", ascending=False)
        if "risk_score" in filtered.columns
        else filtered[display_cols],
        use_container_width=True,
        height=400,
    )

    # ── Export ────────────────────────────────────────────────────────
    csv = filtered.to_csv(index=False).encode("utf-8")
    st.download_button("⬇️ Export Anomalies CSV", csv, "anomalies_export.csv", "text/csv")
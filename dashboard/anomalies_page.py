import streamlit as st
import pandas as pd
import altair as alt


def anomalies_page(df=None):
    st.title("🔍 ML Anomaly Detection")

    if df is None or df.empty:
        try:
            df = pd.read_csv("data/anomalies.csv")
        except Exception:
            st.warning("No anomaly data found. Run your pipeline file first.")
            st.info("Download your personal agent from the home page and run it on your Windows PC.")
            return

    if df.empty:
        st.info("No data available.")
        return

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    anomalies = df[df["anomaly"] == -1].copy()
    normal    = df[df["anomaly"] != -1].copy()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Records", len(df))
    c2.metric("Anomalies",     len(anomalies), delta=f"{len(anomalies)/len(df)*100:.1f}%" if len(df) > 0 else "0%")
    c3.metric("Normal",        len(normal))
    avg_risk = round(anomalies["risk_score"].mean(), 1) if "risk_score" in anomalies.columns and len(anomalies) > 0 else "N/A"
    c4.metric("Avg Risk Score", avg_risk)

    st.divider()

    with st.expander("🔧 Filters", expanded=True):
        col1, col2, col3 = st.columns(3)
        severity_opts  = ["All"] + sorted(anomalies["severity"].dropna().unique().tolist()) if "severity" in anomalies.columns else ["All"]
        selected_sev   = col1.selectbox("Severity", severity_opts)
        user_opts      = ["All"] + sorted(anomalies["username"].dropna().unique().tolist()) if "username" in anomalies.columns else ["All"]
        selected_user  = col2.selectbox("Username", user_opts)
        min_risk       = col3.slider("Min Risk Score", 0, 100, 0) if "risk_score" in anomalies.columns else 0

    filtered = anomalies.copy()
    if selected_sev != "All" and "severity" in filtered.columns:
        filtered = filtered[filtered["severity"] == selected_sev]
    if selected_user != "All" and "username" in filtered.columns:
        filtered = filtered[filtered["username"] == selected_user]
    if "risk_score" in filtered.columns:
        filtered = filtered[filtered["risk_score"] >= min_risk]

    st.write(f"Showing **{len(filtered)}** anomalies after filtering")

    if "severity" in anomalies.columns:
        st.subheader("📊 Severity Breakdown")
        sev_counts = anomalies["severity"].value_counts().reset_index()
        sev_counts.columns = ["Severity","Count"]
        bar = alt.Chart(sev_counts).mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4).encode(
            x=alt.X("Severity:N", sort=["Critical","High","Medium","Low"]),
            y=alt.Y("Count:Q"),
            color=alt.Color("Severity:N", scale=alt.Scale(
                domain=["Critical","High","Medium","Low"],
                range=["#ef4444","#f97316","#eab308","#22c55e"])),
            tooltip=["Severity","Count"]
        ).properties(height=250)
        st.altair_chart(bar, use_container_width=True)

    if "risk_score" in anomalies.columns:
        st.subheader("📈 Risk Score Distribution")
        hist = alt.Chart(anomalies).mark_bar(color="#6366f1", opacity=0.8).encode(
            x=alt.X("risk_score:Q", bin=alt.Bin(maxbins=20), title="Risk Score"),
            y=alt.Y("count():Q", title="Count"),
            tooltip=["count()"]
        ).properties(height=200)
        st.altair_chart(hist, use_container_width=True)

    st.subheader("📋 Anomaly Records")
    display_cols = [c for c in ["timestamp","username","ip_address","event_type_clean","severity","risk_score","message"] if c in filtered.columns]
    st.dataframe(
        filtered[display_cols].sort_values("risk_score", ascending=False) if "risk_score" in filtered.columns else filtered[display_cols],
        use_container_width=True, height=400
    )
    csv = filtered.to_csv(index=False).encode("utf-8")
    st.download_button("⬇️ Export Anomalies CSV", csv, "anomalies_export.csv", "text/csv")
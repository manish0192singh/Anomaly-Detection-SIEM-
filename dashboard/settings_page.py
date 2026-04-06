import streamlit as st
import os
import json

CONFIG_FILE = "data/siem_config.json"


def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE) as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "contamination":       0.01,
        "failed_login_thresh": 8,
        "multi_ip_thresh":     3,
        "high_volume_thresh":  150,
    }


def save_config(cfg):
    os.makedirs("data", exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=4)


def write_env(key, value):
    env_file = ".env"
    lines = []
    found = False
    if os.path.exists(env_file):
        with open(env_file) as f:
            lines = f.readlines()
        for i, line in enumerate(lines):
            if line.startswith(f"{key}="):
                lines[i] = f"{key}={value}\n"
                found = True
                break
    if not found:
        lines.append(f"{key}={value}\n")
    with open(env_file, "w") as f:
        f.writelines(lines)


def settings_page():
    st.title("⚙️ Settings")

    cfg = load_config()

    # ── Detection thresholds ──────────────────────────────────────────
    st.subheader("🎯 Detection Thresholds")
    with st.form("thresholds_form"):
        col1, col2 = st.columns(2)
        contamination = col1.slider(
            "ML Contamination Rate", 0.01, 0.20,
            float(cfg.get("contamination", 0.01)), step=0.01
        )
        failed_thresh = col2.number_input(
            "Failed Login Burst Threshold", 1, 100,
            int(cfg.get("failed_login_thresh", 8))
        )
        multi_ip = col1.number_input(
            "Multiple IP Alert Threshold", 2, 20,
            int(cfg.get("multi_ip_thresh", 3))
        )
        high_vol = col2.number_input(
            "High Volume IP Threshold", 10, 1000,
            int(cfg.get("high_volume_thresh", 150))
        )
        if st.form_submit_button("💾 Save Thresholds"):
            save_config({
                "contamination":       contamination,
                "failed_login_thresh": failed_thresh,
                "multi_ip_thresh":     multi_ip,
                "high_volume_thresh":  high_vol,
            })
            st.success("Thresholds saved!")

    st.divider()

    # ── Email notifications ───────────────────────────────────────────
    st.subheader("📧 Email Notifications")
    with st.form("email_form"):
        col1, col2 = st.columns(2)
        smtp_host  = col1.text_input("SMTP Host", "smtp.gmail.com")
        smtp_port  = col2.number_input("SMTP Port", 1, 65535, 587)
        smtp_user  = col1.text_input("SMTP Username", "")
        smtp_pass  = col2.text_input("SMTP Password", "", type="password")
        alert_mail = st.text_input("Alert Recipient Email", "")
        if st.form_submit_button("💾 Save Email Settings"):
            write_env("SMTP_HOST",   smtp_host)
            write_env("SMTP_PORT",   str(smtp_port))
            write_env("SMTP_USER",   smtp_user)
            write_env("SMTP_PASS",   smtp_pass)
            write_env("ALERT_EMAIL", alert_mail)
            st.success("Email settings saved!")

    st.divider()

    # ── Webhook ───────────────────────────────────────────────────────
    st.subheader("🔔 Webhook Notifications")
    with st.form("webhook_form"):
        webhook = st.text_input(
            "Webhook URL", "",
            help="Slack / Teams / Discord incoming webhook URL"
        )
        if st.form_submit_button("💾 Save Webhook"):
            write_env("WEBHOOK_URL", webhook)
            st.success("Webhook saved!")

    st.divider()

    # ── About ─────────────────────────────────────────────────────────
    st.subheader("ℹ️ About")
    st.markdown("""
| Component | Details |
|---|---|
| **ML Model** | Isolation Forest + Local Outlier Factor |
| **Features** | 12 engineered features per log entry |
| **Rules** | 11 SIEM detection rules |
| **MITRE Coverage** | 10+ ATT&CK tactics tagged |
| **Database** | SQLite per-user storage on cloud |
    """)
    st.info(
        "💡 To collect your Windows logs, "
        "download your personal agent from the home page."
    )
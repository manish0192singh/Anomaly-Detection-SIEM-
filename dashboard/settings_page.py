import streamlit as st
import os
import json
import subprocess
import sys
from dotenv import dotenv_values, set_key


ENV_FILE = ".env"
CONFIG_FILE = "data/siem_config.json"


def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {
        "contamination":       0.05,
        "failed_login_thresh": 5,
        "multi_ip_thresh":     3,
        "high_volume_thresh":  50,
        "odd_hour_start":      0,
        "odd_hour_end":        5,
    }


def save_config(cfg):
    os.makedirs("data", exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=4)


def settings_page():
    st.title("⚙️ Settings")

    cfg = load_config()
    env = dotenv_values(ENV_FILE) if os.path.exists(ENV_FILE) else {}

    # ── Detection thresholds ──────────────────────────────────────────
    st.subheader("🎯 Detection Thresholds")
    with st.form("thresholds_form"):
        col1, col2 = st.columns(2)

        contamination = col1.slider(
            "ML Contamination Rate (expected anomaly %)",
            0.01, 0.20,
            float(cfg.get("contamination", 0.05)),
            step=0.01,
            help="Lower = fewer but more confident anomaly detections"
        )
        failed_thresh = col2.number_input(
            "Failed Login Burst Threshold",
            1, 100,
            int(cfg.get("failed_login_thresh", 5))
        )
        multi_ip = col1.number_input(
            "Multiple IP Alert Threshold",
            2, 20,
            int(cfg.get("multi_ip_thresh", 3))
        )
        high_vol = col2.number_input(
            "High Volume IP Threshold (events)",
            10, 1000,
            int(cfg.get("high_volume_thresh", 50))
        )
        odd_start = col1.number_input("Odd-Hour Start (24h)", 0, 23, int(cfg.get("odd_hour_start", 0)))
        odd_end   = col2.number_input("Odd-Hour End (24h)",   0, 23, int(cfg.get("odd_hour_end", 5)))

        if st.form_submit_button("💾 Save Thresholds"):
            new_cfg = {
                "contamination":       contamination,
                "failed_login_thresh": failed_thresh,
                "multi_ip_thresh":     multi_ip,
                "high_volume_thresh":  high_vol,
                "odd_hour_start":      odd_start,
                "odd_hour_end":        odd_end,
            }
            save_config(new_cfg)
            st.success("Thresholds saved! Re-run pipeline to apply.")

    st.divider()

    # ── Email notification ────────────────────────────────────────────
    st.subheader("📧 Email Notifications")
    with st.form("email_form"):
        col1, col2 = st.columns(2)
        smtp_host  = col1.text_input("SMTP Host",  env.get("SMTP_HOST", "smtp.gmail.com"))
        smtp_port  = col2.number_input("SMTP Port", 1, 65535, int(env.get("SMTP_PORT", 587)))
        smtp_user  = col1.text_input("SMTP Username", env.get("SMTP_USER", ""))
        smtp_pass  = col2.text_input("SMTP Password", env.get("SMTP_PASS", ""), type="password")
        alert_mail = st.text_input("Alert Recipient Email", env.get("ALERT_EMAIL", ""))

        if st.form_submit_button("💾 Save Email Settings"):
            _write_env("SMTP_HOST",   smtp_host)
            _write_env("SMTP_PORT",   str(smtp_port))
            _write_env("SMTP_USER",   smtp_user)
            _write_env("SMTP_PASS",   smtp_pass)
            _write_env("ALERT_EMAIL", alert_mail)
            st.success("Email settings saved to .env")

    st.divider()

    # ── Webhook notification ──────────────────────────────────────────
    st.subheader("🔔 Webhook Notifications (Slack / Teams / Discord)")
    with st.form("webhook_form"):
        webhook = st.text_input(
            "Webhook URL",
            env.get("WEBHOOK_URL", ""),
            help="Paste your Slack / Teams / Discord incoming webhook URL"
        )
        if st.form_submit_button("💾 Save Webhook"):
            _write_env("WEBHOOK_URL", webhook)
            st.success("Webhook URL saved to .env")

    st.divider()

    # ── Pipeline controls ─────────────────────────────────────────────
    st.subheader("🚀 Pipeline Controls")

    col1, col2 = st.columns(2)

    with col1:
        st.write("**Run full pipeline** (collect → preprocess → detect → alert)")
        if st.button("▶️ Run Full Pipeline"):
            with st.spinner("Running pipeline..."):
                scripts = [
                    "log_collector.py",
                    "preprocessing.py",
                    "rule_engine.py",
                    "anomaly_model.py",
                    "alerts_generator.py",
                ]
                results = []
                for script in scripts:
                    r = subprocess.run(
                        [sys.executable, script],
                        cwd="backend",
                        capture_output=True,
                        text=True,
                    )
                    status = "✅" if r.returncode == 0 else "❌"
                    results.append(f"{status} {script}")
                    if r.returncode != 0:
                        st.error(f"{script}: {r.stderr[:200]}")
                st.success("\n".join(results))

    with col2:
        st.write("**Retrain ML model** (deletes saved model, forces retrain)")
        if st.button("🔄 Retrain Model"):
            import glob
            model_files = glob.glob("data/models/*.pkl")
            for f in model_files:
                os.remove(f)
            st.info(f"Deleted {len(model_files)} model file(s). Run pipeline to retrain.")

    st.divider()

    # ── API info ──────────────────────────────────────────────────────
    st.subheader("🔌 REST API")
    st.info(
        "The FastAPI backend runs separately. Start it with:\n\n"
        "```bash\ncd backend && uvicorn api:app --reload --port 8000\n```\n\n"
        "Then visit: http://localhost:8000/docs"
    )

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
| **Notifications** | Email (SMTP) + Webhook (Slack/Teams/Discord) |
| **API** | FastAPI REST API with 15+ endpoints |
    """)


def _write_env(key, value):
    """Write a key=value to the .env file."""
    lines = []
    found = False
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as f:
            lines = f.readlines()
        for i, line in enumerate(lines):
            if line.startswith(f"{key}="):
                lines[i] = f"{key}={value}\n"
                found = True
                break
    if not found:
        lines.append(f"{key}={value}\n")
    with open(ENV_FILE, "w") as f:
        f.writelines(lines)
import streamlit as st
import json
import os

SETTINGS_FILE = "data/settings.json"

DEFAULT_SETTINGS = {
    "retention_days": 7,
    "log_limit": 2000,
}

def load_settings():
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r") as f:
                return json.load(f)
        except:
            return DEFAULT_SETTINGS
    else:
        return DEFAULT_SETTINGS

def save_settings(settings):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=4)

def settings_page():
    st.title("⚙️ System Settings")
    st.write("Configure core SIEM system preferences.")

    settings = load_settings()

    st.subheader("🗂 Log Settings")

    settings["retention_days"] = st.slider(
        "Log Retention (Days)",
        1, 30, settings.get("retention_days", 7)
    )

    """settings["log_limit"] = st.number_input(
        "Maximum Logs to Collect",
        min_value=500,
        max_value=20000,
        value=settings.get("log_limit", 2000),
        step=500
    )"""

    st.info("""
    These settings control how many logs your system collects and how long old logs are kept.
    Notification settings have been removed to simplify the application.
    """)

    if st.button("💾 Save Settings"):
        save_settings(settings)
        st.success("Settings saved successfully!")
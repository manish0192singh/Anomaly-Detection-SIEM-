import json
import os

DATA_FOLDER = "../data"
SETTINGS_FILE = os.path.join(DATA_FOLDER, "settings.json")

def get_settings():
    """Load settings.json; return {} if missing."""
    if not os.path.exists(SETTINGS_FILE):
        return {}
    try:
        with open(SETTINGS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def save_settings(settings_dict):
    """Save settings.json to data folder."""
    os.makedirs(DATA_FOLDER, exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings_dict, f, indent=4)
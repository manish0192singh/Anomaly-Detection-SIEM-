import pandas as pd

def load_logs():
    return pd.DataFrame({
        "timestamp": ["2025-02-01", "2025-02-02"],
        "user": ["admin", "user1"],
        "event": ["login_success", "login_failed"],
        "ip": ["192.168.1.1", "192.168.1.5"]
    })

def load_anomalies():
    return pd.DataFrame({
        "timestamp": ["2025-02-02"],
        "user": ["user1"],
        "event": ["login_time_unusual"],
        "anomaly_score": [0.89]
    })

def load_alerts():
    return pd.DataFrame({
        "timestamp": ["2025-02-02"],
        "alert": ["Multiple failed logins"],
        "severity": ["High"]
    })

def load_user_behaviour():
    return pd.DataFrame({
        "timestamp": ["2025-02-01", "2025-02-02"],
        "login_count": [3, 10]
    })
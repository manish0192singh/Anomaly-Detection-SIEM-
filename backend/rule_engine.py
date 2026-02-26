import pandas as pd
import json
from datetime import datetime

class RuleEngine:

    def __init__(self, input_path="../data/structured_logs.csv", output_path="../data/rule_alerts.json"):
        self.input_path = input_path
        self.output_path = output_path

    def load_logs(self):
        df = pd.read_csv(self.input_path)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="ignore")
        return df

    # ----------------------------------------------------
    # RULE 1: Multiple failed login attempts (brute-force)
    # ----------------------------------------------------
    def detect_failed_login_bursts(self, df):
        alerts = []
        failed = df[df["event_type_clean"] == "Failed Login"]

        grouped = failed.groupby("username").size()

        for username, count in grouped.items():
            if count >= 5:  # threshold
                alerts.append({
                    "type": "Failed Login Burst",
                    "severity": "High",
                    "username": username,
                    "count": int(count),
                    "description": f"{count} failed login attempts detected for user '{username}'."
                })
        return alerts

    # ----------------------------------------------------
    # RULE 2: Privilege escalation detection
    # ----------------------------------------------------
    def detect_privilege_escalation(self, df):
        alerts = []
        priv = df[df["event_type_clean"] == "Privilege Escalation"]

        for _, row in priv.iterrows():
            alerts.append({
                "type": "Privilege Escalation",
                "severity": "High",
                "username": row["username"],
                "timestamp": str(row["timestamp"]),
                "description": f"Privilege escalation detected for user '{row['username']}'."
            })
        return alerts

    # ----------------------------------------------------
    # RULE 3: Logins at unusual hours (12 AM – 5 AM)
    # ----------------------------------------------------
    def detect_odd_hour_logins(self, df):
        alerts = []
        login_events = df[df["event_type_clean"] == "Successful Login"]

        for _, row in login_events.iterrows():
            try:
                hour = pd.to_datetime(row["timestamp"]).hour
            except:
                continue

            if 0 <= hour <= 5:
                alerts.append({
                    "type": "Odd Hour Login",
                    "severity": "Medium",
                    "username": row["username"],
                    "timestamp": str(row["timestamp"]),
                    "description": f"Login during unusual hours (12 AM – 5 AM) by '{row['username']}'."
                })
        return alerts

    # ----------------------------------------------------
    # RUN ALL RULES
    # ----------------------------------------------------
    def run_rules(self):
        df = self.load_logs()

        all_alerts = []
        all_alerts.extend(self.detect_failed_login_bursts(df))
        all_alerts.extend(self.detect_privilege_escalation(df))
        all_alerts.extend(self.detect_odd_hour_logins(df))

        with open(self.output_path, "w") as file:
            json.dump(all_alerts, file, indent=4)

        print(f"[OK] Rule-based alerts saved to {self.output_path}")

        return all_alerts


if __name__ == "__main__":
    engine = RuleEngine()
    engine.run_rules()
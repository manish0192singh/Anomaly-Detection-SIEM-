import json
import pandas as pd
from datetime import datetime


class AlertGenerator:

    def __init__(self):

        # Input files
        self.rule_alert_file = "../data/rule_alerts.json"
        self.anomaly_file = "../data/anomalies.csv"

        # Output file
        self.output_file = "../data/final_alerts.json"


    def load_rule_alerts(self):

        try:
            with open(self.rule_alert_file, "r") as f:
                return json.load(f)

        except Exception as e:
            print(f"[WARNING] Could not read rule alerts: {e}")
            return []


    def load_anomalies(self):

        try:
            df = pd.read_csv(self.anomaly_file)
            return df

        except Exception as e:
            print(f"[WARNING] Could not read anomaly file: {e}")
            return pd.DataFrame()


    def create_alert(self, alert_type, message, severity):

        return {
            "timestamp": str(datetime.now()),
            "type": alert_type,
            "message": message,
            "severity": severity
        }


    def generate(self):

        alerts = []

        # ---------- RULE ALERTS ----------
        rule_alerts = self.load_rule_alerts()

        for alert in rule_alerts:

            alert_type = alert.get("type", "Rule Alert")

            message = alert.get(
                "message",
                f"Security rule triggered: {alert_type}"
            )

            alerts.append(
                self.create_alert(
                    alert_type,
                    message,
                    "High"
                )
            )


        # ---------- ML ANOMALIES ----------
        anomalies = self.load_anomalies()

        if not anomalies.empty:

            anomaly_rows = anomalies[anomalies["anomaly"] == -1]

            for _, row in anomaly_rows.iterrows():

                message = str(row.get("message", "Suspicious log detected"))

                alerts.append(
                    self.create_alert(
                        "ML Anomaly Detected",
                        message,
                        "Medium"
                    )
                )


        # ---------- SAVE ALERTS ----------
        try:

            with open(self.output_file, "w") as f:
                json.dump(alerts, f, indent=4)

            print(f"[OK] Alerts generated -> {self.output_file}")

        except Exception as e:

            print(f"[ERROR] Could not save alerts: {e}")


if __name__ == "__main__":

    generator = AlertGenerator()
    generator.generate()
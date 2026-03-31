import json
import os
import smtplib
import hashlib
import requests
import pandas as pd
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv

load_dotenv()


class AlertGenerator:

    SEVERITY_SCORE = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Normal": 0}

    def __init__(self):
        self.rule_alert_file = "../data/rule_alerts.json"
        self.anomaly_file    = "../data/anomalies.csv"
        self.output_file     = "../data/final_alerts.json"
        self.seen_hashes     = set()

        # Notification config from .env
        self.smtp_host     = os.getenv("SMTP_HOST", "")
        self.smtp_port     = int(os.getenv("SMTP_PORT", 587))
        self.smtp_user     = os.getenv("SMTP_USER", "")
        self.smtp_pass     = os.getenv("SMTP_PASS", "")
        self.alert_email   = os.getenv("ALERT_EMAIL", "")
        self.webhook_url   = os.getenv("WEBHOOK_URL", "")   # Slack / Teams / Discord

    # ------------------------------------------------------------------
    # Loaders
    # ------------------------------------------------------------------

    def load_rule_alerts(self):
        try:
            with open(self.rule_alert_file, "r") as f:
                return json.load(f)
        except Exception as e:
            print(f"[WARNING] Could not read rule alerts: {e}")
            return []

    def load_anomalies(self):
        try:
            return pd.read_csv(self.anomaly_file)
        except Exception as e:
            print(f"[WARNING] Could not read anomaly file: {e}")
            return pd.DataFrame()

    # ------------------------------------------------------------------
    # Alert builder
    # ------------------------------------------------------------------

    def create_alert(self, alert_type, message, severity,
                     username="N/A", ip=None, risk_score=None,
                     source="rule", timestamp=None):
        return {
            "id":          self._hash(alert_type, message, username),
            "timestamp":   str(timestamp or datetime.now()),
            "type":        alert_type,
            "message":     message,
            "severity":    severity,
            "severity_score": self.SEVERITY_SCORE.get(severity, 0),
            "username":    username,
            "ip_address":  ip or "N/A",
            "risk_score":  round(risk_score, 2) if risk_score is not None else None,
            "source":      source,      # "rule" | "ml"
        }

    def _hash(self, *parts):
        """Deduplicate alerts with the same type+message+username."""
        raw = "|".join(str(p) for p in parts)
        return hashlib.md5(raw.encode()).hexdigest()[:12]

    def is_duplicate(self, alert):
        h = alert["id"]
        if h in self.seen_hashes:
            return True
        self.seen_hashes.add(h)
        return False

    # ------------------------------------------------------------------
    # Enrichment: add MITRE ATT&CK tactic tag
    # ------------------------------------------------------------------

    MITRE_MAP = {
        "Failed Login Burst":        "T1110 – Brute Force",
        "Brute Force Success":       "T1110 – Brute Force",
        "Privilege Escalation":      "T1068 – Exploitation for Privilege Escalation",
        "Odd Hour Login":            "T1078 – Valid Accounts",
        "Multiple IP Addresses":     "T1090 – Proxy",
        "Account Enumeration":       "T1087 – Account Discovery",
        "Rapid Successive Logins":   "T1078 – Valid Accounts",
        "After Hours File Access":   "T1083 – File & Directory Discovery",
        "High Volume From IP":       "T1046 – Network Service Discovery",
        "Suspicious Keyword Detected": "T1059 – Command & Scripting Interpreter",
        "Session Anomaly":           "T1563 – Remote Service Session Hijacking",
        "ML Anomaly Detected":       "T1499 – Endpoint Denial of Service",
    }

    def enrich(self, alert):
        alert["mitre_tactic"] = self.MITRE_MAP.get(alert["type"], "Unknown")
        return alert

    # ------------------------------------------------------------------
    # Notifications
    # ------------------------------------------------------------------

    def send_email(self, alerts):
        if not all([self.smtp_host, self.smtp_user, self.smtp_pass, self.alert_email]):
            print("[INFO] Email not configured — skipping.")
            return

        critical = [a for a in alerts if a["severity"] in ("Critical", "High")]
        if not critical:
            return

        body_lines = [f"SIEM Alert Summary — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"]
        for a in critical[:20]:
            body_lines.append(
                f"[{a['severity']}] {a['type']} | User: {a['username']} | {a['message']}"
            )

        msg = MIMEMultipart()
        msg["Subject"] = f"🚨 SIEM: {len(critical)} Critical/High Alerts Detected"
        msg["From"]    = self.smtp_user
        msg["To"]      = self.alert_email
        msg.attach(MIMEText("\n".join(body_lines), "plain"))

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_user, self.smtp_pass)
                server.send_message(msg)
            print(f"[OK] Email sent to {self.alert_email}")
        except Exception as e:
            print(f"[ERROR] Email failed: {e}")

    def send_webhook(self, alerts):
        if not self.webhook_url:
            print("[INFO] Webhook not configured — skipping.")
            return

        critical = [a for a in alerts if a["severity"] in ("Critical", "High")]
        if not critical:
            return

        lines = [f"*🚨 SIEM Alert — {datetime.now().strftime('%Y-%m-%d %H:%M')}*"]
        for a in critical[:10]:
            lines.append(
                f"• `[{a['severity']}]` *{a['type']}* — {a['username']} — {a['message'][:80]}"
            )

        payload = {"text": "\n".join(lines)}

        try:
            r = requests.post(self.webhook_url, json=payload, timeout=10)
            if r.status_code == 200:
                print("[OK] Webhook notification sent.")
            else:
                print(f"[WARN] Webhook returned {r.status_code}")
        except Exception as e:
            print(f"[ERROR] Webhook failed: {e}")

    # ------------------------------------------------------------------
    # Main generate()
    # ------------------------------------------------------------------

    def generate(self):
        alerts = []

        # ── Rule alerts ──
        rule_alerts = self.load_rule_alerts()
        for ra in rule_alerts:
            a = self.create_alert(
                alert_type  = ra.get("type", "Rule Alert"),
                message     = ra.get("description", ra.get("message", "Security rule triggered")),
                severity    = ra.get("severity", "Medium"),
                username    = ra.get("username", "N/A"),
                ip          = ra.get("ip_address"),
                source      = "rule",
                timestamp   = ra.get("timestamp"),
            )
            a = self.enrich(a)
            if not self.is_duplicate(a):
                alerts.append(a)

        # ── ML anomaly alerts ──
        anomalies = self.load_anomalies()
        if not anomalies.empty:
            anomaly_rows = anomalies[anomalies["anomaly"] == -1]
            for _, row in anomaly_rows.iterrows():
                severity   = row.get("severity", "Medium")
                risk_score = row.get("risk_score", None)
                a = self.create_alert(
                    alert_type  = "ML Anomaly Detected",
                    message     = str(row.get("message", "Suspicious log entry"))[:200],
                    severity    = severity if severity != "Normal" else "Medium",
                    username    = str(row.get("username", "Unknown")),
                    ip          = row.get("ip_address"),
                    risk_score  = float(risk_score) if risk_score is not None else None,
                    source      = "ml",
                    timestamp   = row.get("timestamp"),
                )
                a = self.enrich(a)
                if not self.is_duplicate(a):
                    alerts.append(a)

        # ── Sort by severity score desc ──
        alerts.sort(key=lambda x: x["severity_score"], reverse=True)

        # ── Save ──
        try:
            with open(self.output_file, "w") as f:
                json.dump(alerts, f, indent=4, default=str)
            print(f"[OK] {len(alerts)} alerts saved -> {self.output_file}")
        except Exception as e:
            print(f"[ERROR] Could not save alerts: {e}")

        # ── Notify ──
        self.send_email(alerts)
        self.send_webhook(alerts)

        # ── Summary ──
        from collections import Counter
        sev_counts = Counter(a["severity"] for a in alerts)
        print(f"     Critical={sev_counts.get('Critical',0)} "
              f"High={sev_counts.get('High',0)} "
              f"Medium={sev_counts.get('Medium',0)} "
              f"Low={sev_counts.get('Low',0)}")

        return alerts


if __name__ == "__main__":
    generator = AlertGenerator()
    generator.generate()
"""
Step 5 — Alert Generator
=========================
Combines rule-based alerts and ML anomalies into one final alert feed.

What it does:
  1. Loads rule alerts from rule_alerts.json
  2. Loads ML anomalies from anomalies.csv
  3. Deduplicates alerts using MD5 hashing
  4. Tags each alert with a MITRE ATT&CK tactic code
  5. Sorts alerts by severity (Critical first)
  6. Saves to final_alerts.json
  7. Sends email and webhook notifications (if configured in .env)

Input:  ../data/rule_alerts.json + ../data/anomalies.csv
Output: ../data/final_alerts.json
"""

import json
import os
import smtplib
import hashlib
import requests
import pandas as pd
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import Counter

# Load email/webhook settings from .env file if it exists
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


class AlertGenerator:

    # Severity score used for sorting (Critical = highest priority)
    SEVERITY_SCORE = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Normal": 0}

    # MITRE ATT&CK framework tactic codes for each alert type
    # MITRE ATT&CK is an internationally recognised cybersecurity framework
    MITRE_MAP = {
        "Failed Login Burst":          "T1110 – Brute Force",
        "Brute Force Success":         "T1110 – Brute Force",
        "Privilege Escalation":        "T1068 – Exploitation for Privilege Escalation",
        "Odd Hour Login":              "T1078 – Valid Accounts",
        "Multiple IP Addresses":       "T1090 – Proxy",
        "Account Enumeration":         "T1087 – Account Discovery",
        "Rapid Successive Logins":     "T1078 – Valid Accounts",
        "After Hours File Access":     "T1083 – File & Directory Discovery",
        "High Volume From IP":         "T1046 – Network Service Discovery",
        "Suspicious Keyword Detected": "T1059 – Command & Scripting Interpreter",
        "Session Anomaly":             "T1563 – Remote Service Session Hijacking",
        "ML Anomaly Detected":         "T1499 – Endpoint Denial of Service",
    }

    def __init__(self):
        self.rule_alert_file = "../data/rule_alerts.json"
        self.anomaly_file    = "../data/anomalies.csv"
        self.output_file     = "../data/final_alerts.json"
        self.seen_hashes     = set()  # used to track duplicates

        # Read notification settings from environment variables (.env file)
        self.smtp_host   = os.getenv("SMTP_HOST", "")
        self.smtp_port   = int(os.getenv("SMTP_PORT", 587))
        self.smtp_user   = os.getenv("SMTP_USER", "")
        self.smtp_pass   = os.getenv("SMTP_PASS", "")
        self.alert_email = os.getenv("ALERT_EMAIL", "")
        self.webhook_url = os.getenv("WEBHOOK_URL", "")  # Slack / Teams / Discord

    # ── Alert Builder ─────────────────────────────────────────────────

    def make_alert(self, alert_type, message, severity,
                   username="N/A", ip=None, risk_score=None,
                   source="rule", timestamp=None):
        """Create a standard alert dictionary with all required fields."""
        return {
            "id":             self._make_id(alert_type, message, username),
            "timestamp":      str(timestamp or datetime.now()),
            "type":           alert_type,
            "message":        message,
            "severity":       severity,
            "severity_score": self.SEVERITY_SCORE.get(severity, 0),
            "username":       username,
            "ip_address":     ip or "N/A",
            "risk_score":     round(risk_score, 2) if risk_score is not None else None,
            "source":         source,   # "rule" = from rule engine, "ml" = from AI model
            "mitre_tactic":   self.MITRE_MAP.get(alert_type, "Unknown"),
        }

    def _make_id(self, *parts):
        """
        Create a unique 12-character ID from alert type + message + username.
        Used to detect and remove duplicate alerts.
        """
        raw = "|".join(str(p) for p in parts)
        return hashlib.md5(raw.encode()).hexdigest()[:12]

    def is_duplicate(self, alert):
        """Return True if we have already seen this exact alert."""
        h = alert["id"]
        if h in self.seen_hashes:
            return True
        self.seen_hashes.add(h)
        return False

    # ── Notifications ─────────────────────────────────────────────────

    def send_email(self, alerts):
        """Send email summary of Critical and High alerts via SMTP."""
        if not all([self.smtp_host, self.smtp_user, self.smtp_pass, self.alert_email]):
            print("[INFO] Email not configured — skipping.")
            return

        critical = [a for a in alerts if a["severity"] in ("Critical", "High")]
        if not critical:
            return

        # Build email body
        lines = [f"SIEM Alert Summary — {datetime.now().strftime('%Y-%m-%d %H:%M')}\n"]
        for a in critical[:20]:
            lines.append(f"[{a['severity']}] {a['type']} | User: {a['username']} | {a['message']}")

        msg            = MIMEMultipart()
        msg["Subject"] = f"🚨 SIEM: {len(critical)} Critical/High Alerts Detected"
        msg["From"]    = self.smtp_user
        msg["To"]      = self.alert_email
        msg.attach(MIMEText("\n".join(lines), "plain"))

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()  # encrypt the connection
                server.login(self.smtp_user, self.smtp_pass)
                server.send_message(msg)
            print(f"[OK] Email sent to {self.alert_email}")
        except Exception as e:
            print(f"[ERROR] Email failed: {e}")

    def send_webhook(self, alerts):
        """Send alert summary to Slack, Teams, or Discord via webhook URL."""
        if not self.webhook_url:
            print("[INFO] Webhook not configured — skipping.")
            return

        critical = [a for a in alerts if a["severity"] in ("Critical", "High")]
        if not critical:
            return

        lines = [f"*🚨 SIEM Alert — {datetime.now().strftime('%Y-%m-%d %H:%M')}*"]
        for a in critical[:10]:
            lines.append(f"• `[{a['severity']}]` *{a['type']}* — {a['username']} — {a['message'][:80]}")

        try:
            r = requests.post(self.webhook_url, json={"text": "\n".join(lines)}, timeout=10)
            if r.status_code == 200:
                print("[OK] Webhook notification sent.")
            else:
                print(f"[WARN] Webhook returned status {r.status_code}")
        except Exception as e:
            print(f"[ERROR] Webhook failed: {e}")

    # ── Main Generator ────────────────────────────────────────────────

    def generate(self):
        """
        Main function — combines rule alerts and ML anomalies,
        deduplicates, enriches with MITRE tags, sorts, saves, and notifies.
        """
        alerts = []

        # ── Step 1: Load and process rule-based alerts ────────────────
        try:
            with open(self.rule_alert_file) as f:
                rule_alerts = json.load(f)
        except Exception as e:
            print(f"[WARNING] Could not load rule alerts: {e}")
            rule_alerts = []

        for ra in rule_alerts:
            alert = self.make_alert(
                alert_type = ra.get("type", "Rule Alert"),
                message    = ra.get("description", ra.get("message", "Security rule triggered")),
                severity   = ra.get("severity", "Medium"),
                username   = ra.get("username", "N/A"),
                ip         = ra.get("ip_address"),
                source     = "rule",
                timestamp  = ra.get("timestamp"),
            )
            if not self.is_duplicate(alert):
                alerts.append(alert)

        # ── Step 2: Load and process ML anomaly alerts ────────────────
        try:
            anomalies = pd.read_csv(self.anomaly_file)
        except Exception as e:
            print(f"[WARNING] Could not load anomalies: {e}")
            anomalies = pd.DataFrame()

        if not anomalies.empty:
            for _, row in anomalies[anomalies["anomaly"] == -1].iterrows():
                severity = row.get("severity", "Medium")
                alert = self.make_alert(
                    alert_type = "ML Anomaly Detected",
                    message    = str(row.get("message", "Suspicious log entry"))[:200],
                    severity   = severity if severity != "Normal" else "Medium",
                    username   = str(row.get("username", "Unknown")),
                    ip         = row.get("ip_address"),
                    risk_score = float(row["risk_score"]) if pd.notna(row.get("risk_score")) else None,
                    source     = "ml",
                    timestamp  = row.get("timestamp"),
                )
                if not self.is_duplicate(alert):
                    alerts.append(alert)

        # ── Step 3: Sort by severity (Critical first) ─────────────────
        alerts.sort(key=lambda x: x["severity_score"], reverse=True)

        # ── Step 4: Save to file ──────────────────────────────────────
        with open(self.output_file, "w") as f:
            json.dump(alerts, f, indent=4, default=str)

        # ── Step 5: Print summary ─────────────────────────────────────
        counts = Counter(a["severity"] for a in alerts)
        print(f"[OK] {len(alerts)} alerts saved -> {self.output_file}")
        print(f"     Critical={counts.get('Critical',0)}  "
              f"High={counts.get('High',0)}  "
              f"Medium={counts.get('Medium',0)}  "
              f"Low={counts.get('Low',0)}")

        # ── Step 6: Send notifications ────────────────────────────────
        self.send_email(alerts)
        self.send_webhook(alerts)

        return alerts


if __name__ == "__main__":
    generator = AlertGenerator()
    generator.generate()
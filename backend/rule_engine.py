"""
Step 3 — Rule Engine
=====================
Detects known security threats using 11 rules based on real attack patterns.
Each rule checks for a specific type of suspicious behaviour.

Input:  ../data/structured_logs.csv
Output: ../data/rule_alerts.json

Rules:
  1.  Failed Login Burst         — too many failed logins for one user
  2.  Privilege Escalation       — admin rights gained after failed logins
  3.  Odd Hour Login             — login between midnight and 5 AM
  4.  Brute Force Success        — failed logins followed by a successful one
  5.  Multiple IP Addresses      — same user logging in from many IPs
  6.  Account Enumeration        — many failed logins across different usernames
  7.  Rapid Successive Logins    — multiple logins within 60 seconds
  8.  After Hours File Access    — files accessed late at night
  9.  High Volume From IP        — one IP generating too many events
  10. Suspicious Keywords        — known hacking tool names in log messages
  11. Session Anomaly            — more logouts than logins (possible tampering)
"""

import pandas as pd
import json
from datetime import datetime


class RuleEngine:

    def __init__(self):
        self.input_path  = "../data/structured_logs.csv"
        self.output_path = "../data/rule_alerts.json"

    # ── Helper ────────────────────────────────────────────────────────

    def make_alert(self, alert_type, severity, username, description,
                   timestamp=None, ip=None, count=None):
        """Create a standard alert dictionary."""
        alert = {
            "type":        alert_type,
            "severity":    severity,
            "username":    str(username),
            "description": description,
            "timestamp":   str(timestamp or datetime.now()),
        }
        if ip:
            alert["ip_address"] = str(ip)
        if count is not None:
            alert["count"] = int(count)
        return alert

    # ── Rules ─────────────────────────────────────────────────────────

    def detect_failed_login_bursts(self, df):
        """Rule 1: Alert if a user has 8 or more failed login attempts."""
        alerts  = []
        failed  = df[df["event_type_clean"] == "Failed Login"]
        grouped = failed.groupby("username").size()

        for username, count in grouped.items():
            if count >= 8:
                alerts.append(self.make_alert(
                    "Failed Login Burst", "High", username,
                    f"{count} failed login attempts for '{username}'.",
                    count=count
                ))
        return alerts

    def detect_privilege_escalation(self, df):
        """
        Rule 2: Alert if privilege escalation happens after failed logins,
        or if it comes from an external IP address.
        This avoids false positives from normal Windows system processes.
        """
        alerts       = []
        priv_events  = df[df["event_type_clean"] == "Privilege Escalation"]
        failed_users = set(df[df["event_type_clean"] == "Failed Login"]["username"])

        for _, row in priv_events.iterrows():
            user = row["username"]
            ip   = str(row.get("ip_address", ""))

            # External IPs start with these ranges (not internal 192.168.x.x)
            is_external = ip.startswith("203.") or ip.startswith("185.") or ip.startswith("45.")

            if user in failed_users or is_external:
                alerts.append(self.make_alert(
                    "Privilege Escalation", "Critical", user,
                    f"Privilege escalation detected for '{user}'.",
                    timestamp=row["timestamp"], ip=row.get("ip_address")
                ))
        return alerts

    def detect_odd_hour_logins(self, df):
        """Rule 3: Alert if a successful login happens between midnight and 5 AM."""
        alerts = []
        logins = df[df["event_type_clean"] == "Successful Login"]

        for _, row in logins.iterrows():
            try:
                hour = pd.to_datetime(row["timestamp"]).hour
            except Exception:
                continue

            if 0 <= hour <= 5:
                alerts.append(self.make_alert(
                    "Odd Hour Login", "Medium", row["username"],
                    f"Login between 12 AM and 5 AM by '{row['username']}'.",
                    timestamp=row["timestamp"], ip=row.get("ip_address")
                ))
        return alerts

    def detect_brute_force_success(self, df):
        """
        Rule 4: Alert if a user had multiple failed logins and then
        successfully logged in — this means the attacker got in.
        """
        alerts  = []
        df_sort = df.sort_values("timestamp")

        for user in df_sort["username"].unique():
            u_df     = df_sort[df_sort["username"] == user]
            failures = u_df[u_df["event_type_clean"] == "Failed Login"]
            success  = u_df[u_df["event_type_clean"] == "Successful Login"]

            if len(failures) >= 3 and len(success) >= 1:
                last_fail = failures["timestamp"].max()
                first_ok  = success["timestamp"].min()

                # Success must come AFTER the failures
                if pd.notna(last_fail) and pd.notna(first_ok) and first_ok > last_fail:
                    alerts.append(self.make_alert(
                        "Brute Force Success", "Critical", user,
                        f"'{user}' had {len(failures)} failed logins then logged in successfully.",
                        timestamp=first_ok, count=len(failures)
                    ))
        return alerts

    def detect_multiple_ips(self, df):
        """Rule 5: Alert if a user logs in from 3 or more different IP addresses."""
        alerts  = []
        has_ip  = df[df["ip_address"].notna() & (df["ip_address"] != "None")]
        grouped = has_ip.groupby("username")["ip_address"].nunique()

        for username, ip_count in grouped.items():
            if ip_count >= 3:
                alerts.append(self.make_alert(
                    "Multiple IP Addresses", "High", username,
                    f"'{username}' accessed the system from {ip_count} different IP addresses.",
                    count=ip_count
                ))
        return alerts

    def detect_account_enumeration(self, df):
        """
        Rule 6: Alert if there are many failed logins with unknown usernames
        or across many different usernames — sign of an attacker scanning accounts.
        """
        alerts = []
        failed = df[df["event_type_clean"] == "Failed Login"]

        # Many failures with unknown usernames
        unknown = failed[failed["username"].isin(["Unknown", "-", ""])]
        if len(unknown) >= 10:
            alerts.append(self.make_alert(
                "Account Enumeration", "High", "N/A",
                f"{len(unknown)} failed logins with unknown usernames detected.",
                count=len(unknown)
            ))

        # Many distinct usernames failing
        distinct = failed["username"].nunique()
        if distinct >= 10:
            alerts.append(self.make_alert(
                "Account Enumeration", "High", "Multiple",
                f"Failed logins across {distinct} different usernames — possible enumeration.",
                count=distinct
            ))
        return alerts

    def detect_rapid_logins(self, df):
        """Rule 7: Alert if a user logs in multiple times within 60-second windows."""
        alerts  = []
        logins  = df[df["event_type_clean"] == "Successful Login"].sort_values("timestamp")

        for user, grp in logins.groupby("username"):
            times = grp["timestamp"].dropna().sort_values().tolist()
            rapid = 0

            for i in range(1, len(times)):
                if (times[i] - times[i - 1]).total_seconds() < 60:
                    rapid += 1

            if rapid >= 3:
                alerts.append(self.make_alert(
                    "Rapid Successive Logins", "Medium", user,
                    f"'{user}' logged in {rapid} times within 60-second windows.",
                    count=rapid
                ))
        return alerts

    def detect_after_hours_file_access(self, df):
        """Rule 8: Alert if files are accessed after 8 PM or before 6 AM."""
        alerts = []
        fa     = df[df["event_type_clean"] == "File Access"]

        for _, row in fa.iterrows():
            try:
                hour = pd.to_datetime(row["timestamp"]).hour
            except Exception:
                continue

            if hour >= 20 or hour <= 6:
                alerts.append(self.make_alert(
                    "After Hours File Access", "Medium", row["username"],
                    f"File accessed at {hour}:00 (after hours) by '{row['username']}'.",
                    timestamp=row["timestamp"]
                ))
        return alerts

    def detect_high_volume_ip(self, df):
        """Rule 9: Alert if a single IP address generates 150 or more events."""
        alerts  = []
        has_ip  = df[df["ip_address"].notna() & (df["ip_address"] != "None")]
        grouped = has_ip.groupby("ip_address").size()

        for ip, count in grouped.items():
            if count >= 150:
                alerts.append(self.make_alert(
                    "High Volume From IP", "High", "N/A",
                    f"IP address {ip} generated {count} events — possible scan or attack.",
                    ip=ip, count=count
                ))
        return alerts

    def detect_suspicious_keywords(self, df):
        """
        Rule 10: Alert if log messages contain known hacking tool names
        or suspicious commands like mimikatz, powershell -enc, etc.
        """
        alerts   = []
        keywords = [
            "malware", "ransomware", "exploit", "shellcode",
            "mimikatz", "powershell -enc", "base64", "cmd.exe /c",
            "wget http", "curl http", "/etc/passwd", "net user /add"
        ]

        pattern = "|".join(keywords)
        matches = df[df["message"].str.contains(pattern, case=False, na=False)]

        for _, row in matches.iterrows():
            alerts.append(self.make_alert(
                "Suspicious Keyword Detected", "Critical", row["username"],
                f"Suspicious keyword in log by '{row['username']}': {str(row['message'])[:120]}",
                timestamp=row["timestamp"], ip=row.get("ip_address")
            ))
        return alerts

    def detect_orphan_logouts(self, df):
        """
        Rule 11: Alert if a user has significantly more logouts than logins.
        This could mean session hijacking or log file tampering.
        """
        alerts  = []
        df_sort = df.sort_values("timestamp")

        for user, grp in df_sort.groupby("username"):
            logouts = grp["event_type_clean"].tolist().count("Logout")
            logins  = grp["event_type_clean"].tolist().count("Successful Login")

            if logouts > logins + 2:
                alerts.append(self.make_alert(
                    "Session Anomaly", "Low", user,
                    f"'{user}' has {logouts} logouts but only {logins} logins — "
                    f"possible session hijacking or log tampering.",
                    count=logouts
                ))
        return alerts

    # ── Main Runner ───────────────────────────────────────────────────

    def run_rules(self):
        """Run all 11 rules and save combined alerts to JSON file."""
        df = pd.read_csv(self.input_path)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df["message"]   = df["message"].astype(str)

        all_alerts = []
        rules = [
            self.detect_failed_login_bursts,
            self.detect_privilege_escalation,
            self.detect_odd_hour_logins,
            self.detect_brute_force_success,
            self.detect_multiple_ips,
            self.detect_account_enumeration,
            self.detect_rapid_logins,
            self.detect_after_hours_file_access,
            self.detect_high_volume_ip,
            self.detect_suspicious_keywords,
            self.detect_orphan_logouts,
        ]

        for rule in rules:
            try:
                results = rule(df)
                all_alerts.extend(results)
                if results:
                    print(f"  [RULE] {rule.__name__}: {len(results)} alert(s)")
            except Exception as e:
                print(f"  [WARN] {rule.__name__} failed: {e}")

        with open(self.output_path, "w") as f:
            json.dump(all_alerts, f, indent=4, default=str)

        print(f"[OK] {len(all_alerts)} rule alerts saved -> {self.output_path}")
        return all_alerts


if __name__ == "__main__":
    engine = RuleEngine()
    engine.run_rules()
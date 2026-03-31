import pandas as pd
import json
from datetime import datetime, timedelta
from collections import defaultdict


class RuleEngine:

    def __init__(
        self,
        input_path="../data/structured_logs.csv",
        output_path="../data/rule_alerts.json",
    ):
        self.input_path  = input_path
        self.output_path = output_path

    # ------------------------------------------------------------------
    # Loader
    # ------------------------------------------------------------------

    def load_logs(self):
        df = pd.read_csv(self.input_path)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df["message"]   = df["message"].astype(str)
        return df

    # ------------------------------------------------------------------
    # Helper
    # ------------------------------------------------------------------

    def alert(self, alert_type, severity, username, description,
               timestamp=None, ip=None, count=None):
        a = {
            "type":        alert_type,
            "severity":    severity,
            "username":    str(username),
            "description": description,
            "timestamp":   str(timestamp or datetime.now()),
        }
        if ip:
            a["ip_address"] = str(ip)
        if count is not None:
            a["count"] = int(count)
        return a

    # ------------------------------------------------------------------
    # Rule 1 — Failed login burst
    # ------------------------------------------------------------------

    def detect_failed_login_bursts(self, df):
        alerts = []
        failed  = df[df["event_type_clean"] == "Failed Login"]
        grouped = failed.groupby("username").size()
        for username, count in grouped.items():
            if count >= 8:   # raised threshold — avoids false positives from typos
                alerts.append(self.alert(
                    "Failed Login Burst", "High", username,
                    f"{count} failed login attempts for '{username}'.",
                    count=count
                ))
        return alerts

    # ------------------------------------------------------------------
    # Rule 2 — Privilege escalation
    # ------------------------------------------------------------------

    def detect_privilege_escalation(self, df):
        alerts = []
        priv   = df[df["event_type_clean"] == "Privilege Escalation"]

        # Only alert if the same user has privilege escalation AND
        # a failed login — reduces false positives from normal system processes
        failed_users = set(
            df[df["event_type_clean"] == "Failed Login"]["username"].tolist()
        )

        # Also alert for any unknown/external IP doing priv escalation
        for _, row in priv.iterrows():
            user = row["username"]
            ip   = str(row.get("ip_address", ""))
            is_external = ip.startswith("203.") or ip.startswith("185.") \
                          or ip.startswith("45.")

            if user in failed_users or is_external:
                alerts.append(self.alert(
                    "Privilege Escalation", "Critical", user,
                    f"Privilege escalation detected for '{user}'.",
                    timestamp=row["timestamp"], ip=row.get("ip_address")
                ))
        return alerts

    # ------------------------------------------------------------------
    # Rule 3 — Odd-hour logins (midnight–5 AM)
    # ------------------------------------------------------------------

    def detect_odd_hour_logins(self, df):
        alerts = []
        logins  = df[df["event_type_clean"] == "Successful Login"]
        for _, row in logins.iterrows():
            try:
                hour = pd.to_datetime(row["timestamp"]).hour
            except Exception:
                continue
            if 0 <= hour <= 5:
                alerts.append(self.alert(
                    "Odd Hour Login", "Medium", row["username"],
                    f"Login between 12 AM–5 AM by '{row['username']}'.",
                    timestamp=row["timestamp"], ip=row.get("ip_address")
                ))
        return alerts

    # ------------------------------------------------------------------
    # Rule 4 — Brute-force: many failures then success
    # ------------------------------------------------------------------

    def detect_brute_force_success(self, df):
        alerts  = []
        df_sort = df.sort_values("timestamp")
        users   = df_sort["username"].unique()
        for user in users:
            u_df     = df_sort[df_sort["username"] == user]
            failures = u_df[u_df["event_type_clean"] == "Failed Login"]
            success  = u_df[u_df["event_type_clean"] == "Successful Login"]
            if len(failures) >= 3 and len(success) >= 1:
                last_fail = failures["timestamp"].max()
                first_ok  = success["timestamp"].min()
                if pd.notna(last_fail) and pd.notna(first_ok) and first_ok > last_fail:
                    alerts.append(self.alert(
                        "Brute Force Success", "Critical", user,
                        f"'{user}' had {len(failures)} failures then logged in successfully.",
                        timestamp=first_ok, count=len(failures)
                    ))
        return alerts

    # ------------------------------------------------------------------
    # Rule 5 — Multiple IPs for same user
    # ------------------------------------------------------------------

    def detect_multiple_ips(self, df):
        alerts  = []
        has_ip  = df[df["ip_address"].notna() & (df["ip_address"] != "None")]
        grouped = has_ip.groupby("username")["ip_address"].nunique()
        for username, ip_count in grouped.items():
            if ip_count >= 3:
                alerts.append(self.alert(
                    "Multiple IP Addresses", "High", username,
                    f"'{username}' accessed from {ip_count} different IPs.",
                    count=ip_count
                ))
        return alerts

    # ------------------------------------------------------------------
    # Rule 6 — Account enumeration (many distinct unknown users failing)
    # ------------------------------------------------------------------

    def detect_account_enumeration(self, df):
        alerts  = []
        failed  = df[df["event_type_clean"] == "Failed Login"]
        unknown = failed[failed["username"].isin(["Unknown", "-", ""])]
        if len(unknown) >= 10:
            alerts.append(self.alert(
                "Account Enumeration", "High", "N/A",
                f"{len(unknown)} failed logins with unknown/anonymous usernames detected.",
                count=len(unknown)
            ))
        # Also flag if many distinct usernames failing quickly
        distinct_users = failed["username"].nunique()
        if distinct_users >= 10:
            alerts.append(self.alert(
                "Account Enumeration", "High", "Multiple",
                f"Failed logins across {distinct_users} different usernames — possible enumeration.",
                count=distinct_users
            ))
        return alerts

    # ------------------------------------------------------------------
    # Rule 7 — Rapid successive logins (same user, <1 min apart)
    # ------------------------------------------------------------------

    def detect_rapid_logins(self, df):
        alerts  = []
        logins  = df[df["event_type_clean"] == "Successful Login"].sort_values("timestamp")
        grouped = logins.groupby("username")
        for user, grp in grouped:
            times = grp["timestamp"].dropna().sort_values().tolist()
            rapid = 0
            for i in range(1, len(times)):
                delta = (times[i] - times[i - 1]).total_seconds()
                if delta < 60:
                    rapid += 1
            if rapid >= 3:
                alerts.append(self.alert(
                    "Rapid Successive Logins", "Medium", user,
                    f"'{user}' had {rapid} logins within 60-second windows.",
                    count=rapid
                ))
        return alerts

    # ------------------------------------------------------------------
    # Rule 8 — After-hours file access
    # ------------------------------------------------------------------

    def detect_after_hours_file_access(self, df):
        alerts = []
        fa     = df[df["event_type_clean"] == "File Access"]
        for _, row in fa.iterrows():
            try:
                hour = pd.to_datetime(row["timestamp"]).hour
            except Exception:
                continue
            if hour >= 20 or hour <= 6:
                alerts.append(self.alert(
                    "After Hours File Access", "Medium", row["username"],
                    f"File access at unusual hour ({hour}:00) by '{row['username']}'.",
                    timestamp=row["timestamp"]
                ))
        return alerts

    # ------------------------------------------------------------------
    # Rule 9 — High-volume events from single source IP
    # ------------------------------------------------------------------

    def detect_high_volume_ip(self, df):
        alerts  = []
        has_ip  = df[df["ip_address"].notna() & (df["ip_address"] != "None")]
        grouped = has_ip.groupby("ip_address").size()
        for ip, count in grouped.items():
            if count >= 150:   # raised — 50 was too sensitive for normal traffic
                alerts.append(self.alert(
                    "High Volume From IP", "High", "N/A",
                    f"IP {ip} generated {count} events — possible scan or attack.",
                    ip=ip, count=count
                ))
        return alerts

    # ------------------------------------------------------------------
    # Rule 10 — Suspicious keywords in messages
    # ------------------------------------------------------------------

    def detect_suspicious_keywords(self, df):
        alerts   = []
        keywords = [
            "malware", "ransomware", "exploit", "shellcode",
            "mimikatz", "powershell -enc", "base64", "cmd.exe /c",
            "wget http", "curl http", "/etc/passwd", "net user /add"
        ]
        pattern = "|".join(keywords)
        matches = df[df["message"].str.contains(pattern, case=False, na=False)]
        for _, row in matches.iterrows():
            alerts.append(self.alert(
                "Suspicious Keyword Detected", "Critical", row["username"],
                f"Suspicious keyword found in log by '{row['username']}': "
                f"{str(row['message'])[:120]}",
                timestamp=row["timestamp"], ip=row.get("ip_address")
            ))
        return alerts

    # ------------------------------------------------------------------
    # Rule 11 — Repeated logouts without re-login (session anomaly)
    # ------------------------------------------------------------------

    def detect_orphan_logouts(self, df):
        alerts  = []
        df_sort = df.sort_values("timestamp")
        for user, grp in df_sort.groupby("username"):
            events  = grp["event_type_clean"].tolist()
            logouts = events.count("Logout")
            logins  = events.count("Successful Login")
            if logouts > logins + 2:
                alerts.append(self.alert(
                    "Session Anomaly", "Low", user,
                    f"'{user}' has {logouts} logouts but only {logins} logins — "
                    f"possible session hijacking or log tampering.",
                    count=logouts
                ))
        return alerts

    # ------------------------------------------------------------------
    # Runner
    # ------------------------------------------------------------------

    def run_rules(self):
        df = self.load_logs()

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

        for rule_fn in rules:
            try:
                results = rule_fn(df)
                all_alerts.extend(results)
                if results:
                    print(f"  [RULE] {rule_fn.__name__}: {len(results)} alert(s)")
            except Exception as e:
                print(f"  [WARN] {rule_fn.__name__} failed: {e}")

        with open(self.output_path, "w") as f:
            json.dump(all_alerts, f, indent=4, default=str)

        print(f"[OK] {len(all_alerts)} rule-based alerts saved -> {self.output_path}")
        return all_alerts


if __name__ == "__main__":
    engine = RuleEngine()
    engine.run_rules()
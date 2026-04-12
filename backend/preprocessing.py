"""
Step 2 — Preprocessor
======================
Reads raw logs and extracts useful fields from the message text.
Adds time-based features used by the ML model.

Input:  ../data/processed_logs.csv
Output: ../data/structured_logs.csv
"""

import pandas as pd
import re


class Preprocessor:

    def __init__(self):
        self.input_path  = "../data/processed_logs.csv"
        self.output_path = "../data/structured_logs.csv"

    # ── Extract Fields from Raw Log Messages ─────────────────────────

    def extract_username(self, message):
        """Extract username from log message using regex patterns."""
        if not isinstance(message, str):
            return "Unknown"

        patterns = [
            r'Account Name:\s*([A-Za-z0-9_\\$\-\.]+)',
            r'user(?:name)?\s*[:=]\s*([A-Za-z0-9_\\$\-\.]+)',
            r'Subject Account Name:\s*([A-Za-z0-9_\\$\-\.]+)',
            r'New Logon.*?Account Name:\s*([A-Za-z0-9_\\$\-\.]+)',
            r'for\s+([A-Za-z0-9_\\$\-\.]+)\s+on',
        ]

        for pattern in patterns:
            match = re.search(pattern, message, re.IGNORECASE)
            if match:
                value = match.group(1).strip()
                if value and value not in ("-", "$", ""):
                    return value

        return "Unknown"

    def extract_ip(self, message):
        """Extract IP address from log message. Ignores loopback addresses."""
        if not isinstance(message, str):
            return None

        match = re.search(r"(\d{1,3}\.){3}\d{1,3}", message)
        if match:
            ip = match.group(0)
            # Skip loopback and empty addresses
            if not ip.startswith("127.") and ip != "0.0.0.0":
                return ip

        return None

    def extract_event_type(self, event_id):
        """
        Convert a Windows Event ID number to a human-readable label.
        For example: 4625 → 'Failed Login', 4672 → 'Privilege Escalation'
        """
        try:
            event_id = int(event_id)
        except Exception:
            return "Other"

        mapping = {
            4624: "Successful Login",
            4625: "Failed Login",
            4634: "Logout",
            4647: "Logout",
            4648: "Explicit Credential Login",
            4656: "File Access",
            4657: "Registry Modified",
            4663: "File Access",
            4672: "Privilege Escalation",
            4673: "Privilege Escalation",
            4688: "Process Created",
            4689: "Process Terminated",
            4698: "Scheduled Task Created",
            4699: "Scheduled Task Deleted",
            4700: "Scheduled Task Enabled",
            4702: "Scheduled Task Updated",
            4719: "Audit Policy Changed",
            4720: "User Account Created",
            4722: "User Account Enabled",
            4723: "Password Change Attempt",
            4724: "Password Reset Attempt",
            4725: "User Account Disabled",
            4726: "User Account Deleted",
            4728: "User Added to Group",
            4732: "User Added to Group",
            4740: "Account Locked Out",
            4756: "User Added to Group",
            4767: "Account Unlocked",
            4768: "Kerberos TGT Request",
            4769: "Kerberos Service Ticket",
            4771: "Kerberos Pre-auth Failed",
            4776: "NTLM Auth Attempt",
            4798: "User Local Group Enum",
            4799: "Group Membership Enum",
            5140: "Network Share Access",
            5145: "Network Share Check",
            7034: "Service Crashed",
            7036: "Service State Change",
            7045: "New Service Installed",
        }

        return mapping.get(event_id, "Other")

    def flag_suspicious(self, row):
        """
        Add quick flag labels to each log entry for easy filtering.
        Examples: 'failed_login', 'priv_esc', 'suspicious_cmd', 'night_activity'
        """
        flags = []
        msg   = str(row.get("message", "")).lower()
        et    = row.get("event_type_clean", "")

        if et == "Failed Login":
            flags.append("failed_login")
        if et == "Privilege Escalation":
            flags.append("priv_esc")
        if et in ("Process Created", "Scheduled Task Created", "New Service Installed"):
            flags.append("execution")
        if any(k in msg for k in ["mimikatz", "powershell -enc", "base64", "cmd /c", "/etc/passwd"]):
            flags.append("suspicious_cmd")
        if row.get("is_night"):
            flags.append("night_activity")

        return ",".join(flags) if flags else ""

    # ── Main Pipeline ─────────────────────────────────────────────────

    def preprocess(self):
        """
        Run the full preprocessing pipeline:
        1. Load raw logs
        2. Extract username, IP, event type from message text
        3. Add time-based features (hour, is_night, is_weekend)
        4. Add suspicious activity flags
        5. Save to structured_logs.csv
        """
        # Load raw logs
        df = pd.read_csv(self.input_path)
        df["message"] = df["message"].astype(str)

        # Extract fields from raw message text
        df["username"]         = df["message"].apply(self.extract_username)
        df["ip_address"]       = df["message"].apply(self.extract_ip)
        df["event_type_clean"] = df["event_id"].apply(self.extract_event_type)

        # Add time-based features for ML model
        df["timestamp"]   = pd.to_datetime(df["timestamp"], errors="coerce")
        df["hour"]        = df["timestamp"].dt.hour
        df["day_of_week"] = df["timestamp"].dt.dayofweek
        df["is_night"]    = df["hour"].apply(lambda h: int(h >= 22 or h <= 5))
        df["is_weekend"]  = df["day_of_week"].isin([5, 6]).astype(int)

        # Add suspicious activity flags
        df["flags"] = df.apply(self.flag_suspicious, axis=1)

        # Save structured logs
        df.to_csv(self.output_path, index=False)
        print(f"[OK] Structured logs saved -> {self.output_path}  ({len(df)} rows)")
        return df


if __name__ == "__main__":
    processor = Preprocessor()
    processor.preprocess()
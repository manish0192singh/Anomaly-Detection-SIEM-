"""
Step 1 — Log Collector
=======================
Collects Windows Event Logs from Security, System, and Application channels.
On non-Windows systems, generates realistic demo data instead.

Output: ../data/processed_logs.csv
"""

import pandas as pd
import os
import platform
import random
from datetime import datetime, timedelta

# Load settings for log limit
from settings_loader import get_settings
settings = get_settings()
LOG_LIMIT = settings.get("log_limit", 5000)

# Try to import Windows-only library
if platform.system() == "Windows":
    try:
        import win32evtlog
        import win32evtlogutil
        WINDOWS_AVAILABLE = True
    except ImportError:
        WINDOWS_AVAILABLE = False
        print("[WARNING] pywin32 not installed. Run: pip install pywin32")
else:
    WINDOWS_AVAILABLE = False
    print("[INFO] Non-Windows system — using demo data.")


class WindowsLogCollector:

    def __init__(self):
        self.channels    = ["Security", "System", "Application"]
        self.output_path = "../data/processed_logs.csv"
        self.max_records = LOG_LIMIT   # ← ONLY CHANGE HERE

    # ── Real Windows Log Collection ───────────────────────────────────

    def read_windows_logs(self):
        """Read real logs from Windows Event Log channels."""
        logs = []

        for channel in self.channels:
            count = 0
            try:
                handle = win32evtlog.OpenEventLog(None, channel)
                flags  = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                          win32evtlog.EVENTLOG_SEQUENTIAL_READ)

                while count < self.max_records:   # ← UPDATED TO USE LOG LIMIT
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not events:
                        break

                    for event in events:
                        if count >= self.max_records:
                            break

                        try:
                            message = win32evtlogutil.SafeFormatMessage(event, channel)
                        except Exception:
                            message = f"Event ID {event.EventID & 0xFFFF}"

                        if not message or not message.strip():
                            message = f"Event ID {event.EventID & 0xFFFF} from {channel}"

                        logs.append({
                            "timestamp":  str(event.TimeGenerated),
                            "source":     channel,
                            "event_id":   event.EventID & 0xFFFF,
                            "event_type": event.EventType,
                            "computer":   event.ComputerName,
                            "message":    message.strip()[:500],
                        })
                        count += 1

                win32evtlog.CloseEventLog(handle)
                print(f"  [OK] {channel}: {count} events collected")

            except Exception as e:
                print(f"  [ERROR] Cannot read {channel}: {e}")

        return pd.DataFrame(logs)

    # ── Demo Data (used on non-Windows systems) ───────────────────────

    def generate_demo_logs(self):
        print("  [INFO] Generating demo log data...")

        random.seed(42)

        users     = ["john.smith", "sarah.jones", "mike.brown",
                     "lisa.white", "david.clark", "svc_backup", "svc_antivirus"]
        computers = ["DESKTOP-JOHN", "LAPTOP-SARAH", "DESKTOP-MIKE",
                     "LAPTOP-LISA", "SERVER-01"]
        ips       = ["192.168.1.101", "192.168.1.102", "192.168.1.103",
                     "192.168.1.104", "192.168.1.10"]

        event_profiles = [
            (4624, 1),
            (4634, 1),
            (4688, 1),
            (4663, 1),
            (4625, 2),
            (4648, 2),
            (4720, 4),
            (4672, 3),
            (4740, 3),
            (5140, 2),
        ]
        weights = [35, 25, 15, 10, 5, 3, 1, 2, 1, 3]

        logs = []
        base = datetime.now()

        # Respect LOG LIMIT for demo logs too
        max_entries = LOG_LIMIT

        for _ in range(max_entries):
            if random.random() < 0.85:
                hour = random.randint(8, 18)
            else:
                hour = random.choice(list(range(0, 8)) + list(range(19, 24)))

            timestamp = (base - timedelta(days=random.randint(0, 6))).replace(
                hour=hour,
                minute=random.randint(0, 59),
                second=random.randint(0, 59)
            )

            eid, etype = random.choices(event_profiles, weights=weights, k=1)[0]
            user = random.choice(users)
            comp = random.choice(computers)
            ip   = random.choice(ips)

            logs.append({
                "timestamp":  timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "source":     "Security" if eid in [4624,4625,4634,4672,4740,4648] else "System",
                "event_id":   eid,
                "event_type": etype,
                "computer":   comp,
                "message":    _build_message(eid, user, ip, comp),
            })

        logs = _inject_attack(logs, base, users[0], "203.0.113.45")

        df = pd.DataFrame(logs).sort_values("timestamp").reset_index(drop=True)
        print(f"  [OK] Generated {len(df)} demo log entries")
        return df

    # ── Save & Run ────────────────────────────────────────────────────

    def save_logs(self, df):
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        df.to_csv(self.output_path, index=False)
        print(f"[OK] Logs saved -> {self.output_path}  ({len(df)} rows)")

    def run(self):
        df = self.read_windows_logs() if WINDOWS_AVAILABLE else self.generate_demo_logs()

        if df.empty:
            print("[WARNING] No logs collected.")
            return df

        self.save_logs(df)
        return df


# ── Helpers ───────────────────────────────────────────────────────────

def _build_message(event_id, user, ip, computer):
    templates = {
        4624: f"An account was successfully logged on.\nAccount Name: {user}\nSource Network Address: {ip}\nWorkstation Name: {computer}\nLogon Type: 2",
        4625: f"An account failed to log on.\nAccount Name: {user}\nSource Network Address: {ip}\nFailure Reason: Unknown user name or bad password\nLogon Type: 2",
        4634: f"An account was logged off.\nAccount Name: {user}\nLogon Type: 2",
        4672: f"Special privileges assigned to new logon.\nAccount Name: {user}\nPrivileges: SeChangeNotifyPrivilege SeImpersonatePrivilege",
        4688: f"A new process has been created.\nAccount Name: {user}\nProcess Name: C:\\Windows\\System32\\svchost.exe\nCreator Process Name: C:\\Windows\\System32\\services.exe",
        4720: f"A user account was created.\nNew Account Name: {user}_temp\nSubject Account Name: {user}",
        4740: f"A user account was locked out.\nAccount Name: {user}\nCaller Computer Name: {computer}",
        4648: f"A logon was attempted using explicit credentials.\nAccount Name: {user}\nTarget Server Name: {computer}\nNetwork Address: {ip}",
        4663: f"An attempt was made to access an object.\nAccount Name: {user}\nObject Name: C:\\Users\\{user}\\Documents\\report.xlsx\nAccesses: ReadData",
        5140: f"A network share object was accessed.\nAccount Name: {user}\nShare Name: \\\\{computer}\\SharedDocs\nSource Address: {ip}",
    }
    return templates.get(event_id, f"System event {event_id} on {computer} by {user}")


def _inject_attack(logs, base, attacker, attack_ip):
    t = (base - timedelta(days=1)).replace(hour=23, minute=5, second=0)

    for i in range(6):
        logs.append({
            "timestamp":  (t + timedelta(seconds=i * 20)).strftime("%Y-%m-%d %H:%M:%S"),
            "source":     "Security",
            "event_id":   4625,
            "event_type": 2,
            "computer":   "SERVER-01",
            "message":    f"An account failed to log on.\nAccount Name: {attacker}\nSource Network Address: {attack_ip}\nFailure Reason: Wrong password\nLogon Type: 3",
        })

    logs.append({
        "timestamp":  (t + timedelta(seconds=140)).strftime("%Y-%m-%d %H:%M:%S"),
        "source":     "Security",
        "event_id":   4624,
        "event_type": 1,
        "computer":   "SERVER-01",
        "message":    f"An account was successfully logged on.\nAccount Name: {attacker}\nSource Network Address: {attack_ip}\nLogon Type: 3",
    })

    logs.append({
        "timestamp":  (t + timedelta(seconds=180)).strftime("%Y-%m-%d %H:%M:%S"),
        "source":     "Security",
        "event_id":   4672,
        "event_type": 3,
        "computer":   "SERVER-01",
        "message":    f"Special privileges assigned to new logon.\nAccount Name: {attacker}\nPrivileges: SeDebugPrivilege SeTcbPrivilege SeBackupPrivilege\nSource Network Address: {attack_ip}",
    })

    return logs


if __name__ == "__main__":
    pass
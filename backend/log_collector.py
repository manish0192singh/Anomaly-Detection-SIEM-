import pandas as pd
import os
import sys
import platform
from datetime import datetime

# Windows-only import
if platform.system() == "Windows":
    try:
        import win32evtlog
        import win32evtlogutil
        import win32con
        WINDOWS_AVAILABLE = True
    except ImportError:
        WINDOWS_AVAILABLE = False
        print("[WARNING] pywin32 not installed. Run: pip install pywin32")
else:
    WINDOWS_AVAILABLE = False
    print("[INFO] Non-Windows system detected. Using demo data fallback.")


class WindowsLogCollector:

    def __init__(self):
        self.channels    = ["Security", "System", "Application"]
        self.output_path = "../data/processed_logs.csv"
        self.max_records = 5000

    # ------------------------------------------------------------------
    # Real Windows log collection
    # ------------------------------------------------------------------

    def read_windows_logs(self):
        logs = []

        for channel in self.channels:
            print(f"  [INFO] Reading {channel} logs...")
            count = 0

            try:
                handle = win32evtlog.OpenEventLog(None, channel)
                flags  = (
                    win32evtlog.EVENTLOG_BACKWARDS_READ |
                    win32evtlog.EVENTLOG_SEQUENTIAL_READ
                )

                while count < self.max_records:
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not events:
                        break

                    for event in events:
                        if count >= self.max_records:
                            break
                        try:
                            message = win32evtlogutil.SafeFormatMessage(event, channel)
                        except Exception:
                            message = "Unable to parse event message"

                        if not message or message.strip() == "":
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

    # ------------------------------------------------------------------
    # Fallback: realistic demo data (mostly normal, few real threats)
    # ------------------------------------------------------------------

    def generate_demo_logs(self):
        import random
        import numpy as np
        from datetime import timedelta

        print("  [INFO] Generating realistic demo log data...")

        random.seed(42)
        np.random.seed(42)

        # Realistic office users
        users     = ["john.smith", "sarah.jones", "mike.brown",
                     "lisa.white", "david.clark", "svc_backup", "svc_antivirus"]
        computers = ["DESKTOP-JOHN", "LAPTOP-SARAH", "DESKTOP-MIKE",
                     "LAPTOP-LISA", "SERVER-01"]
        # Internal IPs only — realistic office network
        ips       = ["192.168.1.101", "192.168.1.102", "192.168.1.103",
                     "192.168.1.104", "192.168.1.10"]

        # Realistic event distribution
        # Real offices: mostly logins/logouts, very few suspicious events
        event_profiles = [
            (4624, 1),   # Successful Login      — very common
            (4634, 1),   # Logout                — very common
            (4688, 1),   # Process Created       — common
            (4663, 1),   # File Access           — common
            (4625, 2),   # Failed Login          — occasional (typo passwords)
            (4648, 2),   # Explicit Credentials  — occasional
            (4720, 4),   # Account Created       — rare
            (4672, 3),   # Privilege Use         — rare (system processes)
            (4740, 3),   # Account Locked Out    — rare
            (5140, 2),   # Network Share Access  — occasional
        ]

        # 80% of logs are normal login/logout/file activity
        weights = [35, 25, 15, 10, 5, 3, 1, 2, 1, 3]

        logs  = []
        base  = datetime.now()
        total = 2000

        for i in range(total):
            # 85% business hours activity, 15% off-hours
            if random.random() < 0.85:
                hour      = random.randint(8, 18)
                days_back = random.randint(0, 6)
            else:
                hour      = random.choice(list(range(0, 8)) + list(range(19, 24)))
                days_back = random.randint(0, 6)

            minute    = random.randint(0, 59)
            second    = random.randint(0, 59)
            timestamp = (base - timedelta(days=days_back)).replace(
                hour=hour, minute=minute, second=second
            )

            eid, etype = random.choices(event_profiles, weights=weights, k=1)[0]
            user = random.choice(users)
            comp = random.choice(computers)
            ip   = random.choice(ips)

            message = _build_message(eid, user, ip, comp)

            logs.append({
                "timestamp":  timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                "source":     "Security" if eid in [4624,4625,4634,4672,4740,4648]
                              else "System",
                "event_id":   eid,
                "event_type": etype,
                "computer":   comp,
                "message":    message,
            })

        # Inject ONLY 1 small realistic attack to demonstrate detection
        logs = _inject_minimal_attacks(logs, base, users[0], "203.0.113.45")

        df = pd.DataFrame(logs).sort_values("timestamp").reset_index(drop=True)
        print(f"  [OK] Generated {len(df)} demo log entries "
              f"(~{len(df)-8} normal activity, 8 suspicious events)")
        return df

    # ------------------------------------------------------------------
    # Save
    # ------------------------------------------------------------------

    def save_logs(self, df):
        os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
        df.to_csv(self.output_path, index=False)
        print(f"[OK] Logs saved -> {self.output_path}  ({len(df)} rows)")

    # ------------------------------------------------------------------
    # Main runner
    # ------------------------------------------------------------------

    def read_logs(self):
        if WINDOWS_AVAILABLE:
            return self.read_windows_logs()
        else:
            return self.generate_demo_logs()

    def run(self):
        df = self.read_logs()
        if df.empty:
            print("[WARNING] No logs collected.")
            return df
        self.save_logs(df)
        return df


# ------------------------------------------------------------------
# Message builder
# ------------------------------------------------------------------

def _build_message(event_id, user, ip, computer):
    templates = {
        4624: (
            f"An account was successfully logged on.\n"
            f"Account Name: {user}\n"
            f"Source Network Address: {ip}\n"
            f"Workstation Name: {computer}\n"
            f"Logon Type: 2"
        ),
        4625: (
            f"An account failed to log on.\n"
            f"Account Name: {user}\n"
            f"Source Network Address: {ip}\n"
            f"Failure Reason: Unknown user name or bad password\n"
            f"Logon Type: 2"
        ),
        4634: (
            f"An account was logged off.\n"
            f"Account Name: {user}\n"
            f"Logon Type: 2"
        ),
        4672: (
            f"Special privileges assigned to new logon.\n"
            f"Account Name: {user}\n"
            f"Privileges: SeChangeNotifyPrivilege SeImpersonatePrivilege"
        ),
        4688: (
            f"A new process has been created.\n"
            f"Account Name: {user}\n"
            f"Process Name: C:\\Windows\\System32\\svchost.exe\n"
            f"Creator Process Name: C:\\Windows\\System32\\services.exe"
        ),
        4720: (
            f"A user account was created.\n"
            f"New Account Name: {user}_temp\n"
            f"Subject Account Name: {user}"
        ),
        4740: (
            f"A user account was locked out.\n"
            f"Account Name: {user}\n"
            f"Caller Computer Name: {computer}"
        ),
        4648: (
            f"A logon was attempted using explicit credentials.\n"
            f"Account Name: {user}\n"
            f"Target Server Name: {computer}\n"
            f"Network Address: {ip}"
        ),
        4663: (
            f"An attempt was made to access an object.\n"
            f"Account Name: {user}\n"
            f"Object Name: C:\\Users\\{user}\\Documents\\report.xlsx\n"
            f"Accesses: ReadData"
        ),
        5140: (
            f"A network share object was accessed.\n"
            f"Account Name: {user}\n"
            f"Share Name: \\\\{computer}\\SharedDocs\n"
            f"Source Address: {ip}"
        ),
    }
    return templates.get(
        event_id,
        f"System event {event_id} on {computer} by {user}"
    )


# ------------------------------------------------------------------
# Minimal realistic attack injection
# ------------------------------------------------------------------

def _inject_minimal_attacks(logs, base, attacker, attack_ip):
    """
    Inject only 1 realistic attack sequence.
    8 suspicious events out of ~2000 = realistic 0.4% anomaly rate.

    What we inject:
    - 6 failed logins from external IP  → triggers brute force rule
    - 1 successful login after          → triggers brute force success rule
    - 1 privilege escalation            → triggers privilege escalation rule

    This gives the teacher a clear demonstration without
    flooding the dashboard with fake critical alerts.
    """
    from datetime import timedelta

    # Attack happened yesterday at 11 PM
    t = base - timedelta(days=1)
    t = t.replace(hour=23, minute=5, second=0)

    # 6 failed logins from external IP
    for i in range(6):
        logs.append({
            "timestamp":  (t + timedelta(seconds=i * 20)).strftime("%Y-%m-%d %H:%M:%S"),
            "source":     "Security",
            "event_id":   4625,
            "event_type": 2,
            "computer":   "SERVER-01",
            "message": (
                f"An account failed to log on.\n"
                f"Account Name: {attacker}\n"
                f"Source Network Address: {attack_ip}\n"
                f"Failure Reason: Wrong password\n"
                f"Logon Type: 3"
            ),
        })

    # Successful login after failures
    logs.append({
        "timestamp":  (t + timedelta(seconds=140)).strftime("%Y-%m-%d %H:%M:%S"),
        "source":     "Security",
        "event_id":   4624,
        "event_type": 1,
        "computer":   "SERVER-01",
        "message": (
            f"An account was successfully logged on.\n"
            f"Account Name: {attacker}\n"
            f"Source Network Address: {attack_ip}\n"
            f"Logon Type: 3"
        ),
    })

    # Privilege escalation after login
    logs.append({
        "timestamp":  (t + timedelta(seconds=180)).strftime("%Y-%m-%d %H:%M:%S"),
        "source":     "Security",
        "event_id":   4672,
        "event_type": 3,
        "computer":   "SERVER-01",
        "message": (
            f"Special privileges assigned to new logon.\n"
            f"Account Name: {attacker}\n"
            f"Privileges: SeDebugPrivilege SeTcbPrivilege SeBackupPrivilege\n"
            f"Source Network Address: {attack_ip}"
        ),
    })

    return logs


if __name__ == "__main__":
    collector = WindowsLogCollector()
    collector.run()
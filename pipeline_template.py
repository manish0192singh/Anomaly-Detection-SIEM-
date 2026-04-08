"""
AI SIEM — Personal Pipeline
=============================
This file was generated specifically for your machine.
Just run it — it will:
  1. Collect your Windows Event Logs
  2. Detect anomalies using AI
  3. Generate security alerts
  4. Upload your data to your personal dashboard
  5. Open your dashboard in the browser

Requirements (install once):
    pip install pandas scikit-learn joblib requests pywin32
"""

import os
import sys
import json
import platform
import socket
import subprocess
import webbrowser
import requests
import re
import random
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

# ── Personal config (baked in at download time) ───────────────────────
# These values are baked in when you download the file
# OR read from environment variables when running as .exe
USER_ID        = os.getenv("SIEM_USER_ID",       "__USER_ID_PLACEHOLDER__")
SERVER_URL     = os.getenv("SIEM_SERVER_URL",     "__SERVER_URL_PLACEHOLDER__")
DASHBOARD_BASE = os.getenv("SIEM_DASHBOARD_URL",  "__DASHBOARD_URL_PLACEHOLDER__")
MACHINE        = socket.gethostname()

# ── Local working directory ───────────────────────────────────────────
WORK_DIR   = Path.home() / ".ai_siem" / USER_ID
DATA_DIR   = WORK_DIR / "data"
MODELS_DIR = DATA_DIR / "models"
DATA_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)

DASHBOARD_URL = f"{DASHBOARD_BASE}/?user_id={USER_ID}"


def banner():
    print("\n" + "="*55)
    print("   AI SIEM — Personal Security Pipeline")
    print("="*55)
    print(f"   Machine  : {MACHINE}")
    print(f"   User ID  : {USER_ID}")
    print(f"   Dashboard: {DASHBOARD_URL}")
    print("="*55 + "\n")


# ══════════════════════════════════════════════════════════════════════
# STEP 1 — Collect Logs
# ══════════════════════════════════════════════════════════════════════

def collect_logs():
    print("[1/5] Collecting Windows Event Logs...")
    import pandas as pd

    windows_ok = False
    if platform.system() == "Windows":
        try:
            import win32evtlog, win32evtlogutil
            windows_ok = True
        except ImportError:
            print("      pywin32 not found — using demo data")

    if windows_ok:
        logs = _real_logs()
    else:
        logs = _demo_logs()

    df = pd.DataFrame(logs).sort_values("timestamp").reset_index(drop=True)
    df.to_csv(DATA_DIR / "processed_logs.csv", index=False)
    print(f"      Collected {len(df)} log entries ✓")
    return df


def _real_logs():
    import win32evtlog, win32evtlogutil
    logs = []
    for channel in ["Security", "System", "Application"]:
        try:
            handle = win32evtlog.OpenEventLog(None, channel)
            flags  = (win32evtlog.EVENTLOG_BACKWARDS_READ |
                      win32evtlog.EVENTLOG_SEQUENTIAL_READ)
            count  = 0
            while count < 2000:
                events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not events: break
                for event in events:
                    if count >= 2000: break
                    try:    msg = win32evtlogutil.SafeFormatMessage(event, channel)
                    except: msg = f"Event {event.EventID & 0xFFFF}"
                    logs.append({
                        "timestamp":  str(event.TimeGenerated),
                        "source":     channel,
                        "event_id":   event.EventID & 0xFFFF,
                        "event_type": event.EventType,
                        "computer":   event.ComputerName,
                        "message":    str(msg).strip()[:500],
                    })
                    count += 1
            win32evtlog.CloseEventLog(handle)
        except Exception as e:
            print(f"      Warning: {channel}: {e}")
    return logs


def _demo_logs():
    random.seed(42)
    users     = ["john.smith","sarah.jones","mike.brown","lisa.white","svc_backup"]
    computers = ["DESKTOP-001","LAPTOP-HR","SERVER-01","WORKSTATION-02"]
    ips       = ["192.168.1.101","192.168.1.102","192.168.1.103","192.168.1.10"]
    profiles  = [(4624,1),(4634,1),(4688,1),(4663,1),(4625,2),(4648,2),(4672,3),(4740,3)]
    weights   = [35,25,15,10,6,4,3,2]
    logs, base= [], datetime.now()
    for _ in range(2000):
        hour = random.randint(8,18) if random.random()<0.85 \
               else random.choice(list(range(0,8))+list(range(19,24)))
        ts   = (base-timedelta(days=random.randint(0,6))).replace(
                    hour=hour, minute=random.randint(0,59), second=random.randint(0,59))
        eid,etype = random.choices(profiles, weights=weights, k=1)[0]
        u,c,ip    = random.choice(users),random.choice(computers),random.choice(ips)
        logs.append({"timestamp":ts.strftime("%Y-%m-%d %H:%M:%S"),
            "source":"Security" if eid in [4624,4625,4634,4672,4740,4648] else "System",
            "event_id":eid,"event_type":etype,"computer":c,
            "message":_msg(eid,u,ip,c)})
    # 1 small attack
    t = (base-timedelta(days=1)).replace(hour=23,minute=5,second=0)
    for i in range(6):
        logs.append({"timestamp":(t+timedelta(seconds=i*20)).strftime("%Y-%m-%d %H:%M:%S"),
            "source":"Security","event_id":4625,"event_type":2,"computer":"SERVER-01",
            "message":f"An account failed to log on.\nAccount Name: {users[0]}\n"
                      f"Source Network Address: 203.0.113.45\nFailure Reason: Wrong password"})
    logs.append({"timestamp":(t+timedelta(seconds=140)).strftime("%Y-%m-%d %H:%M:%S"),
        "source":"Security","event_id":4624,"event_type":1,"computer":"SERVER-01",
        "message":f"An account was successfully logged on.\nAccount Name: {users[0]}\n"
                  f"Source Network Address: 203.0.113.45"})
    logs.append({"timestamp":(t+timedelta(seconds=180)).strftime("%Y-%m-%d %H:%M:%S"),
        "source":"Security","event_id":4672,"event_type":3,"computer":"SERVER-01",
        "message":f"Special privileges assigned.\nAccount Name: {users[0]}\n"
                  f"Privileges: SeDebugPrivilege SeTcbPrivilege\n"
                  f"Source Network Address: 203.0.113.45"})
    return logs


def _msg(eid, user, ip, computer):
    t = {
        4624: f"An account was successfully logged on.\nAccount Name: {user}\nSource Network Address: {ip}\nWorkstation Name: {computer}",
        4625: f"An account failed to log on.\nAccount Name: {user}\nSource Network Address: {ip}\nFailure Reason: Wrong password",
        4634: f"An account was logged off.\nAccount Name: {user}\nLogon Type: 2",
        4672: f"Special privileges assigned.\nAccount Name: {user}\nPrivileges: SeChangeNotifyPrivilege",
        4688: f"A new process has been created.\nAccount Name: {user}\nProcess Name: C:\\Windows\\System32\\svchost.exe",
        4663: f"An attempt was made to access an object.\nAccount Name: {user}\nObject Name: C:\\Users\\{user}\\Documents\\report.xlsx",
        4648: f"Explicit credential logon.\nAccount Name: {user}\nTarget Server: {computer}\nNetwork Address: {ip}",
        4740: f"A user account was locked out.\nAccount Name: {user}\nCaller Computer: {computer}",
    }
    return t.get(eid, f"System event {eid} on {computer} by {user}")


# ══════════════════════════════════════════════════════════════════════
# STEP 2 — Preprocess
# ══════════════════════════════════════════════════════════════════════

def preprocess():
    print("[2/5] Preprocessing logs...")
    import pandas as pd

    df = pd.read_csv(DATA_DIR / "processed_logs.csv")
    df["message"]   = df["message"].astype(str)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    df["username"]         = df["message"].apply(_extract_username)
    df["ip_address"]       = df["message"].apply(_extract_ip)
    df["event_type_clean"] = df["event_id"].apply(_extract_event_type)
    df["hour"]             = df["timestamp"].dt.hour
    df["day_of_week"]      = df["timestamp"].dt.dayofweek
    df["is_night"]         = df["hour"].apply(lambda h: int(h>=22 or h<=5))
    df["is_weekend"]       = df["day_of_week"].isin([5,6]).astype(int)

    df.to_csv(DATA_DIR / "structured_logs.csv", index=False)
    print(f"      Structured {len(df)} log entries ✓")
    return df


def _extract_username(msg):
    for pat in [r'Account Name:\s*([A-Za-z0-9_\\$\-\.]+)',
                r'user(?:name)?\s*[:=]\s*([A-Za-z0-9_\\$\-\.]+)']:
        m = re.search(pat, str(msg), re.IGNORECASE)
        if m and m.group(1) not in ("-","$",""):
            return m.group(1)
    return "Unknown"


def _extract_ip(msg):
    m = re.search(r"(\d{1,3}\.){3}\d{1,3}", str(msg))
    if m:
        ip = m.group(0)
        if not ip.startswith("127.") and ip != "0.0.0.0":
            return ip
    return None


def _extract_event_type(eid):
    mapping = {
        4624:"Successful Login", 4625:"Failed Login",
        4634:"Logout",           4647:"Logout",
        4672:"Privilege Escalation", 4673:"Privilege Escalation",
        4688:"Process Created",  4720:"User Account Created",
        4740:"Account Locked Out", 4663:"File Access",
        4698:"Scheduled Task Created", 7045:"New Service Installed",
    }
    try: return mapping.get(int(eid), "Other")
    except: return "Other"


# ══════════════════════════════════════════════════════════════════════
# STEP 3 — Detect Anomalies
# ══════════════════════════════════════════════════════════════════════

def detect_anomalies():
    print("[3/5] Running AI anomaly detection...")
    import pandas as pd
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib

    df = pd.read_csv(DATA_DIR / "structured_logs.csv")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    feature_cols = ["hour","day_of_week","is_night","is_weekend"]
    df_feat = df[feature_cols].fillna(0)

    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(df_feat)

    model_path = MODELS_DIR / "iso_forest.pkl"
    if model_path.exists():
        model = joblib.load(model_path)
    else:
        model = IsolationForest(n_estimators=200, contamination=0.01,
                                random_state=42, n_jobs=-1)
        model.fit(X_scaled)
        joblib.dump(model, model_path)

    df["anomaly"] = model.predict(X_scaled)
    raw = model.score_samples(X_scaled)
    mn,mx = raw.min(), raw.max()
    df["risk_score"] = ((raw-mx)/(mn-mx+1e-9)*100).round(2)

    LOW_RISK  = {"Successful Login","Logout","File Access"}
    HIGH_RISK = {"Privilege Escalation","Process Created","Scheduled Task Created",
                 "New Service Installed","User Account Created","Account Locked Out"}

    def severity(row):
        if row["anomaly"] != -1: return "Normal"
        s, et = row["risk_score"], row.get("event_type_clean","Other")
        if et in LOW_RISK:
            return "High" if s>=90 else "Medium" if s>=70 else "Low"
        if et in HIGH_RISK:
            return "Critical" if s>=70 else "High" if s>=45 else "Medium"
        return "Critical" if s>=85 else "High" if s>=60 else "Medium" if s>=35 else "Low"

    df["severity"] = df.apply(severity, axis=1)
    df.to_csv(DATA_DIR / "anomalies.csv", index=False)

    anom_count = (df["anomaly"] == -1).sum()
    print(f"      Detected {anom_count} anomalies ✓")
    return df


# ══════════════════════════════════════════════════════════════════════
# STEP 4 — Generate Alerts
# ══════════════════════════════════════════════════════════════════════

def generate_alerts():
    print("[4/5] Generating security alerts...")
    import pandas as pd

    df      = pd.read_csv(DATA_DIR / "structured_logs.csv")
    anom_df = pd.read_csv(DATA_DIR / "anomalies.csv")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    alerts = []
    seen   = set()

    SEV_SCORE = {"Critical":4,"High":3,"Medium":2,"Low":1}
    MITRE = {
        "Failed Login Burst":       "T1110 – Brute Force",
        "Brute Force Success":      "T1110 – Brute Force",
        "Privilege Escalation":     "T1068 – Privilege Escalation",
        "Odd Hour Login":           "T1078 – Valid Accounts",
        "ML Anomaly Detected":      "T1499 – Endpoint DoS",
        "Suspicious Keyword":       "T1059 – Command & Scripting",
        "Account Locked Out":       "T1110 – Brute Force",
    }

    def add_alert(atype, msg, sev, user="N/A", ip=None, ts=None, src="rule", risk=None):
        h = hashlib.md5(f"{atype}{msg}{user}".encode()).hexdigest()[:12]
        if h in seen: return
        seen.add(h)
        alerts.append({
            "id": h, "timestamp": str(ts or datetime.now()),
            "type": atype, "message": msg, "severity": sev,
            "severity_score": SEV_SCORE.get(sev,0),
            "username": user, "ip_address": ip or "N/A",
            "risk_score": risk, "source": src,
            "mitre_tactic": MITRE.get(atype,"Unknown"),
        })

    # Rule 1 — Failed login burst
    if "event_type_clean" in df.columns:
        failed = df[df["event_type_clean"]=="Failed Login"]
        for user, count in failed.groupby("username").size().items():
            if count >= 8:
                add_alert("Failed Login Burst",
                    f"{count} failed logins for '{user}'", "High", user, count=count)

    # Rule 2 — Brute force success
    for user in df["username"].unique():
        u = df[df["username"]==user]
        f = u[u["event_type_clean"]=="Failed Login"]
        s = u[u["event_type_clean"]=="Successful Login"]
        if len(f)>=3 and len(s)>=1:
            if pd.notna(f["timestamp"].max()) and pd.notna(s["timestamp"].min()):
                if s["timestamp"].min() > f["timestamp"].max():
                    add_alert("Brute Force Success",
                        f"'{user}' had {len(f)} failures then logged in.",
                        "Critical", user)

    # Rule 3 — Privilege escalation
    failed_users = set(df[df["event_type_clean"]=="Failed Login"]["username"])
    for _,row in df[df["event_type_clean"]=="Privilege Escalation"].iterrows():
        ip = str(row.get("ip_address",""))
        if row["username"] in failed_users or ip.startswith("203."):
            add_alert("Privilege Escalation",
                f"Privilege escalation for '{row['username']}'.",
                "Critical", row["username"], ip, row["timestamp"])

    # Rule 4 — Odd hour logins
    for _,row in df[df["event_type_clean"]=="Successful Login"].iterrows():
        try:
            if 0 <= pd.to_datetime(row["timestamp"]).hour <= 5:
                add_alert("Odd Hour Login",
                    f"Login 12AM–5AM by '{row['username']}'.",
                    "Medium", row["username"], row.get("ip_address"), row["timestamp"])
        except: pass

    # ML anomalies
    for _,row in anom_df[anom_df["anomaly"]==-1].iterrows():
        sev = row.get("severity","Medium")
        add_alert("ML Anomaly Detected",
            str(row.get("message","Suspicious log"))[:150],
            sev if sev!="Normal" else "Medium",
            str(row.get("username","Unknown")),
            row.get("ip_address"), row.get("timestamp"),
            src="ml", risk=row.get("risk_score"))

    alerts.sort(key=lambda x: x["severity_score"], reverse=True)

    with open(DATA_DIR / "final_alerts.json","w") as f:
        json.dump(alerts, f, indent=2, default=str)

    print(f"      Generated {len(alerts)} alerts ✓")
    return alerts


# ══════════════════════════════════════════════════════════════════════
# STEP 5 — Upload to dashboard
# ══════════════════════════════════════════════════════════════════════

def upload_to_dashboard(logs_df, anom_df, alerts):
    print("[5/5] Uploading data to your dashboard...")

    import pandas as pd
    import math

    def clean_value(v):
        if v is None:
            return None
        if hasattr(v, 'isoformat'):
            return str(v)
        if hasattr(v, 'item'):
            return v.item()
        try:
            if isinstance(v, float) and math.isnan(v):
                return None
        except Exception:
            pass
        return v

    def df_to_list(df, cols):
        df = df.copy()
        for c in cols:
            if c not in df.columns:
                df[c] = None
        for c in df.columns:
            if 'datetime' in str(df[c].dtype):
                df[c] = df[c].astype(str).replace('NaT', None)
        rows = df[cols].to_dict("records")
        return [{k: clean_value(v) for k, v in row.items()} for row in rows]

    def clean_alerts(alerts_list):
        return [{k: clean_value(v) for k, v in alert.items()} for alert in alerts_list]

    log_cols  = ["timestamp","source","event_id","event_type","computer",
                 "message","username","ip_address","event_type_clean",
                 "hour","is_night","is_weekend"]
    anom_cols = ["timestamp","username","ip_address","event_type_clean",
                 "anomaly","risk_score","severity","message"]

    payload = {
        "user_id":   USER_ID,
        "machine":   MACHINE,
        "logs":      df_to_list(logs_df, log_cols),
        "anomalies": df_to_list(anom_df, anom_cols),
        "alerts":    clean_alerts(alerts),
    }

    try:
        json.dumps(payload)
    except Exception as e:
        print(f"      Data formatting error: {e}")
        return

    try:
        r = requests.post(
            f"{SERVER_URL}/upload",
            json=payload,
            timeout=120,
            headers={"Content-Type": "application/json"}
        )
        if r.status_code == 200:
            print(f"      Upload successful ✓")
            print(f"\n{'='*55}")
            print(f"  ✅ Your dashboard is ready!")
            print(f"  🌐 {DASHBOARD_URL}")
            print(f"{'='*55}\n")
            webbrowser.open(DASHBOARD_URL)
        else:
            print(f"      Upload failed: {r.status_code} — {r.text[:200]}")
    except Exception as e:
        print(f"      Could not reach server: {e}")


if __name__ == "__main__":
    banner()
    try:
        logs_df  = collect_logs()
        logs_df  = preprocess()
        anom_df  = detect_anomalies()
        alerts   = generate_alerts()
        upload_to_dashboard(logs_df, anom_df, alerts)
    except KeyboardInterrupt:
        print("\n[Stopped by user]")
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
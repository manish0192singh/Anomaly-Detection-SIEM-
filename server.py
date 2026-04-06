from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import sqlite3
import uuid
import os
from datetime import datetime
from pathlib import Path

app = FastAPI(title="AI SIEM Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR      = Path(__file__).parent
DB_PATH       = BASE_DIR / "siem.db"
DOWNLOADS_DIR = BASE_DIR / "downloads"
DOWNLOADS_DIR.mkdir(exist_ok=True)

STREAMLIT_URL = os.getenv("STREAMLIT_URL", "http://localhost:8501")
RENDER_URL    = os.getenv("RENDER_EXTERNAL_URL", "http://localhost:8000")

# ── Database ──────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY, created_at TEXT,
        last_seen TEXT, machine TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT, timestamp TEXT, source TEXT,
        event_id INTEGER, event_type INTEGER, computer TEXT,
        message TEXT, username TEXT, ip_address TEXT,
        event_type_clean TEXT, hour INTEGER,
        is_night INTEGER, is_weekend INTEGER, uploaded_at TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS anomalies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT, timestamp TEXT, username TEXT,
        ip_address TEXT, event_type_clean TEXT, anomaly INTEGER,
        risk_score REAL, severity TEXT, message TEXT, uploaded_at TEXT)""")
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT, alert_id TEXT, timestamp TEXT, type TEXT,
        message TEXT, severity TEXT, severity_score INTEGER,
        username TEXT, ip_address TEXT, risk_score REAL,
        source TEXT, mitre_tactic TEXT, uploaded_at TEXT)""")
    conn.commit()
    conn.close()

init_db()

# ── Pydantic Models (v1 compatible) ───────────────────────────────────
class LogEntry(BaseModel):
    timestamp:        Optional[str]   = None
    source:           Optional[str]   = None
    event_id:         Optional[int]   = None
    event_type:       Optional[int]   = None
    computer:         Optional[str]   = None
    message:          Optional[str]   = None
    username:         Optional[str]   = None
    ip_address:       Optional[str]   = None
    event_type_clean: Optional[str]   = None
    hour:             Optional[int]   = None
    is_night:         Optional[int]   = None
    is_weekend:       Optional[int]   = None

    class Config:
        extra = "allow"

class AnomalyEntry(BaseModel):
    timestamp:        Optional[str]   = None
    username:         Optional[str]   = None
    ip_address:       Optional[str]   = None
    event_type_clean: Optional[str]   = None
    anomaly:          Optional[int]   = None
    risk_score:       Optional[float] = None
    severity:         Optional[str]   = None
    message:          Optional[str]   = None

    class Config:
        extra = "allow"

class AlertEntry(BaseModel):
    id:            Optional[str]   = None
    timestamp:     Optional[str]   = None
    type:          Optional[str]   = None
    message:       Optional[str]   = None
    severity:      Optional[str]   = None
    severity_score:Optional[int]   = None
    username:      Optional[str]   = None
    ip_address:    Optional[str]   = None
    risk_score:    Optional[float] = None
    source:        Optional[str]   = None
    mitre_tactic:  Optional[str]   = None

    class Config:
        extra = "allow"

class UploadPayload(BaseModel):
    user_id:   str
    machine:   str
    logs:      List[LogEntry]     = []
    anomalies: List[AnomalyEntry] = []
    alerts:    List[AlertEntry]   = []

    class Config:
        extra = "allow"

# ── Routes ────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "service": "AI SIEM Server",
        "status":  "running",
        "time":    datetime.now().isoformat()
    }

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/register")
def register(machine: str = "unknown"):
    user_id = str(uuid.uuid4()).replace("-", "")[:12]
    now     = datetime.now().isoformat()
    conn    = get_db()
    conn.execute(
        "INSERT OR IGNORE INTO users VALUES (?,?,?,?)",
        (user_id, now, now, machine)
    )
    conn.commit()
    conn.close()
    return {
        "user_id":      user_id,
        "download_url": f"{RENDER_URL}/download/{user_id}",
        "dashboard_url":f"{STREAMLIT_URL}/?user_id={user_id}",
        "message":      "Run the downloaded file on your Windows PC"
    }

@app.get("/download/{user_id}")
def download(user_id: str):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE user_id=?", (user_id,)
    ).fetchone()
    conn.close()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    template_path = BASE_DIR / "pipeline_template.py"
    if not template_path.exists():
        raise HTTPException(status_code=500, detail="Template not found")
    content = template_path.read_text()
    content = content.replace("__USER_ID_PLACEHOLDER__", user_id)
    content = content.replace("__SERVER_URL_PLACEHOLDER__", RENDER_URL)
    content = content.replace("__DASHBOARD_URL_PLACEHOLDER__", STREAMLIT_URL)
    out_path = DOWNLOADS_DIR / f"pipeline_{user_id}.py"
    out_path.write_text(content)
    return FileResponse(
        path=str(out_path),
        filename="run_pipeline.py",
        media_type="text/x-python"
    )

@app.post("/upload")
def upload(payload: UploadPayload):
    now  = datetime.now().isoformat()
    uid  = payload.user_id
    conn = get_db()
    conn.execute(
        "UPDATE users SET last_seen=?, machine=? WHERE user_id=?",
        (now, payload.machine, uid)
    )
    conn.execute("DELETE FROM logs      WHERE user_id=?", (uid,))
    conn.execute("DELETE FROM anomalies WHERE user_id=?", (uid,))
    conn.execute("DELETE FROM alerts    WHERE user_id=?", (uid,))

    for log in payload.logs:
        conn.execute("""INSERT INTO logs (user_id,timestamp,source,event_id,
            event_type,computer,message,username,ip_address,event_type_clean,
            hour,is_night,is_weekend,uploaded_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (uid, log.timestamp, log.source, log.event_id, log.event_type,
             log.computer, log.message, log.username, log.ip_address,
             log.event_type_clean, log.hour, log.is_night, log.is_weekend, now))

    for a in payload.anomalies:
        conn.execute("""INSERT INTO anomalies (user_id,timestamp,username,
            ip_address,event_type_clean,anomaly,risk_score,severity,
            message,uploaded_at) VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (uid, a.timestamp, a.username, a.ip_address, a.event_type_clean,
             a.anomaly, a.risk_score, a.severity, a.message, now))

    for al in payload.alerts:
        conn.execute("""INSERT INTO alerts (user_id,alert_id,timestamp,type,
            message,severity,severity_score,username,ip_address,risk_score,
            source,mitre_tactic,uploaded_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (uid, al.id, al.timestamp, al.type, al.message, al.severity,
             al.severity_score, al.username, al.ip_address, al.risk_score,
             al.source, al.mitre_tactic, now))

    conn.commit()
    conn.close()
    return {
        "status":    "ok",
        "user_id":   uid,
        "logs":      len(payload.logs),
        "anomalies": len(payload.anomalies),
        "alerts":    len(payload.alerts)
    }

@app.get("/data/{user_id}/stats")
def get_stats(user_id: str):
    conn  = get_db()
    logs  = conn.execute("SELECT COUNT(*) FROM logs WHERE user_id=?",
                         (user_id,)).fetchone()[0]
    anom  = conn.execute(
        "SELECT COUNT(*) FROM anomalies WHERE user_id=? AND anomaly=-1",
        (user_id,)).fetchone()[0]
    alrts = conn.execute("SELECT COUNT(*) FROM alerts WHERE user_id=?",
                         (user_id,)).fetchone()[0]
    crit  = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE user_id=? AND severity='Critical'",
        (user_id,)).fetchone()[0]
    user  = conn.execute(
        "SELECT last_seen, machine FROM users WHERE user_id=?",
        (user_id,)).fetchone()
    conn.close()
    return {
        "user_id":    user_id,
        "total_logs": logs,
        "anomalies":  anom,
        "alerts":     alrts,
        "critical":   crit,
        "last_seen":  user[0] if user else None,
        "machine":    user[1] if user else None,
    }

@app.get("/data/{user_id}/logs")
def get_logs(user_id: str, limit: int = 5000):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM logs WHERE user_id=? ORDER BY timestamp DESC LIMIT ?",
        (user_id, limit)).fetchall()
    conn.close()
    return {"logs": [dict(r) for r in rows], "count": len(rows)}

@app.get("/data/{user_id}/anomalies")
def get_anomalies(user_id: str):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM anomalies WHERE user_id=? ORDER BY risk_score DESC",
        (user_id,)).fetchall()
    conn.close()
    return {"anomalies": [dict(r) for r in rows], "count": len(rows)}

@app.get("/data/{user_id}/alerts")
def get_alerts(user_id: str):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM alerts WHERE user_id=? ORDER BY severity_score DESC",
        (user_id,)).fetchall()
    conn.close()
    return {"alerts": [dict(r) for r in rows], "count": len(rows)}

@app.get("/view/{user_id}")
def view(user_id: str):
    url = f"{STREAMLIT_URL}/?user_id={user_id}"
    return HTMLResponse(
        f"<html><head>"
        f"<meta http-equiv='refresh' content='0; url={url}'>"
        f"</head><body><a href='{url}'>Click here</a></body></html>"
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
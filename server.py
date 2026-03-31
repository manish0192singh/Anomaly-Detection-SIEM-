"""
AI SIEM — Central Server
=========================
Runs on Render. Handles:
- Generating unique user IDs
- Receiving uploaded log/anomaly/alert data from users
- Serving personalized run_pipeline.py downloads
- Serving the Streamlit dashboard with per-user data
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import sqlite3
import uuid
import json
import os
import hashlib
from datetime import datetime
from pathlib import Path

app = FastAPI(title="AI SIEM Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Paths ─────────────────────────────────────────────────────────────
BASE_DIR      = Path(__file__).parent
DB_PATH       = BASE_DIR / "data" / "siem.db"
DOWNLOADS_DIR = BASE_DIR / "downloads"
BASE_DIR.mkdir(exist_ok=True)
(BASE_DIR / "data").mkdir(exist_ok=True)
DOWNLOADS_DIR.mkdir(exist_ok=True)


# ── Database setup ────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    c    = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id    TEXT PRIMARY KEY,
            created_at TEXT,
            last_seen  TEXT,
            machine    TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    TEXT,
            timestamp  TEXT,
            source     TEXT,
            event_id   INTEGER,
            event_type INTEGER,
            computer   TEXT,
            message    TEXT,
            username   TEXT,
            ip_address TEXT,
            event_type_clean TEXT,
            hour       INTEGER,
            is_night   INTEGER,
            is_weekend INTEGER,
            uploaded_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS anomalies (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    TEXT,
            timestamp  TEXT,
            username   TEXT,
            ip_address TEXT,
            event_type_clean TEXT,
            anomaly    INTEGER,
            risk_score REAL,
            severity   TEXT,
            message    TEXT,
            uploaded_at TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      TEXT,
            alert_id     TEXT,
            timestamp    TEXT,
            type         TEXT,
            message      TEXT,
            severity     TEXT,
            severity_score INTEGER,
            username     TEXT,
            ip_address   TEXT,
            risk_score   REAL,
            source       TEXT,
            mitre_tactic TEXT,
            uploaded_at  TEXT
        )
    """)

    conn.commit()
    conn.close()
    print("[OK] Database initialised")


init_db()


# ── Models ────────────────────────────────────────────────────────────

class LogEntry(BaseModel):
    timestamp:        Optional[str] = None
    source:           Optional[str] = None
    event_id:         Optional[int] = None
    event_type:       Optional[int] = None
    computer:         Optional[str] = None
    message:          Optional[str] = None
    username:         Optional[str] = None
    ip_address:       Optional[str] = None
    event_type_clean: Optional[str] = None
    hour:             Optional[int] = None
    is_night:         Optional[int] = None
    is_weekend:       Optional[int] = None


class AnomalyEntry(BaseModel):
    timestamp:        Optional[str] = None
    username:         Optional[str] = None
    ip_address:       Optional[str] = None
    event_type_clean: Optional[str] = None
    anomaly:          Optional[int] = None
    risk_score:       Optional[float] = None
    severity:         Optional[str] = None
    message:          Optional[str] = None


class AlertEntry(BaseModel):
    id:            Optional[str] = None
    timestamp:     Optional[str] = None
    type:          Optional[str] = None
    message:       Optional[str] = None
    severity:      Optional[str] = None
    severity_score:Optional[int] = None
    username:      Optional[str] = None
    ip_address:    Optional[str] = None
    risk_score:    Optional[float] = None
    source:        Optional[str] = None
    mitre_tactic:  Optional[str] = None


class UploadPayload(BaseModel):
    user_id:   str
    machine:   str
    logs:      List[LogEntry]      = []
    anomalies: List[AnomalyEntry]  = []
    alerts:    List[AlertEntry]    = []


# ── Endpoints ─────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
def root():
    return {
        "service": "AI SIEM Server",
        "status":  "running",
        "time":    datetime.now().isoformat(),
    }


@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok"}


# ── Generate unique user ID + personalised download ───────────────────

@app.get("/register", tags=["User"])
def register_user(machine: str = "unknown"):
    """
    Called when user clicks 'Get My Agent' on the dashboard.
    Returns a unique user_id and their personalised download URL.
    """
    user_id = str(uuid.uuid4())[:12].replace("-", "")

    conn = get_db()
    conn.execute(
        "INSERT OR IGNORE INTO users VALUES (?,?,?,?)",
        (user_id, datetime.now().isoformat(), datetime.now().isoformat(), machine)
    )
    conn.commit()
    conn.close()

    server_url = os.getenv("RENDER_EXTERNAL_URL", "http://localhost:8000")

    return {
        "user_id":      user_id,
        "download_url": f"{server_url}/download/{user_id}",
        "dashboard_url": f"{server_url}/view/{user_id}",
        "message":      "Run the downloaded file on your Windows PC",
    }


@app.get("/download/{user_id}", tags=["User"])
def download_pipeline(user_id: str):
    """
    Serves a personalised run_pipeline.py with the user's ID baked in.
    """
    # Verify user exists
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE user_id=?", (user_id,)
    ).fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=404, detail="User ID not found")

    server_url = os.getenv("RENDER_EXTERNAL_URL", "http://localhost:8000")

    # Read the pipeline template and inject user ID + server URL
    template_path = BASE_DIR / "pipeline_template.py"
    if not template_path.exists():
        raise HTTPException(status_code=500, detail="Pipeline template not found")

    template = template_path.read_text()
    personalised = template.replace(
        "__USER_ID_PLACEHOLDER__", user_id
    ).replace(
        "__SERVER_URL_PLACEHOLDER__", server_url
    )

    # Save personalised file temporarily
    out_path = DOWNLOADS_DIR / f"run_pipeline_{user_id}.py"
    out_path.write_text(personalised)

    return FileResponse(
        path=str(out_path),
        filename="run_pipeline.py",
        media_type="text/x-python"
    )


# ── Receive uploaded data from user's pipeline ────────────────────────

@app.post("/upload", tags=["Data"])
def upload_data(payload: UploadPayload):
    """
    Receives logs, anomalies, and alerts from a user's run_pipeline.py
    """
    user_id = payload.user_id
    now     = datetime.now().isoformat()

    conn = get_db()

    # Update last seen
    conn.execute(
        "UPDATE users SET last_seen=?, machine=? WHERE user_id=?",
        (now, payload.machine, user_id)
    )

    # Clear old data for this user (replace with fresh run)
    conn.execute("DELETE FROM logs      WHERE user_id=?", (user_id,))
    conn.execute("DELETE FROM anomalies WHERE user_id=?", (user_id,))
    conn.execute("DELETE FROM alerts    WHERE user_id=?", (user_id,))

    # Insert logs
    for log in payload.logs:
        conn.execute("""
            INSERT INTO logs
            (user_id,timestamp,source,event_id,event_type,computer,message,
             username,ip_address,event_type_clean,hour,is_night,is_weekend,uploaded_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (user_id, log.timestamp, log.source, log.event_id, log.event_type,
              log.computer, log.message, log.username, log.ip_address,
              log.event_type_clean, log.hour, log.is_night, log.is_weekend, now))

    # Insert anomalies
    for a in payload.anomalies:
        conn.execute("""
            INSERT INTO anomalies
            (user_id,timestamp,username,ip_address,event_type_clean,
             anomaly,risk_score,severity,message,uploaded_at)
            VALUES (?,?,?,?,?,?,?,?,?,?)
        """, (user_id, a.timestamp, a.username, a.ip_address,
              a.event_type_clean, a.anomaly, a.risk_score,
              a.severity, a.message, now))

    # Insert alerts
    for al in payload.alerts:
        conn.execute("""
            INSERT INTO alerts
            (user_id,alert_id,timestamp,type,message,severity,severity_score,
             username,ip_address,risk_score,source,mitre_tactic,uploaded_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (user_id, al.id, al.timestamp, al.type, al.message,
              al.severity, al.severity_score, al.username, al.ip_address,
              al.risk_score, al.source, al.mitre_tactic, now))

    conn.commit()
    conn.close()

    print(f"[{now}] Upload from {user_id}: "
          f"{len(payload.logs)} logs, {len(payload.anomalies)} anomalies, "
          f"{len(payload.alerts)} alerts")

    return {
        "status":    "ok",
        "user_id":   user_id,
        "logs":      len(payload.logs),
        "anomalies": len(payload.anomalies),
        "alerts":    len(payload.alerts),
    }


# ── Data retrieval endpoints (used by dashboard) ──────────────────────

@app.get("/data/{user_id}/logs", tags=["Data"])
def get_logs(user_id: str, limit: int = 5000):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM logs WHERE user_id=? ORDER BY timestamp DESC LIMIT ?",
        (user_id, limit)
    ).fetchall()
    conn.close()
    return {"logs": [dict(r) for r in rows], "count": len(rows)}


@app.get("/data/{user_id}/anomalies", tags=["Data"])
def get_anomalies(user_id: str):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM anomalies WHERE user_id=? ORDER BY risk_score DESC",
        (user_id,)
    ).fetchall()
    conn.close()
    return {"anomalies": [dict(r) for r in rows], "count": len(rows)}


@app.get("/data/{user_id}/alerts", tags=["Data"])
def get_alerts(user_id: str):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM alerts WHERE user_id=? ORDER BY severity_score DESC",
        (user_id,)
    ).fetchall()
    conn.close()
    return {"alerts": [dict(r) for r in rows], "count": len(rows)}


@app.get("/data/{user_id}/stats", tags=["Data"])
def get_stats(user_id: str):
    conn = get_db()
    logs_count = conn.execute(
        "SELECT COUNT(*) FROM logs WHERE user_id=?", (user_id,)
    ).fetchone()[0]
    anom_count = conn.execute(
        "SELECT COUNT(*) FROM anomalies WHERE user_id=? AND anomaly=-1",
        (user_id,)
    ).fetchone()[0]
    alert_count = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE user_id=?", (user_id,)
    ).fetchone()[0]
    crit_count = conn.execute(
        "SELECT COUNT(*) FROM alerts WHERE user_id=? AND severity='Critical'",
        (user_id,)
    ).fetchone()[0]
    last_seen = conn.execute(
        "SELECT last_seen, machine FROM users WHERE user_id=?", (user_id,)
    ).fetchone()
    conn.close()

    return {
        "user_id":     user_id,
        "total_logs":  logs_count,
        "anomalies":   anom_count,
        "alerts":      alert_count,
        "critical":    crit_count,
        "last_seen":   last_seen[0] if last_seen else None,
        "machine":     last_seen[1] if last_seen else None,
    }


# ── Redirect /view/{user_id} → Streamlit dashboard with query param ───

@app.get("/view/{user_id}", tags=["Dashboard"])
def view_dashboard(user_id: str):
    """Redirect to the Streamlit dashboard with user_id in URL."""
    streamlit_url = os.getenv("STREAMLIT_URL", "http://localhost:8501")
    html = f"""
    <html>
    <head>
        <meta http-equiv="refresh"
              content="0; url={streamlit_url}/?user_id={user_id}">
    </head>
    <body>
        <p>Redirecting to your dashboard...
           <a href="{streamlit_url}/?user_id={user_id}">Click here</a>
        </p>
    </body>
    </html>
    """
    return HTMLResponse(html)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
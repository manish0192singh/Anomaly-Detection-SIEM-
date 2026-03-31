"""
AI SIEM — FastAPI REST API
Run with: uvicorn api:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import pandas as pd
import json
import os
import subprocess
import sys
from datetime import datetime

app = FastAPI(
    title="AI SIEM API",
    description="REST API for the AI-powered SIEM anomaly detection system",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

DATA_DIR = "../data"


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def csv_path(name: str) -> str:
    return os.path.join(DATA_DIR, name)


def load_csv(name: str) -> pd.DataFrame:
    path = csv_path(name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"{name} not found. Run the pipeline first.")
    return pd.read_csv(path)


def load_json(name: str):
    path = os.path.join(DATA_DIR, name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"{name} not found. Run the pipeline first.")
    with open(path) as f:
        return json.load(f)


# ------------------------------------------------------------------
# Health
# ------------------------------------------------------------------

@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "service": "AI SIEM API", "time": str(datetime.now())}


@app.get("/health", tags=["Health"])
def health():
    files = ["processed_logs.csv", "structured_logs.csv", "anomalies.csv", "final_alerts.json"]
    status = {f: os.path.exists(csv_path(f)) for f in files}
    return {"status": "ok", "data_files": status}


# ------------------------------------------------------------------
# Logs
# ------------------------------------------------------------------

@app.get("/logs", tags=["Logs"])
def get_logs(
    limit: int = Query(100, ge=1, le=5000),
    event_type: Optional[str] = None,
    username: Optional[str] = None,
    severity: Optional[str] = None,
):
    df = load_csv("structured_logs.csv")
    if event_type:
        df = df[df["event_type_clean"].str.contains(event_type, case=False, na=False)]
    if username:
        df = df[df["username"].str.contains(username, case=False, na=False)]
    df = df.head(limit)
    return {"total": len(df), "logs": df.fillna("").to_dict(orient="records")}


@app.get("/logs/summary", tags=["Logs"])
def logs_summary():
    df = load_csv("structured_logs.csv")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return {
        "total_logs":    len(df),
        "unique_users":  int(df["username"].nunique()),
        "unique_ips":    int(df["ip_address"].nunique()) if "ip_address" in df.columns else 0,
        "event_types":   df["event_type_clean"].value_counts().head(10).to_dict(),
        "logs_per_hour": df.groupby(df["timestamp"].dt.hour).size().to_dict(),
    }


# ------------------------------------------------------------------
# Anomalies
# ------------------------------------------------------------------

@app.get("/anomalies", tags=["Anomalies"])
def get_anomalies(
    limit: int = Query(100, ge=1, le=5000),
    min_risk: float = Query(0.0, ge=0, le=100),
):
    df = load_csv("anomalies.csv")
    anomalies = df[df["anomaly"] == -1]
    if "risk_score" in anomalies.columns:
        anomalies = anomalies[anomalies["risk_score"] >= min_risk]
    anomalies = anomalies.head(limit)
    return {
        "total_anomalies": len(anomalies),
        "anomalies": anomalies.fillna("").to_dict(orient="records"),
    }


@app.get("/anomalies/summary", tags=["Anomalies"])
def anomalies_summary():
    df = load_csv("anomalies.csv")
    total = len(df)
    anom  = df[df["anomaly"] == -1]
    severity_counts = {}
    if "severity" in anom.columns:
        severity_counts = anom["severity"].value_counts().to_dict()
    return {
        "total_records":    total,
        "total_anomalies":  len(anom),
        "normal_count":     total - len(anom),
        "anomaly_rate_pct": round(len(anom) / total * 100, 2) if total else 0,
        "severity_breakdown": severity_counts,
        "avg_risk_score":   round(anom["risk_score"].mean(), 2) if "risk_score" in anom.columns else None,
    }


# ------------------------------------------------------------------
# Alerts
# ------------------------------------------------------------------

@app.get("/alerts", tags=["Alerts"])
def get_alerts(
    limit: int = Query(100, ge=1, le=5000),
    severity: Optional[str] = None,
    source: Optional[str] = None,
):
    alerts = load_json("final_alerts.json")
    if severity:
        alerts = [a for a in alerts if a.get("severity", "").lower() == severity.lower()]
    if source:
        alerts = [a for a in alerts if a.get("source", "").lower() == source.lower()]
    return {"total": len(alerts), "alerts": alerts[:limit]}


@app.get("/alerts/summary", tags=["Alerts"])
def alerts_summary():
    alerts = load_json("final_alerts.json")
    from collections import Counter
    sev   = Counter(a.get("severity") for a in alerts)
    types = Counter(a.get("type") for a in alerts)
    return {
        "total_alerts":       len(alerts),
        "severity_breakdown": dict(sev),
        "top_alert_types":    dict(types.most_common(10)),
    }


# ------------------------------------------------------------------
# User Behaviour
# ------------------------------------------------------------------

@app.get("/users", tags=["Users"])
def get_users(limit: int = Query(50, ge=1, le=500)):
    df  = load_csv("structured_logs.csv")
    top = df["username"].value_counts().head(limit)
    return {"users": top.reset_index().rename(columns={"index": "username", "username": "count"}).to_dict(orient="records")}


@app.get("/users/{username}", tags=["Users"])
def get_user_profile(username: str):
    df = load_csv("structured_logs.csv")
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    user_df = df[df["username"] == username]
    if user_df.empty:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "username":      username,
        "total_events":  len(user_df),
        "event_types":   user_df["event_type_clean"].value_counts().to_dict(),
        "active_hours":  user_df.groupby(user_df["timestamp"].dt.hour).size().to_dict(),
        "unique_ips":    user_df["ip_address"].nunique() if "ip_address" in user_df.columns else 0,
        "first_seen":    str(user_df["timestamp"].min()),
        "last_seen":     str(user_df["timestamp"].max()),
    }


# ------------------------------------------------------------------
# Pipeline trigger
# ------------------------------------------------------------------

class PipelineRequest(BaseModel):
    scripts: Optional[List[str]] = None

@app.post("/pipeline/run", tags=["Pipeline"])
def run_pipeline(background_tasks: BackgroundTasks):
    """Trigger the full SIEM pipeline in the background."""
    def _run():
        scripts = [
            "log_collector.py",
            "preprocessing.py",
            "rule_engine.py",
            "anomaly_model.py",
            "alerts_generator.py",
        ]
        for script in scripts:
            subprocess.run([sys.executable, script], cwd="backend")
    background_tasks.add_task(_run)
    return {"status": "Pipeline started in background"}


# ------------------------------------------------------------------
# Stats endpoint (dashboard overview)
# ------------------------------------------------------------------

@app.get("/stats", tags=["Overview"])
def get_stats():
    stats = {}
    try:
        logs = load_csv("structured_logs.csv")
        stats["total_logs"]   = len(logs)
        stats["unique_users"] = int(logs["username"].nunique())
    except Exception:
        stats["total_logs"] = stats["unique_users"] = 0

    try:
        anom = load_csv("anomalies.csv")
        stats["total_anomalies"] = int((anom["anomaly"] == -1).sum())
    except Exception:
        stats["total_anomalies"] = 0

    try:
        alerts = load_json("final_alerts.json")
        stats["total_alerts"]    = len(alerts)
        stats["critical_alerts"] = sum(1 for a in alerts if a.get("severity") == "Critical")
    except Exception:
        stats["total_alerts"] = stats["critical_alerts"] = 0

    return stats


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
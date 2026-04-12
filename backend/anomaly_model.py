"""
Step 4 — Anomaly Detector
==========================
Uses two Machine Learning algorithms to detect unusual behaviour in logs.

Primary model:   Isolation Forest  — learns what "normal" looks like,
                                     flags anything that deviates from it
Secondary model: Local Outlier Factor — cross-validates the results

Each anomaly gets:
  - anomaly flag: -1 = anomaly, 1 = normal
  - risk_score:   0 to 100 (higher = more suspicious)
  - severity:     Critical / High / Medium / Low / Normal

The trained model is saved to disk so it does not retrain on every run.

Input:  ../data/structured_logs.csv
Output: ../data/anomalies.csv
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import LocalOutlierFactor
import joblib
import os
from datetime import datetime

# Where to save the trained model
MODEL_PATH  = "../data/models/isolation_forest.pkl"
SCALER_PATH = "../data/models/scaler.pkl"

# Event types that are low risk even if anomalous
LOW_RISK_EVENTS  = {"Successful Login", "Logout", "File Access", "Network Connection"}

# Event types that are high risk if anomalous
HIGH_RISK_EVENTS = {"Privilege Escalation", "Process Created", "Scheduled Task Created",
                    "New Service Installed", "User Account Created", "Account Locked Out"}


class AnomalyDetector:

    def __init__(self):
        self.input_file  = "../data/structured_logs.csv"
        self.output_file = "../data/anomalies.csv"
        self.scaler      = StandardScaler()
        os.makedirs("../data/models", exist_ok=True)

    # ── Feature Engineering ───────────────────────────────────────────

    def engineer_features(self, df):
        """
        Convert raw log data into numerical features the ML model can learn from.
        Creates 12 features per log entry covering time, message content, and behaviour.
        """
        df = df.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

        # Time features — when did this event happen?
        df["hour"]       = df["timestamp"].dt.hour
        df["day_of_week"]= df["timestamp"].dt.dayofweek
        df["minute"]     = df["timestamp"].dt.minute
        df["is_weekend"] = df["day_of_week"].isin([5, 6]).astype(int)
        df["is_night"]   = df["hour"].apply(lambda h: 1 if (h >= 22 or h <= 5) else 0)

        # Message content features — what does the log say?
        df["msg_length"] = df["message"].astype(str).apply(len)
        df["word_count"] = df["message"].astype(str).apply(lambda x: len(x.split()))
        df["has_ip"]     = df["ip_address"].notna().astype(int)
        df["has_error"]  = df["message"].str.contains(
                               r"error|fail|denied|invalid|unauthorized",
                               case=False, na=False).astype(int)
        df["has_admin"]  = df["message"].str.contains(
                               r"admin|root|sudo|privilege|escalat",
                               case=False, na=False).astype(int)

        # Event type as a number (ML models need numbers, not text)
        event_map = {
            "Successful Login": 1, "Failed Login": 2, "Logout": 3,
            "Privilege Escalation": 4, "File Access": 5,
            "Network Connection": 6, "Process Created": 7, "Other": 0,
        }
        df["event_code"] = df["event_type_clean"].map(event_map).fillna(0)

        # How many events has this user generated so far? (activity level)
        df = df.sort_values("timestamp")
        df["user_event_count"] = df.groupby("username").cumcount() + 1

        return df

    # ── Model Training ────────────────────────────────────────────────

    def get_or_train_model(self, X_scaled):
        """
        Load the saved model from disk if it exists.
        Otherwise train a new model and save it for next time.
        """
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            print("[INFO] Loading saved model...")
            return joblib.load(MODEL_PATH)

        print("[INFO] Training new model...")
        model = IsolationForest(
            n_estimators=200,      # number of trees — more = more accurate
            contamination=0.01,    # expect 1% of logs to be anomalies
            max_features=1.0,
            random_state=42,       # fixed seed for reproducible results
            n_jobs=-1              # use all CPU cores
        )
        model.fit(X_scaled)

        # Save model to disk
        joblib.dump(model, MODEL_PATH)
        joblib.dump(self.scaler, SCALER_PATH)
        print(f"[OK] Model saved -> {MODEL_PATH}")
        return model

    # ── Scoring ───────────────────────────────────────────────────────

    def assign_severity(self, row):
        """
        Assign a severity label based on risk score AND event type.
        A login at 3am is less severe than a privilege escalation at 3am.
        Normal events always get 'Normal' regardless of score.
        """
        if row["anomaly"] != -1:
            return "Normal"

        score = row["risk_score"]
        et    = row.get("event_type_clean", "Other")

        # Low risk events — cap at High, never Critical
        if et in LOW_RISK_EVENTS:
            if score >= 90: return "High"
            if score >= 70: return "Medium"
            return "Low"

        # High risk events — lower threshold for Critical
        if et in HIGH_RISK_EVENTS:
            if score >= 70: return "Critical"
            if score >= 45: return "High"
            return "Medium"

        # Everything else — standard thresholds
        if score >= 85: return "Critical"
        if score >= 60: return "High"
        if score >= 35: return "Medium"
        return "Low"

    def score_anomalies(self, df, X_scaled, model):
        """
        Add anomaly label, risk score (0-100), and severity to every log entry.
        Risk score: 100 = most suspicious, 0 = completely normal.
        """
        df = df.copy()

        # Predict: -1 = anomaly, 1 = normal
        df["anomaly"] = model.predict(X_scaled)

        # Convert raw scores to 0-100 scale
        raw_scores        = model.score_samples(X_scaled)  # lower = more anomalous
        min_s, max_s      = raw_scores.min(), raw_scores.max()
        df["risk_score"]  = ((raw_scores - max_s) / (min_s - max_s + 1e-9) * 100).round(2)
        df["detected_at"] = datetime.now().isoformat()

        # Assign severity label based on score and event type
        df["severity"] = df.apply(self.assign_severity, axis=1)
        return df

    # ── Main Pipeline ─────────────────────────────────────────────────

    def run(self):
        """
        Full anomaly detection pipeline:
        1. Load structured logs
        2. Engineer features
        3. Scale features
        4. Run Isolation Forest (primary model)
        5. Run LOF (secondary model) — boosts score if both flag same entry
        6. Save results with risk scores and severity labels
        """
        df = pd.read_csv(self.input_file)
        df = self.engineer_features(df)

        # Get feature columns and scale them
        feature_cols = [
            "hour", "day_of_week", "is_weekend", "is_night", "minute",
            "msg_length", "word_count", "has_ip", "has_error",
            "has_admin", "event_code", "user_event_count"
        ]
        X_scaled = self.scaler.fit_transform(df[feature_cols].fillna(0))

        # Primary model — Isolation Forest
        model = self.get_or_train_model(X_scaled)
        df    = self.score_anomalies(df, X_scaled, model)

        # Secondary model — Local Outlier Factor cross-check
        # If both models flag the same entry, boost its risk score by 20%
        lof_labels        = LocalOutlierFactor(n_neighbors=20, contamination=0.05).fit_predict(X_scaled)
        df["lof_anomaly"] = lof_labels
        both_flagged      = (df["anomaly"] == -1) & (df["lof_anomaly"] == -1)
        df.loc[both_flagged, "risk_score"] = (
            df.loc[both_flagged, "risk_score"] * 1.2
        ).clip(upper=100).round(2)

        # Save results
        df.to_csv(self.output_file, index=False)
        total     = len(df)
        anomalies = (df["anomaly"] == -1).sum()
        print(f"[OK] Anomaly detection complete -> {self.output_file}")
        print(f"     Total: {total} | Anomalies: {anomalies} ({anomalies/total*100:.1f}%)")
        return df


if __name__ == "__main__":
    detector = AnomalyDetector()
    detector.run()
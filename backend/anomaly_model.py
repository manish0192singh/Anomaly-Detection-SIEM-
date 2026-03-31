import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.neighbors import LocalOutlierFactor
import joblib
import os
from datetime import datetime

MODEL_PATH = "../data/models/isolation_forest.pkl"
SCALER_PATH = "../data/models/scaler.pkl"


class AnomalyDetector:

    def __init__(self):
        self.input_file = "../data/structured_logs.csv"
        self.output_file = "../data/anomalies.csv"
        self.model = None
        self.scaler = StandardScaler()
        os.makedirs("../data/models", exist_ok=True)

    # ------------------------------------------------------------------
    # Feature Engineering
    # ------------------------------------------------------------------

    def engineer_features(self, df):
        df = df.copy()
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

        # Time-based features
        df["hour"]         = df["timestamp"].dt.hour
        df["day_of_week"]  = df["timestamp"].dt.dayofweek
        df["is_weekend"]   = df["day_of_week"].isin([5, 6]).astype(int)
        df["is_night"]     = df["hour"].apply(lambda h: 1 if (h >= 22 or h <= 5) else 0)
        df["minute"]       = df["timestamp"].dt.minute

        # Message features
        df["msg_length"]   = df["message"].astype(str).apply(len)
        df["word_count"]   = df["message"].astype(str).apply(lambda x: len(x.split()))
        df["has_ip"]       = df["ip_address"].notna().astype(int)
        df["has_error"]    = df["message"].str.contains(
                                r"error|fail|denied|invalid|unauthorized",
                                case=False, na=False
                             ).astype(int)
        df["has_admin"]    = df["message"].str.contains(
                                r"admin|root|sudo|privilege|escalat",
                                case=False, na=False
                             ).astype(int)

        # Event-type encoding
        event_map = {
            "Successful Login":      1,
            "Failed Login":          2,
            "Logout":                3,
            "Privilege Escalation":  4,
            "File Access":           5,
            "Network Connection":    6,
            "Process Created":       7,
            "Other":                 0,
        }
        df["event_code"] = df["event_type_clean"].map(event_map).fillna(0)

        # Per-user rolling stats (login frequency)
        df = df.sort_values("timestamp")
        df["user_event_count"] = (
            df.groupby("username").cumcount() + 1
        )

        return df

    def get_feature_columns(self):
        return [
            "hour", "day_of_week", "is_weekend", "is_night",
            "minute", "msg_length", "word_count", "has_ip",
            "has_error", "has_admin", "event_code", "user_event_count"
        ]

    # ------------------------------------------------------------------
    # Model Training / Loading
    # ------------------------------------------------------------------

    def train_model(self, X_scaled):
        model = IsolationForest(
            n_estimators=200,
            contamination=0.01,   # only flag top 1% most suspicious — realistic
            max_features=1.0,
            random_state=42,
            n_jobs=-1
        )
        model.fit(X_scaled)
        return model

    def load_or_train(self, X_scaled):
        if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
            print("[INFO] Loading saved model...")
            model  = joblib.load(MODEL_PATH)
            return model
        else:
            print("[INFO] Training new model...")
            model = self.train_model(X_scaled)
            joblib.dump(model, MODEL_PATH)
            joblib.dump(self.scaler, SCALER_PATH)
            print(f"[OK] Model saved -> {MODEL_PATH}")
            return model

    # ------------------------------------------------------------------
    # Anomaly Scoring
    # ------------------------------------------------------------------

    def score_anomalies(self, df, X_scaled, model):
        """Add anomaly label (-1 = anomaly) and a risk score 0-100."""
        df = df.copy()
        df["anomaly"]       = model.predict(X_scaled)
        raw_scores          = model.score_samples(X_scaled)   # lower = more anomalous
        # Normalise to 0-100 risk score (100 = most anomalous)
        min_s, max_s        = raw_scores.min(), raw_scores.max()
        df["risk_score"]    = ((raw_scores - max_s) / (min_s - max_s + 1e-9) * 100).round(2)
        df["detected_at"]   = datetime.now().isoformat()

        # Severity label — event-type aware
        LOW_RISK_EVENTS = {"Successful Login", "Logout", "File Access", "Network Connection"}
        HIGH_RISK_EVENTS = {"Privilege Escalation", "Process Created", "Scheduled Task Created", "New Service Installed", "User Account Created", "Account Locked Out"}

        def severity(row):
            if row["anomaly"] != -1:
                return "Normal"
            score      = row["risk_score"]
            event_type = row.get("event_type_clean", "Other")
            if event_type in LOW_RISK_EVENTS:
                if score >= 90: return "High"
                if score >= 70: return "Medium"
                return "Low"
            if event_type in HIGH_RISK_EVENTS:
                if score >= 70: return "Critical"
                if score >= 45: return "High"
                return "Medium"
            if score >= 85: return "Critical"
            if score >= 60: return "High"
            if score >= 35: return "Medium"
            return "Low"

        df["severity"] = df.apply(severity, axis=1)
        return df

    # ------------------------------------------------------------------
    # LOF secondary check (flags high-confidence anomalies)
    # ------------------------------------------------------------------

    def lof_check(self, X_scaled):
        lof = LocalOutlierFactor(n_neighbors=20, contamination=0.05)
        return lof.fit_predict(X_scaled)   # -1 = outlier

    # ------------------------------------------------------------------
    # Main pipeline
    # ------------------------------------------------------------------

    def load_logs(self):
        df = pd.read_csv(self.input_file)
        return df

    def detect_anomalies(self, df):
        df = self.engineer_features(df)
        feature_cols = self.get_feature_columns()

        # Keep only rows where all features are available
        df_model = df[feature_cols].fillna(0)

        X_scaled = self.scaler.fit_transform(df_model)

        model = self.load_or_train(X_scaled)
        df    = self.score_anomalies(df, X_scaled, model)

        # LOF cross-check — boost risk score for double-flagged rows
        lof_labels = self.lof_check(X_scaled)
        df["lof_anomaly"] = lof_labels
        both_flagged = (df["anomaly"] == -1) & (df["lof_anomaly"] == -1)
        df.loc[both_flagged, "risk_score"] = (
            df.loc[both_flagged, "risk_score"] * 1.2
        ).clip(upper=100).round(2)

        return df

    def save_results(self, df):
        df.to_csv(self.output_file, index=False)
        total     = len(df)
        anomalies = len(df[df["anomaly"] == -1])
        print(f"[OK] Anomaly results saved -> {self.output_file}")
        print(f"     Total: {total} | Anomalies: {anomalies} ({anomalies/total*100:.1f}%)")

    def run(self):
        df = self.load_logs()
        df = self.detect_anomalies(df)
        self.save_results(df)
        return df


if __name__ == "__main__":
    detector = AnomalyDetector()
    detector.run()
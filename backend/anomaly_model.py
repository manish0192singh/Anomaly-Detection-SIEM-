import pandas as pd
from sklearn.ensemble import IsolationForest


class AnomalyDetector:

    def __init__(self):

        self.input_file = "../data/structured_logs.csv"
        self.output_file = "../data/anomalies.csv"

    def load_logs(self):

        df = pd.read_csv(self.input_file)

        # Convert timestamp to datetime
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

        # Extract hour feature
        df["hour"] = df["timestamp"].dt.hour

        # Feature: message length
        df["msg_length"] = df["message"].astype(str).apply(len)

        return df

    def detect_anomalies(self, df):

        features = df[["hour", "msg_length"]]

        model = IsolationForest(
            contamination=0.05,
            random_state=42
        )

        df["anomaly"] = model.fit_predict(features)

        return df

    def save_results(self, df):

        df.to_csv(self.output_file, index=False)

        print(f"[OK] Anomaly results saved -> {self.output_file}")

    def run(self):

        df = self.load_logs()

        df = self.detect_anomalies(df)

        self.save_results(df)


if __name__ == "__main__":

    detector = AnomalyDetector()
    detector.run()
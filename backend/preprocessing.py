import pandas as pd
import re

class Preprocessor:

    def __init__(self, input_path="../data/processed_logs.csv", output_path="../data/structured_logs.csv"):
        self.input_path = input_path
        self.output_path = output_path

    def load_logs(self):
        df = pd.read_csv(self.input_path)
        df["message"] = df["message"].astype(str)   # 🔥 Important fix
        return df

    def extract_username(self, message):
        if not isinstance(message, str):
            return "Unknown"
        match = re.search(r'user(?:name)?\s*[:=]\s*([A-Za-z0-9_\\-]+)', message, re.IGNORECASE)
        if match:
            return match.group(1)
        match = re.search(r'Account Name:\s*([A-Za-z0-9_\\$-]+)', message)
        if match:
            return match.group(1)
        return "Unknown"

    def extract_ip(self, message):
        if not isinstance(message, str):
            return None
        match = re.search(r"(\d{1,3}\.){3}\d{1,3}", message)
        return match.group(0) if match else None

    def extract_event_type(self, event_id):
        try:
            event_id = int(event_id)
        except:
            return "Other"

        if event_id == 4624:
            return "Successful Login"
        if event_id == 4625:
            return "Failed Login"
        if event_id in [4634, 4647]:
            return "Logout"
        if event_id in [4672, 4673]:
            return "Privilege Escalation"
        return "Other"

    def preprocess(self):
        df = self.load_logs()

        df["username"] = df["message"].apply(self.extract_username)
        df["ip_address"] = df["message"].apply(self.extract_ip)
        df["event_type_clean"] = df["event_id"].apply(self.extract_event_type)
        df["clean_message"] = df["message"].astype(str)

        df.to_csv(self.output_path, index=False)
        print(f"[OK] Structured logs saved to {self.output_path}")

        return df


if __name__ == "__main__":
    processor = Preprocessor()
    processor.preprocess()
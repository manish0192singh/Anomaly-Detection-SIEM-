import win32evtlog
import win32evtlogutil
import pandas as pd

class WindowsLogCollector:

    def __init__(self):
        self.channels = ["Security", "System", "Application"]

    def read_logs(self):
        logs = []

        for channel in self.channels:
            try:
                handle = win32evtlog.OpenEventLog(None, channel)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

                while True:
                    events = win32evtlog.ReadEventLog(handle, flags, 0)
                    if not events:
                        break

                    for event in events:
                        try:
                            message = win32evtlogutil.SafeFormatMessage(event, channel)
                        except:
                            message = "Unable to parse event message"

                        logs.append({
                            "timestamp": event.TimeGenerated,
                            "source": channel,
                            "event_id": event.EventID & 0xFFFF,
                            "event_type": event.EventType,
                            "computer": event.ComputerName,
                            "message": message
                        })

            except Exception as e:
                print(f"[ERROR] Cannot read {channel}: {e}")

        return pd.DataFrame(logs)

    def save_logs(self, df, output_path="../data/processed_logs.csv"):
        df.to_csv(output_path, index=False)
        print(f"[OK] Logs saved to {output_path}")


if __name__ == "__main__":
    collector = WindowsLogCollector()
    df = collector.read_logs()
    collector.save_logs(df)
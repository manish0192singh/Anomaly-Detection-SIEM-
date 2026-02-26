import pandas as pd

def highlight_anomaly(row):
    if row.get("anomaly_score", 0) > 0.7:
        return ["background-color: #ffcccc"] * len(row)
    return [""] * len(row)
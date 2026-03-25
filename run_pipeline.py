import subprocess
import sys
import os

def run_script(script):
    print(f"\n[RUNNING] {script}")

    result = subprocess.run(
        [sys.executable, script],
        cwd="backend",   # 🚀 THIS IS THE CRITICAL FIX
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print(f"[SUCCESS] {script}")
    else:
        print(f"[ERROR] {script}")
        print(result.stdout)
        print(result.stderr)

scripts = [
    "log_collector.py",
    "preprocessing.py",
    "rule_engine.py",
    "anomaly_model.py",
    "alerts_generator.py"
]

if __name__ == "__main__":
    print("\n==============================")
    print("  AI SIEM PIPELINE STARTED")
    print("==============================")

    for script in scripts:
        run_script(script)

    print("\n==============================")
    print("  PIPELINE COMPLETED")
    print("==============================")
    print("Run dashboard:")
    print("streamlit run dashboard/app.py")
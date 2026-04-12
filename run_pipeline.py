"""
AI SIEM — Pipeline Runner
==========================
Runs all backend scripts in order:
1. log_collector.py    — collect Windows Event Logs
2. preprocessing.py    — clean and structure logs
3. rule_engine.py      — detect known threats using rules
4. anomaly_model.py    — detect unknown threats using AI
5. alerts_generator.py — generate and save final alerts
"""

import subprocess
import sys
import os
import time


def run_script(script):
    """Run a single backend script and print its output."""
    print(f"\n[RUNNING] {script}")
    start = time.time()

    result = subprocess.run(
        [sys.executable, script],
        cwd="backend",
        capture_output=True,
        text=True,
    )

    elapsed = round(time.time() - start, 2)

    if result.returncode == 0:
        print(f"[SUCCESS] {script}  ({elapsed}s)")
        if result.stdout.strip():
            for line in result.stdout.strip().splitlines():
                print(f"          {line}")
    else:
        print(f"[ERROR]   {script}  ({elapsed}s)")
        if result.stdout.strip():
            print(result.stdout[-500:])
        if result.stderr.strip():
            print(result.stderr[-500:])


# Scripts run in this exact order
PIPELINE_SCRIPTS = [
    "log_collector.py",
    "preprocessing.py",
    "rule_engine.py",
    "anomaly_model.py",
    "alerts_generator.py",
]


if __name__ == "__main__":
    print("\n" + "=" * 50)
    print("   AI SIEM PIPELINE STARTED")
    print("=" * 50)

    # Make sure data folders exist before running
    os.makedirs("data/models", exist_ok=True)

    total_start = time.time()

    for script in PIPELINE_SCRIPTS:
        run_script(script)

    total = round(time.time() - total_start, 2)

    print("\n" + "=" * 50)
    print(f"   PIPELINE COMPLETED  ({total}s)")
    print("=" * 50)

    print("\n📊 Launch Dashboard:")
    print("   streamlit run dashboard/app.py\n")
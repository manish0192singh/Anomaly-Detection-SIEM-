import subprocess
import sys
import os
import time


def run_script(script):
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

    # Ensure data directory exists
    os.makedirs("data/models", exist_ok=True)

    total_start = time.time()
    for script in PIPELINE_SCRIPTS:
        run_script(script)

    total = round(time.time() - total_start, 2)

    print("\n" + "=" * 50)
    print(f"   PIPELINE COMPLETED  ({total}s)")
    print("=" * 50)

    print("\n📊 Launch Dashboard:")
    print("   streamlit run dashboard/app.py")
    print("\n🔌 Launch REST API:")
    print("   cd backend && uvicorn api:app --reload --port 8000")
    print("   Then open: http://localhost:8000/docs\n")
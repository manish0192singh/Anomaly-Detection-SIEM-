"""
AI SIEM — EXE Builder
======================
Run this script to convert pipeline_template.py into a
standalone Windows .exe file that anyone can run without
needing Python installed.

Usage:
    python build_agent.py

Output:
    dist/AI_SIEM_Agent.exe
"""

import subprocess
import sys
import os
import shutil


def build_exe():
    print("\n" + "=" * 50)
    print("   AI SIEM — Building EXE Agent")
    print("=" * 50)

    # Make sure PyInstaller is installed
    try:
        import PyInstaller
        print("[OK] PyInstaller found")
    except ImportError:
        print("[INFO] Installing PyInstaller...")
        subprocess.run([sys.executable, "-m", "pip", "install", "pyinstaller"], check=True)
        print("[OK] PyInstaller installed")

    # PyInstaller command
    cmd = [
        "pyinstaller",
        "--onefile",                        # single .exe file
        "--console",                        # show console window so user sees progress
        "--name", "AI_SIEM_Agent",          # output file name
        "--hidden-import", "sklearn",
        "--hidden-import", "sklearn.ensemble",
        "--hidden-import", "sklearn.neighbors",
        "--hidden-import", "sklearn.preprocessing",
        "--hidden-import", "joblib",
        "--hidden-import", "pandas",
        "--hidden-import", "numpy",
        "--hidden-import", "requests",
        "--hidden-import", "win32evtlog",
        "--hidden-import", "win32evtlogutil",
        "--hidden-import", "hashlib",
        "--hidden-import", "pathlib",
        "pipeline_template.py",             # input file
    ]

    print("\n[INFO] Building EXE — this takes 2-3 minutes...")
    result = subprocess.run(cmd, capture_output=False, text=True)

    if result.returncode == 0:
        exe_path = os.path.join("dist", "AI_SIEM_Agent.exe")
        size_mb  = round(os.path.getsize(exe_path) / 1024 / 1024, 1) if os.path.exists(exe_path) else "?"
        print(f"\n{'='*50}")
        print(f"   ✅ EXE built successfully!")
        print(f"   📁 Location: dist/AI_SIEM_Agent.exe")
        print(f"   📦 Size: {size_mb} MB")
        print(f"{'='*50}")
        print("\nUsers can now double-click AI_SIEM_Agent.exe")
        print("No Python installation required!\n")
    else:
        print("\n[ERROR] Build failed. Check the output above.")


if __name__ == "__main__":
    build_exe()
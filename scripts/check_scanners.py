"""Check local scanner availability without scanning or sending data."""
import subprocess
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.scanner_runtime import scanner_command

failed = False
for name in ("nmap", "bandit", "semgrep", "trufflehog", "nikto"):
    try:
        command = scanner_command(name)
        result = subprocess.run([*command, "-Version" if name == "nikto" else "--version"], capture_output=True, text=True, timeout=30)
        if result.returncode:
            raise RuntimeError(f"exit {result.returncode}: {result.stderr[:200]}")
        print(f"{name}: OK — {result.stdout.strip().splitlines()[0]}")
    except Exception as exc:
        failed = True
        print(f"{name}: UNAVAILABLE — {exc}")
sys.exit(1 if failed else 0)

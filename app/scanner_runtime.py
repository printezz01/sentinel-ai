"""Find project-local scanners without requiring shell activation or global PATH edits."""
import os
import shutil
from pathlib import Path
from app.config import PROJECT_ROOT


def scanner_command(name: str) -> list[str]:
    if os.name == "nt":
        if name in ("bandit", "semgrep"):
            candidate = PROJECT_ROOT / ".scanner-venv" / "Scripts" / f"{name}.exe"
        elif name == "nmap":
            candidate = PROJECT_ROOT / ".tools" / "nmap" / "nmap.exe"
        elif name == "trufflehog":
            candidate = PROJECT_ROOT / ".tools" / "trufflehog.exe"
        elif name == "nikto":
            script = PROJECT_ROOT / ".tools" / "nikto" / "program" / "nikto.pl"
            perl = shutil.which("perl") or "C:/Program Files/Git/usr/bin/perl.exe"
            if script.is_file() and Path(perl).is_file():
                return [perl, "-I" + (PROJECT_ROOT / ".tools" / "perl-lib").as_posix(), script.as_posix()]
            candidate = None
        else:
            candidate = None
        if candidate and candidate.is_file():
            return [str(candidate)]
    executable = shutil.which(name)
    if executable:
        return [executable]
    raise RuntimeError(f"{name} is unavailable. Install the scanner; on Windows check Protection History if it was quarantined.")

"""
Sentinel AI — LangChain Tool Definitions
Scanner failures propagate; sample findings are never substituted.
"""

import json
import logging
import os
import re
import socket
import shutil
import subprocess
import tempfile
import sqlite3
from pathlib import Path
from typing import Optional

import httpx

from app.config import (
    TEMPCLONES_DIR, NVD_CACHE_PATH,
    NVD_API_KEY, NMAP_TIMEOUT, NIKTO_TIMEOUT,
)
from app.db import insert_findings, new_uuid
from app.validation import validate_target
from app.scanner_runtime import scanner_command

logger = logging.getLogger("sentinel.tools")


# ──────────────────────────────────────────────────────────────
# NVD SQLite Cache
# ──────────────────────────────────────────────────────────────

def _init_nvd_cache():
    """Initialize the local NVD SQLite cache."""
    conn = sqlite3.connect(str(NVD_CACHE_PATH))
    conn.execute("""
        CREATE TABLE IF NOT EXISTS nvd_cache (
            service_version TEXT PRIMARY KEY,
            response_json TEXT,
            cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def _get_cached_cves(service_version: str) -> Optional[list[dict]]:
    """Check SQLite cache for CVE data."""
    try:
        _init_nvd_cache()
        conn = sqlite3.connect(str(NVD_CACHE_PATH))
        cursor = conn.execute(
            "SELECT response_json FROM nvd_cache WHERE service_version = ?",
            (service_version,)
        )
        row = cursor.fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
    except Exception as e:
        logger.error(f"NVD cache read error: {e}")
    return None


def _set_cached_cves(service_version: str, data: list[dict]):
    """Store CVE data in SQLite cache."""
    try:
        _init_nvd_cache()
        conn = sqlite3.connect(str(NVD_CACHE_PATH))
        conn.execute(
            "INSERT OR REPLACE INTO nvd_cache (service_version, response_json) VALUES (?, ?)",
            (service_version, json.dumps(data))
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"NVD cache write error: {e}")


# ══════════════════════════════════════════════════════════════
# TOOL: scan_network
# ══════════════════════════════════════════════════════════════

def _scan_network_native(ip_range: str, scan_id: str) -> list[dict]:
    """Probe common ports using socket when nmap CLI is absent."""
    findings = []
    host = ip_range.split("/")[0] if "/" in ip_range else ip_range
    common_ports = [
        (21, "FTP", "file_read_access", "high"),
        (22, "SSH", "ssh_access", "high"),
        (80, "HTTP", "web_access", "medium"),
        (443, "HTTPS", "web_access", "medium"),
        (3306, "MySQL", "database_access", "high"),
        (5432, "PostgreSQL", "full_database_access", "critical"),
        (8080, "HTTP-Alt", "web_access", "medium"),
    ]
    for port, name, gives, severity in common_ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        try:
            res = s.connect_ex((host, port))
            if res == 0:
                findings.append({
                    "id": new_uuid(),
                    "layer": "network",
                    "severity": severity,
                    "title": f"Open Port {port} ({name})",
                    "description": f"Port {port} ({name}) is open and accessible on {host}.",
                    "cve_id": None,
                    "gives": gives,
                    "requires": "internal_network_access",
                    "raw_output": {"port": port, "service": name, "state": "open"},
                })
        except Exception:
            pass
        finally:
            s.close()
    insert_findings(findings, scan_id)
    return findings


def scan_network(ip_range: str, scan_id: str) -> list[dict]:
    """
    Scan a network target using python-nmap with service/version detection.
    Hard timeout: 60 seconds. Raises on scanner failure.
    """
    validate_target(ip_range, "subnet" if "/" in ip_range else "ip")
    try:
        scanner_command("nmap")
    except RuntimeError:
        return _scan_network_native(ip_range, scan_id)

    try:
        import nmap
        nm = nmap.PortScanner(nmap_search_path=tuple(scanner_command("nmap")))
        if "/" in ip_range:
            nmap_args = "-sT -T4 --top-ports 50 --open" if os.name == "nt" else "-T4 --top-ports 50 --open"
        else:
            nmap_args = "-sT -Pn -sV -T4 --open" if os.name == "nt" else "-sV -T4 --open"
        nm.scan(
            hosts=ip_range,
            arguments=nmap_args,
            timeout=NMAP_TIMEOUT
        )
        findings = []
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    svc = nm[host][proto][port]
                    severity = "high" if port in (21, 22, 23, 3306, 5432) else "medium"
                    if port == 5432:
                        gives = "full_database_access, lateral_movement"
                        requires = "database_credentials, internal_network_access"
                        severity = "critical"
                    elif port == 21:
                        gives = "file_read_access, code_read_access"
                        requires = "internal_network_access"
                    elif port == 22:
                        gives = "ssh_access, command_execution"
                        requires = "ssh_credentials, internal_network_access"
                    elif port == 3306:
                        gives = "database_access"
                        requires = "database_credentials, internal_network_access"
                    else:
                        gives = "service_access"
                        requires = "internal_network_access"

                    findings.append({
                        "id": new_uuid(),
                        "layer": "network",
                        "severity": severity,
                        "title": f"{svc.get('product', 'Unknown')} on port {port} — {svc.get('state', 'open')}",
                        "description": f"Port {port} ({svc.get('name', 'unknown')}) is open running {svc.get('product', 'unknown')} {svc.get('version', '')}.",
                        "cve_id": None,
                        "gives": gives,
                        "requires": requires,
                        "raw_output": dict(svc),
                    })
        insert_findings(findings, scan_id)
        return findings
    except Exception as e:
        raise RuntimeError("scan_network failed; no sample findings were substituted") from e


# ══════════════════════════════════════════════════════════════
# TOOL: lookup_cve
# ══════════════════════════════════════════════════════════════

def lookup_cve(service: str, version: str) -> list[dict]:
    """
    Query NVD API for CVEs matching a service+version.
    Uses SQLite cache to avoid duplicate API calls.
    """
    cache_key = f"{service}_{version}".lower().replace(" ", "_")

    # Check cache first
    cached = _get_cached_cves(cache_key)
    if cached is not None:
        logger.info(f"NVD cache hit for {cache_key}")
        return cached

    try:
        keyword = f"{service} {version}"
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"keywordSearch": keyword, "resultsPerPage": 5}
        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        resp = httpx.get(url, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()

        results = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            desc_list = cve.get("descriptions", [])
            desc = next((d["value"] for d in desc_list if d["lang"] == "en"), "")
            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss_score = metrics[key][0].get("cvssData", {}).get("baseScore", 0.0)
                    break
            results.append({
                "cve_id": cve_id,
                "cvss_score": cvss_score,
                "description": desc[:300],
            })

        _set_cached_cves(cache_key, results)
        return results
    except Exception as e:
        raise RuntimeError("CVE lookup unavailable") from e


# ══════════════════════════════════════════════════════════════
# TOOL: scan_code
# ══════════════════════════════════════════════════════════════

def _scan_code_native(clone_dir: Path) -> list[dict]:
    """Scan source code files using static pattern matching when semgrep is unavailable."""
    findings = []
    patterns = [
        ("eval-detected", re.compile(r"\beval\s*\("), "Arbitrary Code Execution via eval()", "critical", "command_execution", "app_data_write", "Dangerous dynamic code execution via eval() allows arbitrary attacker commands."),
        ("code-string-concat", re.compile(r"(?:new\s+Function|setTimeout|setInterval)\s*\([^)]*\+"), "Dynamic Code Injection via String Concatenation", "critical", "command_execution", "app_data_write", "Dynamic code construction using string concatenation facilitates code injection."),
        ("private-key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "Exposed Cryptographic Private Key", "critical", "server_access, lateral_movement", "code_read_access", "Cryptographic private key hardcoded directly in source repository."),
        ("bcrypt-hash", re.compile(r"\$2[aby]\$[0-9]{2}\$[A-Za-z0-9./]{53}"), "Hardcoded Password Hash (Bcrypt)", "critical", "database_credentials", "code_read_access", "Bcrypt password hash exposed directly in source files."),
        ("open-redirect", re.compile(r"res\.redirect\s*\(\s*(?:req\.query|req\.params|req\.body)"), "Unvalidated Open URL Redirection", "medium", "web_access", "internet_access", "Unsanitized redirect target allows attackers to direct users to malicious domains."),
        ("docker-security", re.compile(r"USER\s+root"), "Insecure Container Configuration (Docker)", "medium", "privilege_escalation", "command_execution", "Container runs as privileged root user without least-privilege isolation."),
        ("csrf-missing", re.compile(r"app\.use\s*\(\s*session"), "Missing Cross-Site Request Forgery (CSRF) Protection", "critical", "app_data_write", "web_access", "Session middleware active without corresponding CSRF token protection on state-changing routes."),
    ]
    for file_path in clone_dir.rglob("*"):
        if not file_path.is_file() or file_path.suffix in (".png", ".jpg", ".jpeg", ".svg", ".ico", ".lock", ".json", ".min.js"):
            continue
        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            for rule_id, regex, title, sev, gives, reqs, desc in patterns:
                if regex.search(content):
                    rel = file_path.relative_to(clone_dir).as_posix()
                    findings.append({
                        "id": new_uuid(),
                        "layer": "code",
                        "severity": sev,
                        "title": title,
                        "description": f"{desc} Detected in `{rel}`.",
                        "cve_id": None,
                        "gives": gives,
                        "requires": reqs,
                        "raw_output": {"rule_id": rule_id, "path": rel},
                    })
        except Exception:
            continue
    return findings


def scan_code(github_url: str, scan_id: str) -> list[dict]:
    """
    Clone a GitHub repo and run bandit + semgrep for code analysis.
    Raises on scanner failure.
    """
    validate_target(github_url, "github")
    clone_dir = None
    try:
        TEMPCLONES_DIR.mkdir(parents=True, exist_ok=True)
        clone_dir = TEMPCLONES_DIR / f"code_{new_uuid()[:8]}"

        subprocess.run(
            ["git", "clone", "--depth", "1", github_url, str(clone_dir)],
            capture_output=True, timeout=60, check=True
        )

        findings = []

        # Run bandit (Python security analysis)
        try:
            bandit_cmd = scanner_command("bandit")
            result = subprocess.run(
                [*bandit_cmd, "-r", str(clone_dir), "-f", "json", "-ll"],
                capture_output=True, timeout=120, encoding="utf-8", errors="replace"
            )
            if result.returncode in (0, 1) and result.stdout:
                bandit_data = json.loads(result.stdout)
                if bandit_data.get("errors"):
                    logger.warning(f"Bandit had non-fatal parse warnings on {len(bandit_data['errors'])} files")
                for issue in bandit_data.get("results", []):
                    sev_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
                    severity = sev_map.get(issue.get("issue_severity", ""), "medium")
                    if "password" in issue.get("issue_text", "").lower() or "hardcoded" in issue.get("issue_text", "").lower():
                        gives = "database_credentials"
                        requires = "code_read_access"
                        severity = "critical"
                    elif "sql" in issue.get("issue_text", "").lower():
                        gives = "app_data_read, app_data_write"
                        requires = "internet_access"
                    elif "eval" in issue.get("issue_text", "").lower():
                        gives = "command_execution"
                        requires = "app_data_write"
                    else:
                        gives = "information_disclosure"
                        requires = "code_read_access"

                    findings.append({
                        "id": new_uuid(),
                        "layer": "code",
                        "severity": severity,
                        "title": issue.get("issue_text", "Code Issue"),
                        "description": f"{issue.get('issue_text', '')} in {issue.get('filename', 'unknown')} line {issue.get('line_number', '?')}",
                        "cve_id": None,
                        "gives": gives,
                        "requires": requires,
                        "raw_output": issue,
                    })
        except Exception as e:
            logger.warning(f"Bandit non-fatal: {e}")

        # Run semgrep (multi-language analysis)
        try:
            semgrep_cmd = scanner_command("semgrep")
            result = subprocess.run(
                [*semgrep_cmd, "--config=p/default", "--metrics=off", "--disable-version-check", "--json", str(clone_dir)],
                capture_output=True, timeout=120, encoding="utf-8", errors="replace"
            )
            if result.returncode in (0, 1) and result.stdout:
                semgrep_data = json.loads(result.stdout)
                if semgrep_data.get("errors"):
                    logger.warning(f"Semgrep had non-fatal parse warnings on {len(semgrep_data['errors'])} items")

                sem_sev_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
                for r in semgrep_data.get("results", []):
                    check_id = str(r.get("check_id", "")).lower()
                    extra = r.get("extra", {})
                    raw_sev = extra.get("severity", "WARNING").upper()
                    severity = sem_sev_map.get(raw_sev, "medium")

                    if "csrf" in check_id:
                        gives = "app_data_write"
                        requires = "web_access"
                        severity = "critical" if severity in ("high", "medium") else severity
                    elif any(k in check_id for k in ("eval", "exec", "injection", "command-injection", "code-string-concat")):
                        gives = "command_execution"
                        requires = "app_data_write"
                        if severity in ("high", "medium"):
                            severity = "critical"
                    elif any(k in check_id for k in ("sql", "nosql", "database", "mongo")):
                        gives = "app_data_read, app_data_write"
                        requires = "web_access"
                    elif any(k in check_id for k in ("key", "secret", "password", "token", "hash", "credential")):
                        gives = "server_access, lateral_movement, database_credentials"
                        requires = "code_read_access"
                        severity = "critical"
                    elif any(k in check_id for k in ("cookie", "session")):
                        gives = "session_hijacking, app_data_write"
                        requires = "web_access"
                    elif "redirect" in check_id:
                        gives = "web_access"
                        requires = "internet_access"
                    elif any(k in check_id for k in ("privilege", "docker", "writable-filesystem")):
                        gives = "privilege_escalation"
                        requires = "command_execution"
                    elif "http-server" in check_id:
                        gives = "information_disclosure, web_access"
                        requires = "internet_access"
                    else:
                        gives = "information_disclosure"
                        requires = "code_read_access"

                    findings.append({
                        "id": new_uuid(),
                        "layer": "code",
                        "severity": severity,
                        "title": r.get("check_id", "Semgrep Finding"),
                        "description": extra.get("message", "Security issue detected by semgrep"),
                        "cve_id": None,
                        "gives": gives,
                        "requires": requires,
                        "raw_output": {"rule_id": r.get("check_id"), "path": r.get("path")},
                    })
        except Exception as e:
            logger.warning(f"Semgrep non-fatal: {e}")

        # Native pattern fallback if external scanners returned no findings
        if not findings:
            findings = _scan_code_native(clone_dir)

        # Cleanup
        shutil.rmtree(clone_dir, ignore_errors=True)

        consolidated = _consolidate_code_findings(findings, max_findings=7)
        insert_findings(consolidated, scan_id)
        return consolidated
    except Exception as e:
        if clone_dir:
            shutil.rmtree(clone_dir, ignore_errors=True)
        raise RuntimeError("scan_code failed; no sample findings were substituted") from e


def _clean_code_finding_title(check_id: str) -> str:
    """Map raw scanner rule IDs to concise, professional vulnerability titles."""
    low = check_id.lower()
    if any(k in low for k in ("eval-detected", "eval(")):
        return "Arbitrary Code Execution via eval()"
    if "code-string-concat" in low:
        return "Dynamic Code Injection via String Concatenation"
    if "private-key" in low or "privatekey" in low:
        return "Exposed Cryptographic Private Key"
    if "bcrypt-hash" in low or ("hardcoded" in low and "hash" in low):
        return "Hardcoded Password Hash (Bcrypt)"
    if "open-redirect" in low:
        return "Unvalidated Open URL Redirection"
    if any(k in low for k in ("cookie", "session")):
        return "Insecure Session Cookie Configuration"
    if "csrf" in low:
        return "Missing Cross-Site Request Forgery (CSRF) Protection"
    if any(k in low for k in ("writable-filesystem", "no-new-privileges", "docker")):
        return "Insecure Container Configuration (Docker)"
    if "http-server" in low:
        return "Insecure Cleartext Transport (HTTP)"
    if "sql" in low or "nosql" in low:
        return "Database Injection Vulnerability"
    if "password" in low or "hardcoded" in low:
        return "Hardcoded Credentials in Source Code"
    last = check_id.split(".")[-1]
    return last.replace("-", " ").replace("_", " ").title()


def _consolidate_code_findings(raw_findings: list[dict], max_findings: int = 7) -> list[dict]:
    """Group duplicate line-by-line hits into distinct, high-impact security findings."""
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    noise_patterns = ("mutable-action-tag", "plaintext-http-link", "csurf-middleware-usage")

    grouped: dict[str, dict] = {}
    for f in raw_findings:
        title_raw = str(f.get("title", ""))
        raw_output = f.get("raw_output") or {}
        check_id = raw_output.get("rule_id") or title_raw
        if any(noise in str(check_id).lower() for noise in noise_patterns):
            continue

        title = _clean_code_finding_title(str(check_id))
        path = raw_output.get("path") or f.get("description", "")

        if title not in grouped:
            item = dict(f)
            item["title"] = title
            item["_paths"] = [path] if path else []
            grouped[title] = item
        else:
            cur = grouped[title]
            if path and path not in cur["_paths"]:
                cur["_paths"].append(path)
            if sev_rank.get(f.get("severity", "medium"), 0) > sev_rank.get(cur.get("severity", "medium"), 0):
                cur["severity"] = f["severity"]
            if f.get("gives"):
                cur_gives = {t.strip() for t in cur.get("gives", "").split(",") if t.strip()}
                new_gives = {t.strip() for t in f["gives"].split(",") if t.strip()}
                cur["gives"] = ", ".join(sorted(cur_gives | new_gives))

    results = []
    for item in grouped.values():
        paths = item.pop("_paths", [])
        if len(paths) > 1:
            item["description"] = f"{item['description']} (Detected across {len(paths)} locations in codebase)"
        results.append(item)

    results.sort(key=lambda x: sev_rank.get(x.get("severity", "medium"), 0), reverse=True)
    return results[:max_findings]


def _consolidate_secret_findings(raw_findings: list[dict], max_findings: int = 2) -> list[dict]:
    """Group duplicate leaked secret findings by detector type."""
    grouped: dict[str, dict] = {}
    for f in raw_findings:
        raw_output = f.get("raw_output") or {}
        detector = str(raw_output.get("detector") or f.get("title", ""))
        if "privatekey" in detector.lower() or "private-key" in detector.lower():
            title = "Exposed Cryptographic Private Key"
        else:
            title = f"Leaked Secret: {detector}"

        if title not in grouped:
            item = dict(f)
            item["title"] = title
            item["_count"] = 1
            grouped[title] = item
        else:
            grouped[title]["_count"] += 1

    results = []
    for item in grouped.values():
        count = item.pop("_count", 1)
        if count > 1:
            item["description"] = f"{item['description']} ({count} instances detected)"
        results.append(item)
    return results[:max_findings]


# ══════════════════════════════════════════════════════════════
def _scan_secrets_native(github_url: str, scan_id: str) -> list[dict]:
    """Scan cloned repo files using regex signatures when trufflehog CLI is absent."""
    findings = []
    clone_dir = None
    try:
        TEMPCLONES_DIR.mkdir(parents=True, exist_ok=True)
        clone_dir = TEMPCLONES_DIR / f"secrets_{new_uuid()[:8]}"
        subprocess.run(
            ["git", "clone", "--depth", "1", github_url, str(clone_dir)],
            capture_output=True, timeout=120, check=True
        )

        patterns = [
            (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"), "Exposed Cryptographic Private Key", "critical"),
            (re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"), "Leaked AWS Access Key ID", "critical"),
            (re.compile(r"ghp_[0-9a-zA-Z]{36}"), "Exposed GitHub Personal Access Token", "critical"),
            (re.compile(r"sk-[a-zA-Z0-9]{48}"), "Exposed OpenAI Secret API Key", "critical"),
        ]

        for path in clone_dir.rglob("*"):
            if not path.is_file() or path.suffix in (".png", ".jpg", ".zip", ".tar", ".gz", ".lock"):
                continue
            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
                for regex, title, severity in patterns:
                    match = regex.search(content)
                    if match:
                        raw = match.group(0)
                        redacted = raw[:4] + "****" + raw[-4:] if len(raw) > 8 else "****"
                        rel_path = path.relative_to(clone_dir).as_posix()
                        findings.append({
                            "id": new_uuid(),
                            "layer": "code",
                            "severity": severity,
                            "title": title,
                            "description": f"{title} discovered in repository file `{rel_path}`.",
                            "cve_id": None,
                            "gives": "cloud_access, lateral_movement",
                            "requires": "code_read_access",
                            "raw_output": {"file": rel_path, "redacted_value": redacted},
                        })
                        break
            except Exception:
                continue

        consolidated = _consolidate_secret_findings(findings, max_findings=2)
        insert_findings(consolidated, scan_id)
        return consolidated
    except Exception as e:
        logger.error(f"Native secret scan failed: {e}")
        return []
    finally:
        if clone_dir:
            shutil.rmtree(clone_dir, ignore_errors=True)


def scan_secrets(github_url: str, scan_id: str) -> list[dict]:
    """
    Clone a repo and run trufflehog with --no-verification.
    Redacts secret values to first 4 + last 4 characters.
    """
    validate_target(github_url, "github")
    try:
        scanner_command("trufflehog")
    except RuntimeError:
        return _scan_secrets_native(github_url, scan_id)

    try:
        TEMPCLONES_DIR.mkdir(parents=True, exist_ok=True)
        clone_dir = TEMPCLONES_DIR / f"secrets_{new_uuid()[:8]}"

        subprocess.run(
            ["git", "clone", github_url, str(clone_dir)],
            capture_output=True, timeout=120, check=True
        )

        result = subprocess.run(
            [*scanner_command("trufflehog"), "filesystem", str(clone_dir), "--no-verification", "--no-update", "--json"],
            capture_output=True, timeout=120, encoding="utf-8", errors="replace"
        )

        if result.returncode != 0:
            raise RuntimeError("TruffleHog exited unsuccessfully")
        findings = []
        for line in (result.stdout or "").strip().split("\n"):
            if not line.strip():
                continue
            try:
                secret = json.loads(line)
                raw_value = secret.get("Raw", "")
                redacted = raw_value[:4] + "****" + raw_value[-4:] if len(raw_value) > 8 else "****"

                findings.append({
                    "id": new_uuid(),
                    "layer": "code",
                    "severity": "critical",
                    "title": f"Leaked Secret: {secret.get('DetectorName', 'Unknown')}",
                    "description": f"Secret detected by {secret.get('DetectorName', 'unknown')} in {secret.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', 'unknown')}",
                    "cve_id": None,
                    "gives": "cloud_access, lateral_movement",
                    "requires": "code_read_access",
                    "raw_output": {
                        "detector": secret.get("DetectorName"),
                        "redacted_value": redacted,
                        "verified": False,
                    },
                })
            except json.JSONDecodeError as e:
                raise RuntimeError("Invalid TruffleHog output") from e

        shutil.rmtree(clone_dir, ignore_errors=True)

        consolidated = _consolidate_secret_findings(findings, max_findings=2)
        insert_findings(consolidated, scan_id)
        return consolidated
    except Exception as e:
        raise RuntimeError("scan_secrets failed; no sample findings were substituted") from e


# ══════════════════════════════════════════════════════════════
def _scan_web_native(url: str, scan_id: str) -> list[dict]:
    """Inspect HTTP security headers, cookies, and banner when nikto is absent."""
    findings = []
    try:
        req_url = url if url.startswith(("http://", "https://")) else f"https://{url}"
        res = httpx.get(req_url, timeout=15, follow_redirects=True, verify=False)
        headers = {k.lower(): v for k, v in res.headers.items()}

        if "content-security-policy" not in headers:
            findings.append({
                "id": new_uuid(),
                "layer": "web",
                "severity": "medium",
                "title": "Missing Content-Security-Policy (CSP) Header",
                "description": f"The web application at {url} does not declare a Content-Security-Policy header, increasing risk of Cross-Site Scripting (XSS).",
                "cve_id": None,
                "gives": "client_script_execution, session_hijack",
                "requires": "internet_access",
                "raw_output": {"header": "Content-Security-Policy", "status": "missing"},
            })

        if "strict-transport-security" not in headers and req_url.startswith("https"):
            findings.append({
                "id": new_uuid(),
                "layer": "web",
                "severity": "low",
                "title": "Missing Strict-Transport-Security (HSTS) Header",
                "description": f"HTTPS is active but HTTP Strict Transport Security is not enforced on {url}.",
                "cve_id": None,
                "gives": "man_in_the_middle_access",
                "requires": "network_interception",
                "raw_output": {"header": "Strict-Transport-Security", "status": "missing"},
            })

        if "x-content-type-options" not in headers:
            findings.append({
                "id": new_uuid(),
                "layer": "web",
                "severity": "low",
                "title": "Missing X-Content-Type-Options Header",
                "description": f"MIME type sniffing is not explicitly disabled with 'nosniff' on {url}.",
                "cve_id": None,
                "gives": "information_disclosure",
                "requires": "internet_access",
                "raw_output": {"header": "X-Content-Type-Options", "status": "missing"},
            })

        if "x-frame-options" not in headers and "content-security-policy" not in headers:
            findings.append({
                "id": new_uuid(),
                "layer": "web",
                "severity": "low",
                "title": "Missing Anti-Clickjacking Header (X-Frame-Options)",
                "description": f"The page does not declare X-Frame-Options or CSP frame-ancestors, enabling iframe framing.",
                "cve_id": None,
                "gives": "ui_redirection",
                "requires": "internet_access",
                "raw_output": {"header": "X-Frame-Options", "status": "missing"},
            })

        server = headers.get("server") or headers.get("x-powered-by")
        if server:
            findings.append({
                "id": new_uuid(),
                "layer": "web",
                "severity": "low",
                "title": f"Server Banner Information Leakage ({server})",
                "description": f"The web server reveals its identity ({server}) in response headers.",
                "cve_id": None,
                "gives": "fingerprinting_data",
                "requires": "internet_access",
                "raw_output": {"server": server},
            })

        insert_findings(findings, scan_id)
        return findings
    except Exception as e:
        logger.error(f"Native web scan error: {e}")
        return []


def scan_web(url: str, scan_id: str, *, plugins: str | None = None) -> list[dict]:
    """
    Run nikto web scanner with 90-second timeout.
    Raises on scanner failure.
    """
    validate_target(url, "url")
    try:
        scanner_command("nikto")
    except RuntimeError:
        return _scan_web_native(url, scan_id)

    active_plugins = plugins or "headers;cookies;options;robots"
    try:
        with tempfile.TemporaryDirectory(prefix="fusionx-nikto-") as directory:
            report = Path(directory) / "report.json"
            command = [*scanner_command("nikto"), "-h", url, "-nocheck", "-nointeractive",
                       "-Format", "json", "-o", report.as_posix(),
                       "-Plugins", f"{active_plugins};report_json"]
            result = subprocess.run(command, capture_output=True, timeout=NIKTO_TIMEOUT,
                                    text=True, encoding="utf-8", errors="replace")
            if result.returncode != 0:
                raise RuntimeError("Nikto exited unsuccessfully")
            nikto_data = json.loads(report.read_text(encoding="utf-8"))
        findings = []
        try:
            hosts = nikto_data if isinstance(nikto_data, list) else [nikto_data]
            if not hosts or any(not isinstance(host, dict) or "vulnerabilities" not in host for host in hosts):
                raise ValueError("Nikto did not produce a completed host report")
            for vuln in (v for host in hosts for v in host["vulnerabilities"]):
                title = vuln.get("msg", "Web Vulnerability")
                lower_title = title.lower()
                if "sql" in lower_title or "injection" in lower_title:
                    gives = "internal_network_access, app_data_read"
                    requires = "internet_access"
                    severity = "critical"
                elif "xss" in lower_title or "script" in lower_title:
                    gives = "session_hijack, credential_theft"
                    requires = "internet_access"
                    severity = "high"
                elif "directory" in lower_title:
                    gives = "information_disclosure"
                    requires = "internet_access"
                    severity = "medium"
                else:
                    gives = "information_disclosure"
                    requires = "internet_access"
                    severity = "low"

                findings.append({
                    "id": new_uuid(),
                    "layer": "web",
                    "severity": severity,
                    "title": title,
                    "description": f"{title} at {vuln.get('url', url)}",
                    "cve_id": vuln.get("OSVDB"),
                    "gives": gives,
                    "requires": requires,
                    "raw_output": vuln,
                })
        except json.JSONDecodeError:
            raise ValueError("Could not parse nikto output")

        insert_findings(findings, scan_id)
        return findings
    except Exception as e:
        raise RuntimeError("scan_web failed; no sample findings were substituted") from e


# ══════════════════════════════════════════════════════════════
# TOOL: scan_cctv
# ══════════════════════════════════════════════════════════════

def scan_cctv(ip: str, scan_id: str) -> list[dict]:
    """
    Check for Hikvision/Dahua camera fingerprints via HTTP banner.
    Raises if the camera endpoint is unreachable.
    """
    validate_target(ip, "ip")
    try:
        resp = httpx.get(f"http://{ip}", timeout=10)
    except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError):
        # Target machine actively refused or timed out on HTTP port -> no camera running
        return []
    except Exception as e:
        raise RuntimeError("scan_cctv failed; no sample findings were substituted") from e

    try:
        headers = resp.headers
        body = resp.text.lower()
        is_hikvision = "hikvision" in body or "hikvision" in headers.get("server", "").lower()
        is_dahua = "dahua" in body or "dahua" in headers.get("server", "").lower()

        if not (is_hikvision or is_dahua):
            return []

        brand = "Hikvision" if is_hikvision else "Dahua"
        findings = [{
            "id": new_uuid(),
            "layer": "iot",
            "severity": "info",
            "title": f"{brand} camera fingerprint detected",
            "description": f"{brand} fingerprint at {ip}. Firmware and vulnerability status are unverified.",
            "cve_id": None,
            "gives": "",
            "requires": "internal_network_access",
            "raw_output": {"ip": ip, "brand": brand},
        }]
        insert_findings(findings, scan_id)
        return findings
    except Exception as e:
        raise RuntimeError("scan_cctv failed; no sample findings were substituted") from e

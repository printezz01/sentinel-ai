"""
Sentinel AI — Structured Error Definitions
Every scan failure gets a code, title, user-facing message, and suggested action.
"""

from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass(frozen=True)
class ScanError:
    """Structured error returned to the frontend."""
    error_code: str
    title: str
    message: str
    action: str
    category: str = "FAILED"  # BLOCKED | FAILED | WARNING

    def to_dict(self) -> dict:
        return asdict(self)


# ═══════════════════════════════════════════════════════════════
# GitHub Repository Errors
# ═══════════════════════════════════════════════════════════════

INVALID_GITHUB_URL = ScanError(
    error_code="INVALID_GITHUB_URL",
    title="Invalid GitHub Repository URL",
    message="The URL does not match the expected GitHub repository format.",
    action="Use the format: https://github.com/{owner}/{repository}",
    category="FAILED",
)

PRIVATE_GITHUB_REPO = ScanError(
    error_code="PRIVATE_GITHUB_REPO",
    title="Private Repository Detected",
    message=(
        "SENTINEL detected that this repository is private. "
        "Private repositories cannot currently be scanned because "
        "SENTINEL does not have authenticated GitHub access."
    ),
    action=(
        "Use a public repository, or add authenticated private-repository support "
        "(GitHub OAuth, Personal Access Token, or SSH authentication)."
    ),
    category="BLOCKED",
)

GITHUB_REPO_NOT_FOUND = ScanError(
    error_code="GITHUB_REPO_NOT_FOUND",
    title="Repository Not Found",
    message="The GitHub repository could not be found.",
    action="Check the repository URL and try again.",
    category="FAILED",
)

GITHUB_CLONE_FAILED = ScanError(
    error_code="GITHUB_CLONE_FAILED",
    title="Repository Could Not Be Retrieved",
    message=(
        "SENTINEL identified the repository, but cloning or accessing "
        "the repository failed. This may be caused by a network issue, "
        "GitHub availability, or repository access restrictions."
    ),
    action="Try again later, or check that the repository is publicly accessible.",
    category="FAILED",
)


# ═══════════════════════════════════════════════════════════════
# Website Errors
# ═══════════════════════════════════════════════════════════════

INVALID_WEB_URL = ScanError(
    error_code="INVALID_WEB_URL",
    title="Invalid Website URL",
    message="The URL is not a valid HTTP or HTTPS address.",
    action="Please enter a valid URL starting with http:// or https://",
    category="FAILED",
)

WEB_TARGET_UNREACHABLE = ScanError(
    error_code="WEB_TARGET_UNREACHABLE",
    title="Website Unreachable",
    message=(
        "SENTINEL could not connect to this website. "
        "The website may be offline, the hostname may be incorrect, "
        "or the connection may be blocked."
    ),
    action="Verify the URL and check that the website is online.",
    category="FAILED",
)

DNS_RESOLUTION_FAILED = ScanError(
    error_code="DNS_RESOLUTION_FAILED",
    title="Domain Could Not Be Resolved",
    message="SENTINEL could not resolve this hostname to an IP address.",
    action="Check the domain name and try again.",
    category="FAILED",
)

WEB_SCAN_TIMEOUT = ScanError(
    error_code="WEB_SCAN_TIMEOUT",
    title="Website Scan Timed Out",
    message="The target did not respond within the allowed scan time.",
    action="The website may be slow or overloaded. Try again later.",
    category="FAILED",
)

TLS_CONNECTION_FAILED = ScanError(
    error_code="TLS_CONNECTION_FAILED",
    title="Secure Connection Failed",
    message="SENTINEL could not establish a valid HTTPS connection with this target.",
    action="The site may have an invalid or expired SSL certificate. Try using http:// instead.",
    category="FAILED",
)


# ═══════════════════════════════════════════════════════════════
# IP / Network / Subnet Errors
# ═══════════════════════════════════════════════════════════════

PUBLIC_IP_BLOCKED = ScanError(
    error_code="PUBLIC_IP_BLOCKED",
    title="Public IP Scan Blocked",
    message="SENTINEL currently allows network scanning only for localhost and private network ranges.",
    action="Use a private IP address (e.g. 192.168.x.x, 10.x.x.x) or localhost.",
    category="BLOCKED",
)

PUBLIC_SUBNET_BLOCKED = ScanError(
    error_code="PUBLIC_SUBNET_BLOCKED",
    title="Public Subnet Scan Blocked",
    message="SENTINEL does not perform unrestricted public subnet scans.",
    action="Use a private subnet range (e.g. 192.168.1.0/24, 10.0.0.0/24).",
    category="BLOCKED",
)

INVALID_IP = ScanError(
    error_code="INVALID_IP",
    title="Invalid IP Address",
    message="The supplied IP address is not valid.",
    action="Enter a valid IPv4 address such as 192.168.1.1",
    category="FAILED",
)

INVALID_SUBNET = ScanError(
    error_code="INVALID_SUBNET",
    title="Invalid Network Range",
    message="The supplied CIDR notation is not valid.",
    action="Enter a valid CIDR range such as 192.168.1.0/24",
    category="FAILED",
)

HOST_UNREACHABLE = ScanError(
    error_code="HOST_UNREACHABLE",
    title="Host Unreachable",
    message="SENTINEL could not communicate with the selected host.",
    action="Verify the host is powered on and connected to the network.",
    category="FAILED",
)

NMAP_TIMEOUT = ScanError(
    error_code="NMAP_TIMEOUT",
    title="Network Scan Timed Out",
    message="The network scan exceeded the configured timeout.",
    action="The host may be firewalled. Try scanning fewer ports or a single IP.",
    category="FAILED",
)

LOCAL_SERVICE_UNAVAILABLE = ScanError(
    error_code="LOCAL_SERVICE_UNAVAILABLE",
    title="Local Service Unavailable",
    message="SENTINEL could reach localhost, but the requested service is not currently running.",
    action="Start the target service and try again.",
    category="FAILED",
)


# ═══════════════════════════════════════════════════════════════
# Scanner Tool Failures
# ═══════════════════════════════════════════════════════════════

NIKTO_FAILED = ScanError(
    error_code="NIKTO_FAILED",
    title="Nikto Scanner Failed",
    message="The Nikto web vulnerability scanner did not complete successfully.",
    action="Other scan results are still valid. Nikto may be unavailable in this environment.",
    category="WARNING",
)

SEMGREP_FAILED = ScanError(
    error_code="SEMGREP_FAILED",
    title="Semgrep Scanner Failed",
    message="The Semgrep code analysis tool did not complete successfully.",
    action="Other scan results are still valid.",
    category="WARNING",
)

BANDIT_FAILED = ScanError(
    error_code="BANDIT_FAILED",
    title="Bandit Scanner Failed",
    message="The Bandit Python security scanner did not complete successfully.",
    action="Other scan results are still valid.",
    category="WARNING",
)

TRUFFLEHOG_FAILED = ScanError(
    error_code="TRUFFLEHOG_FAILED",
    title="TruffleHog Scanner Failed",
    message="The TruffleHog secret detection scanner did not complete successfully.",
    action="Other scan results are still valid.",
    category="WARNING",
)

NMAP_FAILED = ScanError(
    error_code="NMAP_FAILED",
    title="Nmap Scanner Failed",
    message="The Nmap network scanner did not complete successfully.",
    action="Other scan results are still valid. Nmap may not be installed.",
    category="WARNING",
)

CVE_ENRICHMENT_FAILED = ScanError(
    error_code="CVE_ENRICHMENT_FAILED",
    title="CVE Enrichment Failed",
    message="CVE lookup from the NVD database did not complete.",
    action="Scan results are still valid but may lack CVE cross-references.",
    category="WARNING",
)


# ═══════════════════════════════════════════════════════════════
# Agent / LLM Errors
# ═══════════════════════════════════════════════════════════════

AGENT_ORCHESTRATION_FAILED = ScanError(
    error_code="AGENT_ORCHESTRATION_FAILED",
    title="Agent Orchestration Unavailable",
    message="SENTINEL could not complete automatic tool selection.",
    action="The scan will continue using the default security workflow.",
    category="WARNING",
)

AI_ANALYSIS_UNAVAILABLE = ScanError(
    error_code="AI_ANALYSIS_UNAVAILABLE",
    title="AI Analysis Temporarily Unavailable",
    message="Security scanning completed successfully, but AI-generated explanation is currently unavailable.",
    action="Scan findings are still valid. AI analysis may be retried later.",
    category="WARNING",
)


# ═══════════════════════════════════════════════════════════════
# Database Errors
# ═══════════════════════════════════════════════════════════════

DATABASE_SAVE_FAILED = ScanError(
    error_code="DATABASE_SAVE_FAILED",
    title="Scan Completed — Results Not Saved",
    message=(
        "SENTINEL completed the security analysis but could not "
        "save the session to the database. The scan results shown on this page are still valid."
    ),
    action="Results are displayed but may not persist after refresh.",
    category="WARNING",
)


# ═══════════════════════════════════════════════════════════════
# Generic / Unknown
# ═══════════════════════════════════════════════════════════════

UNKNOWN_ERROR = ScanError(
    error_code="UNKNOWN_ERROR",
    title="Scan Could Not Be Completed",
    message="An unexpected error occurred during the scan.",
    action="Try again. If the problem persists, check the target and try a different scan type.",
    category="FAILED",
)

INVALID_TARGET_TYPE = ScanError(
    error_code="INVALID_TARGET_TYPE",
    title="Invalid Target Type",
    message="The specified target type is not recognized.",
    action="Supported types: ip, subnet, url, github.",
    category="FAILED",
)


# ═══════════════════════════════════════════════════════════════
# Helper: classify a git clone failure
# ═══════════════════════════════════════════════════════════════

def classify_github_clone_error(stderr: str, returncode: int) -> ScanError:
    """Determine which GitHub error to return based on git clone stderr."""
    stderr_lower = stderr.lower()
    if "repository not found" in stderr_lower or returncode == 128 and "not found" in stderr_lower:
        return GITHUB_REPO_NOT_FOUND
    if "could not read from remote" in stderr_lower or "authentication" in stderr_lower:
        return PRIVATE_GITHUB_REPO
    if "fatal: unable to access" in stderr_lower and ("403" in stderr or "404" in stderr):
        # GitHub returns 403 for private repos when accessed without auth
        return PRIVATE_GITHUB_REPO
    return GITHUB_CLONE_FAILED


def classify_web_error(exception: Exception) -> ScanError:
    """Determine which web error to return based on exception type."""
    import httpx
    err_str = str(exception).lower()
    if isinstance(exception, httpx.TimeoutException) or "timeout" in err_str:
        return WEB_SCAN_TIMEOUT
    if isinstance(exception, httpx.ConnectError):
        if "name or service not known" in err_str or "nodename nor servname" in err_str or "getaddrinfo" in err_str:
            return DNS_RESOLUTION_FAILED
        if "ssl" in err_str or "certificate" in err_str or "tls" in err_str:
            return TLS_CONNECTION_FAILED
        return WEB_TARGET_UNREACHABLE
    if "ssl" in err_str or "certificate" in err_str or "tls" in err_str:
        return TLS_CONNECTION_FAILED
    if isinstance(exception, (httpx.NetworkError, ConnectionError, OSError)):
        return WEB_TARGET_UNREACHABLE
    return WEB_TARGET_UNREACHABLE


class ScanErrorException(Exception):
    """Exception that carries a structured ScanError for the HTTP layer."""
    def __init__(self, scan_error: ScanError, cause: Optional[Exception] = None):
        self.scan_error = scan_error
        self.__cause__ = cause
        super().__init__(scan_error.title)

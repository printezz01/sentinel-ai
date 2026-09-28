"""Target policy shared by API and scanner tools."""
import ipaddress
from urllib.parse import urlparse
from fastapi import HTTPException
from app.config import ALLOWED_IP_RANGES, ALLOWED_GITHUB_REPOS, ALLOWED_URLS

def _is_local_ip(ip_str: str) -> bool:
    """Check if an IP is localhost or in a private range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_loopback or any(addr in ipaddress.ip_network(r) for r in ALLOWED_IP_RANGES if "/" in r)
    except ValueError:
        return ip_str in ("localhost", "127.0.0.1")


def _is_local_subnet(subnet_str: str) -> bool:
    """Check if a subnet is in allowed private ranges."""
    try:
        net = ipaddress.ip_network(subnet_str, strict=False)
        return any(net.version == allowed.version and net.subnet_of(allowed) for allowed in (ipaddress.ip_network(r) for r in ALLOWED_IP_RANGES if "/" in r))
    except ValueError:
        return False


def _is_allowed_url(url: str) -> bool:
    """Check if a URL points to localhost or an allowed domain."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if not (parsed.scheme in ("http", "https") and not parsed.username and not parsed.password):
        return False
    if _is_local_ip(host):
        return True
    for allowed in ALLOWED_URLS:
        allowed_host = urlparse(allowed).hostname or allowed.replace("https://", "").replace("http://", "").split("/")[0]
        if host.lower() == allowed_host.lower():
            return True
    return False


def _normalize_github_url(url: str) -> str:
    cleaned = url.strip().rstrip("/").removesuffix(".git").lower()
    if not cleaned.startswith(("http://", "https://")):
        cleaned = f"https://{cleaned}"
    return cleaned


def _is_allowed_github(url: str) -> bool:
    """Check if a GitHub URL is in the whitelist."""
    norm_url = _normalize_github_url(url)
    for allowed in ALLOWED_GITHUB_REPOS:
        if norm_url == _normalize_github_url(allowed):
            return True
    return False


def validate_target(target: str, target_type: str) -> None:
    """Validate that a target is safe to scan. Raises HTTPException if not."""
    if target_type == "ip":
        if not _is_local_ip(target):
            raise HTTPException(
                status_code=400,
                detail=f"Rejected: '{target}' is not a safe local target. Only localhost and private IPs are allowed."
            )
    elif target_type == "subnet":
        if not _is_local_subnet(target):
            raise HTTPException(
                status_code=400,
                detail=f"Rejected: '{target}' is not a safe private subnet."
            )
    elif target_type == "url":
        if not _is_allowed_url(target):
            raise HTTPException(
                status_code=400,
                detail=f"Rejected: '{target}' is not a safe local URL. Only localhost URLs are allowed."
            )
    elif target_type == "github":
        if not _is_allowed_github(target):
            raise HTTPException(
                status_code=400,
                detail=f"Rejected: '{target}' is not in the allowed GitHub repos whitelist. Allowed: {', '.join(ALLOWED_GITHUB_REPOS)}"
            )
    else:
        raise HTTPException(status_code=400, detail=f"Invalid target_type: {target_type}")



"""Target policy shared by API and scanner tools."""
import ipaddress
import re
from urllib.parse import urlparse
from fastapi import HTTPException
from app.config import ALLOWED_IP_RANGES

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


def validate_web_target(url: str) -> bool:
    """Accept structurally valid HTTP(S) URLs without a domain allowlist."""
    try:
        if not url or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in url) or "\\" in url:
            return False
        parsed = urlparse(url)
        host = parsed.hostname
        if parsed.scheme not in {"http", "https"} or not host or parsed.username is not None or parsed.password is not None:
            return False
        # Accessing port also rejects malformed and out-of-range ports.
        if parsed.port is not None and parsed.port == 0:
            return False
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            ascii_host = host.encode("idna").decode("ascii").rstrip(".")
            return len(ascii_host) <= 253 and all(
                re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in ascii_host.split(".")
            )
    except (ValueError, UnicodeError):
        return False


def validate_github_repo(url: str) -> bool:
    """Accept repository roots; the existing clone determines availability."""
    if not validate_web_target(url):
        return False
    parsed = urlparse(url)
    if parsed.netloc.lower() != "github.com" or parsed.query or parsed.fragment:
        return False
    parts = parsed.path.strip("/").split("/")
    if len(parts) != 2:
        return False
    owner, repo = parts
    repo = repo.removesuffix(".git")
    return bool(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?", owner)
        and re.fullmatch(r"[A-Za-z0-9_.-]+", repo)
        and repo not in {".", ".."}
    )


def validate_target(target: str, target_type: str) -> None:
    """Validate that a target is safe to scan. Raises HTTPException if not."""
    if target_type == "ip":
        if not _is_local_ip(target):
            raise HTTPException(
                status_code=400,
                detail="Public IP scanning is disabled"
            )
    elif target_type == "subnet":
        if not _is_local_subnet(target):
            raise HTTPException(
                status_code=400,
                detail="Public subnet scanning is disabled"
            )
    elif target_type == "url":
        if not validate_web_target(target):
            raise HTTPException(
                status_code=400,
                detail="Invalid website URL"
            )
    elif target_type == "github":
        if not validate_github_repo(target):
            raise HTTPException(
                status_code=400,
                detail="Invalid GitHub repository URL"
            )
    else:
        raise HTTPException(status_code=400, detail=f"Invalid target_type: {target_type}")



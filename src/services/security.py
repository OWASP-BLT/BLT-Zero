import hashlib
import re
from datetime import datetime


def normalize_domain(input: str) -> str:
    """Normalize domain name to lowercase and trimmed."""
    return input.strip().lower()


def get_client_ip(req) -> str:
    """Get client IP from CF-Connecting-IP header."""
    return req.headers.get("CF-Connecting-IP", "0.0.0.0")


def minute_bucket_iso(date: datetime = None) -> str:
    """Generate a time bucket string for rate limiting (minute precision)."""
    if date is None:
        date = datetime.utcnow()
    
    return date.strftime("%Y-%m-%dT%H:%M")


async def sha256_hex(data: bytes) -> str:
    """Calculate SHA-256 hash and return as hex string."""
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# SSRF protection
# ---------------------------------------------------------------------------

# Reject private / loopback / link-local hosts to prevent SSRF.
_PRIVATE_HOST_RE = re.compile(
    r"^(localhost"
    r"|127\."
    r"|10\."
    r"|172\.(1[6-9]|2[0-9]|3[01])\."
    r"|192\.168\."
    r"|169\.254\."
    r"|0\."
    r"|::1"
    r"|fc[0-9a-f]{2}:"          # IPv6 unique local fc00::/7
    r"|fd[0-9a-f]{2}:"          # IPv6 unique local fd00::/8
    r"|fe[89ab][0-9a-f]:)",     # IPv6 link-local fe80::/10
    re.IGNORECASE,
)


def is_private_host(host: str) -> bool:
    """Return True when *host* resolves to a private / loopback / link-local address."""
    return bool(_PRIVATE_HOST_RE.match(host))

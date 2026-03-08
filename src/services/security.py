import hashlib
from datetime import datetime


def normalize_domain(input: str) -> str:
    """Normalize domain name to lowercase and trimmed."""
    return input.strip().lower()


def get_client_ip(req) -> str:
    """Get client IP from CF-Connecting-IP header."""
    ip = req.headers.get("CF-Connecting-IP", "")
    if ip:
        return ip
    # Fallback chain for non-CF environments
    forwarded_for = req.headers.get("X-Forwarded-For", "").split(",")[0].strip()
    if forwarded_for:
        return forwarded_for
    return "0.0.0.0"  # last-resort, clearly indicates unknown


def minute_bucket_iso(date: datetime = None) -> str:
    """Generate a time bucket string for rate limiting (minute precision)."""
    if date is None:
        date = datetime.utcnow()
    
    return date.strftime("%Y-%m-%dT%H:%M")


async def sha256_hex(data: bytes) -> str:
    """Calculate SHA-256 hash and return as hex string."""
    return hashlib.sha256(data).hexdigest()


def turnstile_enabled(env) -> bool:
    """Check if Turnstile verification is enabled."""
    return (
        env.DISABLE_TURNSTILE != "true" 
        and hasattr(env, "TURNSTILE_SITE_KEY") 
        and env.TURNSTILE_SITE_KEY
        and hasattr(env, "TURNSTILE_SECRET")
        and env.TURNSTILE_SECRET
    )


async def verify_turnstile(env, token: str, ip: str) -> bool:
    """Verify Turnstile token with Cloudflare."""
    # If disabled, always pass
    if not turnstile_enabled(env):
        return True
    
    # Import fetch from js module
    from js import fetch, FormData
    
    form = FormData.new()
    form.append("secret", env.TURNSTILE_SECRET)
    form.append("response", token)
    form.append("remoteip", ip)
    
    resp = await fetch(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        method="POST",
        body=form
    )
    
    if not resp.ok:
        return False
    
    json_data = await resp.json()
    return bool(json_data.get("success", False))


def calculate_backoff_seconds(failure_count: int) -> int:
    """Calculate exponential backoff time in seconds based on failure count.
    
    Returns:
        - 0 failures: 0 seconds
        - 1 failure: 2 seconds
        - 2 failures: 4 seconds
        - 3 failures: 8 seconds
        - 4 failures: 16 seconds
        - 5+ failures: 60 seconds (1 minute cap)
    """
    if failure_count <= 0:
        return 0
    
    if failure_count >= 5:
        return 60
    
    return 2 ** failure_count

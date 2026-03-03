import hashlib
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

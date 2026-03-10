import hashlib
import hmac
import secrets
import time
import base64
import re
from datetime import datetime


def normalize_domain(input: str) -> str:
    """Normalize domain name to lowercase and trimmed."""
    return input.strip().lower()


def validate_domain(domain: str) -> bool:
    """
    Validate domain format (RFC compliant).
    - Check domain length (max 253 chars)
    - Check label length (max 63 chars per label)
    - Validate characters (alphanumeric, hyphens, dots)
    - Prevent obviously invalid domains
    """
    if not domain or not isinstance(domain, str):
        return False
    
    # Remove trailing dot if present (FQDN)
    domain = domain.rstrip('.')
    
    # Check total length (RFC 1035)
    if len(domain) > 253:
        return False
    
    # Check minimum length
    if len(domain) < 1:
        return False
    
    # Split into labels
    labels = domain.split('.')
    
    # Must have at least one label (though typically 2+ for valid domains)
    if len(labels) < 1:
        return False
    
    # Validate each label
    for label in labels:
        # Empty label
        if not label:
            return False
        
        # Label length (RFC 1035: max 63 chars)
        if len(label) > 63:
            return False
        
        # Label must not start or end with hyphen
        if label.startswith('-') or label.endswith('-'):
            return False
        
        # Label must contain only alphanumeric and hyphens
        if not re.match(r'^[a-z0-9-]+$', label, re.IGNORECASE):
            return False
    
    # Prevent obviously invalid domains
    invalid_patterns = [
        'localhost',
        'example.com',
        'example.org',
        'test.com',
        '..',
    ]
    
    domain_lower = domain.lower()
    for pattern in invalid_patterns:
        if pattern in domain_lower:
            return False
    
    return True


def validate_email(email: str) -> bool:
    """
    Validate email address format.
    - Basic RFC 5322 compliant pattern
    - Length checks
    - Basic deliverability checks (format only, not actual SMTP)
    """
    if not email or not isinstance(email, str):
        return False
    
    # Remove whitespace
    email = email.strip()
    
    # Length check (reasonable email length)
    if len(email) < 3 or len(email) > 320:  # RFC 5321: 320 chars max
        return False
    
    # Basic RFC 5322 pattern
    # This is a simplified pattern - full RFC 5322 is extremely complex
    email_pattern = re.compile(
        r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    )
    
    if not email_pattern.match(email):
        return False
    
    # Split into local and domain parts
    try:
        local, domain = email.rsplit('@', 1)
    except ValueError:
        return False
    
    # Local part checks
    if len(local) > 64:  # RFC 5321
        return False
    
    if not local or local.startswith('.') or local.endswith('.'):
        return False
    
    if '..' in local:
        return False
    
    # Domain part checks (reuse domain validation)
    if not validate_domain(domain):
        return False
    
    # Prevent common invalid patterns
    invalid_domains = ['example.com', 'test.com', 'localhost']
    if any(domain.lower().endswith(invalid) for invalid in invalid_domains):
        return False
    
    return True


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


def generate_csrf_token(env) -> str:
    """Generate CSRF token with timestamp and HMAC signature."""
    # Use CSRF_SECRET from env, fallback to a warning if not set
    secret = getattr(env, "CSRF_SECRET", "INSECURE_DEFAULT_SECRET")
    
    # Token format: timestamp:nonce:hmac
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(16)
    
    # Create HMAC signature
    message = f"{timestamp}:{nonce}"
    signature = hmac.new(
        secret.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    # Combine and encode
    token = f"{timestamp}:{nonce}:{signature}"
    return base64.urlsafe_b64encode(token.encode('utf-8')).decode('utf-8')


def validate_csrf_token(env, token: str, max_age_seconds: int = 3600) -> bool:
    """Validate CSRF token signature and age."""
    if not token:
        return False
    
    try:
        # Decode token
        decoded = base64.urlsafe_b64decode(token.encode('utf-8')).decode('utf-8')
        parts = decoded.split(':')
        
        if len(parts) != 3:
            return False
        
        timestamp_str, nonce, received_signature = parts
        timestamp = int(timestamp_str)
        
        # Check age
        current_time = int(time.time())
        if current_time - timestamp > max_age_seconds:
            return False
        
        # Verify signature
        secret = getattr(env, "CSRF_SECRET", "INSECURE_DEFAULT_SECRET")
        message = f"{timestamp_str}:{nonce}"
        expected_signature = hmac.new(
            secret.encode('utf-8'),
            message.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        
        # Use constant-time comparison
        return secrets.compare_digest(received_signature, expected_signature)
    
    except Exception:
        return False


import json
import base64
import re
from datetime import datetime
from urllib.parse import urlparse
from workers import WorkerEntrypoint, Response
from js import URL

from services.templates import submit_page
from services.email import send_email

# ----------------------------
# Utilities (self-contained)
# ----------------------------
def html_response(body: str, status: int = 200):
    return Response(body, status=status, headers={"content-type": "text/html; charset=utf-8"})

def sha256_hex(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()

def get_client_ip(request):
    try:
        cf = request.headers.get("CF-Connecting-IP") or request.headers.get("cf-connecting-ip")
        if cf: return cf
    except Exception: pass
    try:
        xff = request.headers.get("X-Forwarded-For") or request.headers.get("x-forwarded-for")
        if xff: return xff.split(",")[0].strip()
    except Exception: pass
    try:
        ra = request.headers.get("Remote-Addr") or request.headers.get("remote-addr")
        if ra: return ra
    except Exception: pass
    return "0.0.0.0"

def minute_bucket_iso(dt: datetime) -> str: return dt.strftime("%Y-%m-%dT%H:%M")
def hour_bucket_iso(dt: datetime) -> str: return dt.strftime("%Y-%m-%dT%H")
def day_bucket_iso(dt: datetime) -> str: return dt.strftime("%Y-%m-%d")

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

# ----------------------------
# In-memory rate limiting
# ----------------------------
_RL_COUNTERS = {}
_RL_SETS = {}

def _incr_counter(key: str) -> int:
    _RL_COUNTERS[key] = _RL_COUNTERS.get(key, 0) + 1
    return _RL_COUNTERS[key]

def _get_set(key: str):
    s = _RL_SETS.get(key)
    if s is None:
        s = set()
        _RL_SETS[key] = s
    return s

def _limit_exceeded(current: int, limit: int) -> bool:
    return current > limit

def _check_rate_limits(env, ip: str, org_email: str, url_host: str):
    now = datetime.utcnow()
    b_min, b_hr, b_day = minute_bucket_iso(now), hour_bucket_iso(now), day_bucket_iso(now)

    ip_min = int(getattr(env, "RL_IP_PER_MINUTE", "5"))
    ip_hr = int(getattr(env, "RL_IP_PER_HOUR", "50"))
    ip_day = int(getattr(env, "RL_IP_PER_DAY", "200"))
    em_hr = int(getattr(env, "RL_EMAIL_PER_HOUR", "10"))
    emd_hr = int(getattr(env, "RL_EMAIL_DOMAIN_PER_HOUR", "20"))
    de_iphr = int(getattr(env, "RL_DISTINCT_EMAILS_PER_IP_PER_HOUR", "10"))
    glob_min = int(getattr(env, "RL_GLOBAL_PER_MINUTE", "30"))

    org_email_lc = org_email.lower()
    email_domain = org_email_lc.split("@")[-1] if "@" in org_email_lc else "invalid"

    if _limit_exceeded(_incr_counter(f"g:m:{b_min}"), glob_min): return "global rate limit exceeded (per minute)"
    if _limit_exceeded(_incr_counter(f"ip:{ip}:m:{b_min}"), ip_min): return "ip rate limit exceeded (per minute)"
    if _limit_exceeded(_incr_counter(f"ip:{ip}:h:{b_hr}"), ip_hr): return "ip rate limit exceeded (per hour)"
    if _limit_exceeded(_incr_counter(f"ip:{ip}:d:{b_day}"), ip_day): return "ip rate limit exceeded (per day)"
    if _limit_exceeded(_incr_counter(f"email:{org_email_lc}:h:{b_hr}"), em_hr): return "recipient email rate limit exceeded (per hour)"
    if _limit_exceeded(_incr_counter(f"edomain:{email_domain}:h:{b_hr}"), emd_hr): return "recipient email domain rate limit exceeded (per hour)"

    s = _get_set(f"ip:{ip}:distinct_emails:h:{b_hr}")
    s.add(org_email_lc)
    if len(s) > de_iphr: return "too many different recipient emails from this IP (per hour)"

    c = _incr_counter(f"urlhost:{ip}:{url_host}:h:{b_hr}")
    if c > 40: return "too many submissions to the same host from this IP (per hour)"

    return None

# ----------------------------
# Worker Entrypoint
# ----------------------------
class Default(WorkerEntrypoint):
    async def fetch(self, request):
        env = self.env
        url = URL.new(request.url)

        # Home page
        if request.method == "GET" and url.pathname == "/":
            try:
                html = submit_page({
                    "maxFiles": int(getattr(env, "ZIP_MAX_FILES", "5")),
                    "maxTotalBytes": int(getattr(env, "ZIP_MAX_TOTAL_BYTES", "5242880"))
                })
                return html_response(html)
            except Exception as e:
                return Response.json({"error": f"Failed to load UI template: {e}"}, status=500)

        # ZIP-only submission
        if request.method == "POST" and url.pathname == "/submit":
            ip = get_client_ip(request)

            try:
                payload = await request.json()
            except Exception:
                return Response.json({"error": "invalid json"}, status=400)

            if not isinstance(payload, dict):
                return Response.json({"error": "json object required"}, status=400)

            org_email = str(payload.get("org_email", "")).strip()
            report = payload.get("report", {}) or {}
            if not isinstance(report, dict):
                return Response.json({"error": "report must be an object"}, status=400)
            
            # Extract the new payload fields
            zip_b64 = payload.get("zip_content_b64")
            password = payload.get("password")

            if not org_email or not EMAIL_RE.match(org_email):
                return Response.json({"error": "valid org_email required"}, status=400)

            url_val = str(report.get("url", "")).strip()
            description = str(report.get("description", "")).strip()
            markdown = str(report.get("markdown", "")) if report.get("markdown") else ""

            if not url_val or not description:
                return Response.json({"error": "url and description required"}, status=400)
                
            if not zip_b64 or not password:
                return Response.json({"error": "missing encrypted zip payload or password"}, status=400)

            try:
                url_host = urlparse(url_val).netloc.lower()
            except Exception:
                url_host = "invalid"

            err = _check_rate_limits(env, ip, org_email, url_host)
            if err:
                return Response.json({"error": err}, status=429)

            max_report_chars = int(getattr(env, "MAX_REPORT_CHARS", "20000"))
            if len(description) + len(markdown) > max_report_chars:
                return Response.json({"error": "report text too large"}, status=400)

            # Process the pre-encrypted ZIP instead of creating one
            try:
                zip_bytes = base64.b64decode(zip_b64, validate=True)
            except Exception:
                return Response.json({"error": "invalid base64 encoding for zip"}, status=400)

            max_total_bytes = int(getattr(env, "ZIP_MAX_TOTAL_BYTES", "5242880"))
            if len(zip_bytes) > max_total_bytes:
                return Response.json({"error": f"total size exceeds {max_total_bytes} bytes"}, status=400)

            enc_used = "aes256"
            artifact_hash = sha256_hex(zip_bytes)

            subject = f"BLT‑Zero ZIP Report — {artifact_hash[:12]}"
            disclaimers = {
                "aes256": "ZIP encryption: AES‑256 (Client-Side).",
                "none":   "WARNING: Runtime lacks ZIP encryption; sending UNENCRYPTED ZIP. Handle with extreme care.",
            }
            body_lines = [
                f"Recipient: {org_email}",
                f"Target URL: {url_val}",
                "",
                "Attached is the report as a single ZIP archive.",
                f"Password (store safely): {password}",
                "",
                disclaimers.get(enc_used, "ZIP encryption: unknown"),
                "",
                f"Artifact SHA-256: {artifact_hash}",
            ]
            body = "\n".join(body_lines)

            try:
                await send_email(
                    env,
                    org_email,
                    subject,
                    body,
                    attachment_name=f"blt-zero-report-{artifact_hash[:12]}.zip",
                    attachment_data=zip_bytes,
                    attachment_content_type="application/zip",
                )
            except Exception as e:
                return Response.json({"error": f"email delivery failed: {e}"}, status=502)

            return Response.json({
                "ok": True,
                "artifact_hash": artifact_hash,
                "encryption_used": enc_used
            })

        # 404
        return Response("Not found", status=404)
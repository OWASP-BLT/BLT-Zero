import json
import secrets
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from workers import WorkerEntrypoint, Response
from js import URL, crypto as js_crypto

from libs.utils import html_response
from services.db import get_domain, upsert_domain, insert_submission, rate_limit_hit
from services.email import send_email, sync_points
from services.security import (
    normalize_domain,
    validate_domain,
    validate_email,
    get_client_ip,
    minute_bucket_iso,
    sha256_hex,
    verify_turnstile,
    turnstile_enabled,
    generate_csrf_token,
    validate_csrf_token
)
from services.templates import (
    submit_page,
    docs_security,
    docs_org_onboarding,
    docs_decrypt,
    admin_onboard_page,
    onboarding_email_body
)


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        """Main fetch handler for the worker."""
        env = self.env
        ctx = self.ctx
        
        url = URL.new(request.url)
        ts_enabled = turnstile_enabled(env)
        
        # UI - Home page
        if request.method == "GET" and url.pathname == "/":
            # Parse query parameters
            query_params = parse_qs(urlparse(request.url).query)
            domain_prefill_raw = query_params.get("domain", [""])[0]
            
            # Validate and sanitize domain prefill (don't reject, just ignore invalid)
            domain_prefill = ""
            if domain_prefill_raw:
                normalized = normalize_domain(domain_prefill_raw)
                if validate_domain(normalized):
                    domain_prefill = normalized
            
            # Generate CSRF token
            csrf_token = generate_csrf_token(env)
            
            return html_response(
                submit_page({
                    "domainPrefill": domain_prefill,
                    "turnstileSiteKey": env.TURNSTILE_SITE_KEY if ts_enabled else "",
                    "maxFiles": 3,
                    "maxTotalBytes": int(getattr(env, "MAX_UPLOAD_BYTES", "3145728")),
                    "csrfToken": csrf_token,
                })
            )
        
        # Docs
        if request.method == "GET" and url.pathname == "/docs/security":
            return html_response(docs_security())
        
        if request.method == "GET" and url.pathname == "/docs/org-onboarding":
            return html_response(docs_org_onboarding(env.APP_ORIGIN))
        
        if request.method == "GET" and url.pathname == "/docs/decrypt":
            return html_response(docs_decrypt())
        
        # Admin page
        if request.method == "GET" and url.pathname == "/admin/onboard":
            return html_response(
                admin_onboard_page(env.TURNSTILE_SITE_KEY if ts_enabled else "")
            )
        
        # Admin onboard POST
        if request.method == "POST" and url.pathname == "/admin/onboard":
            ip = get_client_ip(request)
            
            try:
                payload = await request.json()
            except:
                return Response.json({"error": "invalid json"}, status=400)
            
            token = str(payload.get("admin_token", ""))
            turnstile_token = str(payload.get("turnstile_token", ""))
            
            if not token:
                return Response.json({"error": "admin_token required"}, status=400)
            if ts_enabled and not turnstile_token:
                return Response.json({"error": "turnstile_token required"}, status=400)
            
            # Admin auth
            admin_token = getattr(env, "ADMIN_TOKEN", None)
            if not admin_token or token != admin_token:
                return Response.json({"error": "unauthorized"}, status=401)
            
            # Turnstile verify (auto-pass if disabled)
            ok = await verify_turnstile(env, turnstile_token, ip)
            if not ok:
                return Response.json({"error": "turnstile failed"}, status=403)
            
            domain = normalize_domain(payload.get("domain", ""))
            org_email = str(payload.get("org_email", "")).strip()
            key_id = str(payload.get("key_id", "")).strip()
            public_key_jwk = str(payload.get("public_key_jwk", "")).strip()
            send_onboarding_email = bool(payload.get("send_onboarding_email", False))
            
            if not domain or not org_email or not key_id or not public_key_jwk:
                return Response.json(
                    {"error": "domain, org_email, key_id, public_key_jwk required"}, status=400
                )
            
            # Basic JWK validation (shape only)
            try:
                jwk = json.loads(public_key_jwk)
                if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or not jwk.get("x") or not jwk.get("y"):
                    return Response.json({"error": "public_key_jwk must be EC P-256 JWK"}, status=400)
            except:
                return Response.json({"error": "public_key_jwk must be valid JSON"}, status=400)
            
            await upsert_domain(env, {
                "domain": domain,
                "org_email": org_email,
                "alg": "ECDH_P256_HKDF_SHA256_AESGCM",
                "key_id": key_id,
                "public_key_jwk": public_key_jwk,
                "is_active": 1,
            })
            
            email_sent = False
            if send_onboarding_email:
                subject = f"BLT-Zero Onboarding — {domain}"
                body = onboarding_email_body(env.APP_ORIGIN, domain)
                await send_email(env, org_email, subject, body)
                email_sent = True
            
            return Response.json({"ok": True, "domain": domain, "email_sent": email_sent})
        
        # Domain key fetch
        if request.method == "GET" and url.pathname == "/api/domain":
            query_params = parse_qs(urlparse(request.url).query)
            d = normalize_domain(query_params.get("domain", [""])[0])
            
            if not d:
                return Response.json({"error": "domain required"}, status=400)
            
            # Validate domain format
            if not validate_domain(d):
                return Response.json({"error": "invalid domain format"}, status=400)
            
            row = await get_domain(env, d)
            if not row or not row["is_active"]:
                return Response.json({"error": "domain not registered"}, status=404)
            
            return Response.json({
                "domain": row["domain"],
                "org_email": row["org_email"],
                "alg": row["alg"],
                "key_id": row["key_id"],
                "public_key_jwk": row["public_key_jwk"],
            })
        
        # Submit
        if request.method == "POST" and url.pathname == "/submit":
            ip = get_client_ip(request)
            bucket = minute_bucket_iso(datetime.utcnow())
            limit_key = f"ip:{ip}:{bucket}"
            
            count = await rate_limit_hit(env, limit_key, bucket)
            max_per_min = int(getattr(env, "RATE_LIMIT_PER_MINUTE", "5"))
            
            if count > max_per_min:
                return Response.json({"error": "rate limit exceeded"}, status=429)
            
            # Validate request size before parsing JSON (DoS protection)
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    size = int(content_length)
                    max_request_bytes = int(getattr(env, "MAX_REQUEST_BYTES", "10485760"))  # 10MB default
                    if size > max_request_bytes:
                        return Response.json({"error": "request too large"}, status=413)
                except ValueError:
                    return Response.json({"error": "invalid content-length"}, status=400)
            
            try:
                payload = await request.json()
            except:
                return Response.json({"error": "invalid json"}, status=400)
            
            # Validate CSRF token
            csrf_token = str(payload.get("csrf_token", ""))
            if not validate_csrf_token(env, csrf_token):
                return Response.json({"error": "invalid or expired CSRF token"}, status=403)
            
            domain = normalize_domain(payload.get("domain", ""))
            
            # Validate domain format
            if not validate_domain(domain):
                return Response.json({"error": "invalid domain format"}, status=400)
            
            username = payload.get("username")
            username = str(username).strip() if username else None
            turnstile_token = str(payload.get("turnstile_token", ""))
            encrypted_package = payload.get("encrypted_package")
            
            if not domain or not encrypted_package:
                return Response.json({"error": "domain and encrypted_package required"}, status=400)
            
            if ts_enabled and not turnstile_token:
                return Response.json({"error": "turnstile_token required"}, status=400)
            
            ok = await verify_turnstile(env, turnstile_token, ip)
            if not ok:
                return Response.json({"error": "turnstile failed"}, status=403)
            
            row = await get_domain(env, domain)
            if not row or not row["is_active"]:
                return Response.json({"error": "domain not registered"}, status=404)
            
            # Validate encrypted package shape only
            if encrypted_package.get("domain") != domain:
                return Response.json({"error": "domain mismatch"}, status=400)
            
            if (not encrypted_package.get("ciphertext_b64") or
                not encrypted_package.get("iv_b64") or
                not encrypted_package.get("salt_b64") or
                not encrypted_package.get("eph_pub_jwk")):
                return Response.json({"error": "invalid encrypted package"}, status=400)
            
            pkg_json = json.dumps(encrypted_package)
            pkg_bytes = pkg_json.encode('utf-8')
            max_bytes = int(getattr(env, "MAX_UPLOAD_BYTES", "3145728"))
            
            if len(pkg_bytes) > max_bytes:
                return Response.json({"error": "encrypted package too large"}, status=413)
            
            artifact_hash = await sha256_hex(pkg_bytes)
            
            # Generate submission ID using crypto.randomUUID()
            submission_id = str(js_crypto.randomUUID())
            
            # Email ciphertext package to org
            subject = f"BLT-Zero Encrypted Report — {domain} — {submission_id}"
            body_lines = [
                f"Encrypted vulnerability report for: {domain}",
                f"Submission ID: {submission_id}",
                f"Ciphertext SHA-256: {artifact_hash}",
                "",
                f"Decrypt guide: {env.APP_ORIGIN}/docs/decrypt",
                f"Security model: {env.APP_ORIGIN}/docs/security",
                "",
                "BLT-Zero cannot decrypt this report.",
            ]
            body = "\n".join(body_lines)
            
            await send_email(
                env,
                row["org_email"],
                subject,
                body,
                f"blt-zero-{domain}-{artifact_hash}.json",
                pkg_json
            )
            
            # Store minimal metadata
            await insert_submission(env, {
                "id": submission_id,
                "domain": domain,
                "username": username,
                "artifact_hash": artifact_hash,
            })
            
            # Points sync async
            if username:
                ctx.waitUntil(sync_points(env, username, domain))
            
            return Response.json({
                "ok": True,
                "submission_id": submission_id,
                "artifact_hash": artifact_hash
            })
        
        # 404
        return Response("Not found", status=404)

import json
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from workers import WorkerEntrypoint, Response
from js import URL, crypto as js_crypto
from libs.utils import html_response
from services.db import get_domain, upsert_domain, insert_submission, rate_limit_hit
from services.email import send_email
from services.security import (
    normalize_domain,
    get_client_ip,
    minute_bucket_iso,
    sha256_hex,
    verify_turnstile,
    turnstile_enabled
)
from services.templates import (
    submit_page,
    docs_security,
    docs_org_onboarding,
    docs_decrypt,
    admin_onboard_page,
    onboarding_email_body
)


def _to_int(value, default, *, minimum=None):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if minimum is not None and parsed < minimum:
        return default
    return parsed


# Config defaults
MAX_FILES = 3
MAX_MB = 3
RATE_LIMIT_PER_MINUTE = 5


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        env = self.env
        ctx = self.ctx

        max_files = MAX_FILES
        max_upload_bytes = _to_int(
            getattr(env, "MAX_UPLOAD_BYTES", None),
            MAX_MB * 1024 * 1024,
            minimum=1,
        )

        url = URL.new(request.url)
        ts_enabled = turnstile_enabled(env)

        # Home
        if request.method == "GET" and url.pathname == "/":
            query_params = parse_qs(urlparse(request.url).query)
            domain_prefill = query_params.get("domain", [""])[0]

            return html_response(
                submit_page({
                    "domainPrefill": domain_prefill,
                    "turnstileSiteKey": env.TURNSTILE_SITE_KEY if ts_enabled else "",
                    "maxFiles": max_files,
                    "maxTotalBytes": max_upload_bytes,
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

        # Admin onboard
        if request.method == "POST" and url.pathname == "/admin/onboard":
            ip = get_client_ip(request)

            try:
                payload = await request.json()
            except Exception:
                return Response.json({"error": "invalid json"}, status=400)

            token = str(payload.get("admin_token", ""))
            turnstile_token = str(payload.get("turnstile_token", ""))

            if not token:
                return Response.json({"error": "admin_token required"}, status=400)
            if ts_enabled and not turnstile_token:
                return Response.json({"error": "turnstile_token required"}, status=400)

            admin_token = getattr(env, "ADMIN_TOKEN", None)
            if not admin_token or token != admin_token:
                return Response.json({"error": "unauthorized"}, status=401)

            ok = await verify_turnstile(env, turnstile_token, ip)
            if not ok:
                return Response.json({"error": "turnstile failed"}, status=403)
            
            domain = normalize_domain(payload.get("domain", ""))
            org_email = str(payload.get("org_email", "")).strip()
            key_id = str(payload.get("key_id", "")).strip()
            public_key_jwk = str(payload.get("public_key_jwk", "")).strip()
            send_onboarding_email = bool(payload.get("send_onboarding_email", False))

            if not domain or not org_email or not key_id or not public_key_jwk:
                return Response.json({"error": "missing required fields"}, status=400)

            try:
                jwk = json.loads(public_key_jwk)
                if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
                    return Response.json({"error": "invalid JWK"}, status=400)
            except Exception:
                return Response.json({"error": "invalid JSON"}, status=400)

            await upsert_domain(env, {
                "domain": domain,
                "org_email": org_email,
                "alg": "ECDH_P256_HKDF_SHA256_AESGCM",
                "key_id": key_id,
                "public_key_jwk": public_key_jwk,
                "is_active": 1,
            })

            if send_onboarding_email:
                await send_email(
                    env,
                    org_email,
                    f"BLT-Zero Onboarding - {domain}",
                    onboarding_email_body(env.APP_ORIGIN, domain),
                )

            return Response.json({"ok": True})

        # Domain fetch
        if request.method == "GET" and url.pathname == "/api/domain":
            query_params = parse_qs(urlparse(request.url).query)
            d = normalize_domain(query_params.get("domain", [""])[0])

            row = await get_domain(env, d)
            if not row:
                return Response.json({"error": "not found"}, status=404)

            return Response.json(row)

        # Submit
        if request.method == "POST" and url.pathname == "/submit":
            ip = get_client_ip(request)
            bucket = minute_bucket_iso(datetime.utcnow())
            count = await rate_limit_hit(env, f"ip:{ip}:{bucket}", bucket)

            if count > RATE_LIMIT_PER_MINUTE:
                return Response.json({"error": "rate limit exceeded"}, status=429)

            try:
                payload = await request.json()
            except Exception:
                return Response.json({"error": "invalid json"}, status=400)

            domain = normalize_domain(payload.get("domain", ""))
            encrypted_package = payload.get("encrypted_package")

            if not domain or not encrypted_package:
                return Response.json({"error": "missing data"}, status=400)

            row = await get_domain(env, domain)
            if not row:
                return Response.json({"error": "domain not registered"}, status=404)

            org_email = row["org_email"]

            pkg_json = json.dumps(encrypted_package)
            pkg_bytes = pkg_json.encode("utf-8")
            if len(pkg_bytes) > max_upload_bytes:
                return Response.json({"error": "too large"}, status=413)

            artifact_hash = sha256_hex(pkg_bytes)
            submission_id = str(js_crypto.randomUUID())

            await send_email(
                env,
                org_email,
                f"BLT-Zero Report - {domain}",
                f"Submission ID: {submission_id}",
                f"{artifact_hash}.json",
                pkg_json,
            )

            await insert_submission(env, {
                "id": submission_id,
                "domain": domain,
                "artifact_hash": artifact_hash,
            })

            return Response.json({"ok": True, "submission_id": submission_id})

        return Response("Not found", status=404)
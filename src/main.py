import io
import json
import zipfile
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from workers import WorkerEntrypoint, Response
from js import URL, crypto as js_crypto, JSON as jsJSON, Uint8Array as JsUint8Array

from libs.utils import html_response
from services.db import get_domain, insert_submission, rate_limit_hit
from services.email import send_email
from services.security import (
    normalize_domain,
    get_client_ip,
    minute_bucket_iso,
    sha256_hex,
    verify_turnstile,
    turnstile_enabled
)
from services.templates import submit_page


async def _aes_gcm_encrypt(plaintext_bytes: bytes):
    """
    Encrypt plaintext using AES-256-GCM via the Web Crypto API.
    Returns (ciphertext_bytes, key_hex, iv_hex).
    """
    # Generate random 12-byte IV
    iv_arr = js_crypto.getRandomValues(JsUint8Array.new(12))

    # Build algorithm objects via JSON.parse so they arrive as native JS objects
    key_alg = jsJSON.parse('{"name":"AES-GCM","length":256}')
    key_usages = jsJSON.parse('["encrypt"]')

    aes_key = await js_crypto.subtle.generateKey(key_alg, True, key_usages)

    # Copy plaintext into a JS Uint8Array
    data_arr = JsUint8Array.new(len(plaintext_bytes))
    for i, b in enumerate(plaintext_bytes):
        data_arr[i] = b

    # Encrypt
    enc_params = jsJSON.parse('{"name":"AES-GCM"}')
    enc_params.iv = iv_arr
    ct_buffer = await js_crypto.subtle.encrypt(enc_params, aes_key, data_arr)
    ct_bytes = bytes(JsUint8Array.new(ct_buffer))

    # Export the raw key bytes
    key_raw_buffer = await js_crypto.subtle.exportKey("raw", aes_key)
    key_bytes = bytes(JsUint8Array.new(key_raw_buffer))

    return ct_bytes, key_bytes.hex(), bytes(iv_arr).hex()


def _build_zip(filename: str, data: bytes) -> bytes:
    """Return in-memory zip bytes containing a single file."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, data)
    return buf.getvalue()


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        """Main fetch handler for the worker."""
        env = self.env

        url = URL.new(request.url)
        ts_enabled = turnstile_enabled(env)

        # UI - Home page (submit form)
        if request.method == "GET" and url.pathname == "/":
            query_params = parse_qs(urlparse(request.url).query)
            domain_prefill = query_params.get("domain", [""])[0]

            return html_response(
                submit_page({
                    "domainPrefill": domain_prefill,
                    "turnstileSiteKey": env.TURNSTILE_SITE_KEY if ts_enabled else "",
                    "maxFiles": 3,
                    "maxTotalBytes": int(getattr(env, "MAX_UPLOAD_BYTES", "3145728")),
                })
            )

        # Submit encrypted report
        if request.method == "POST" and url.pathname == "/submit":
            ip = get_client_ip(request)
            bucket = minute_bucket_iso(datetime.utcnow())
            limit_key = f"ip:{ip}:{bucket}"

            count = await rate_limit_hit(env, limit_key, bucket)
            max_per_min = int(getattr(env, "RATE_LIMIT_PER_MINUTE", "5"))

            if count > max_per_min:
                return Response.json({"error": "rate limit exceeded"}, status=429)

            try:
                payload = await request.json()
            except Exception:
                return Response.json({"error": "invalid json"}, status=400)

            domain = normalize_domain(payload.get("domain", ""))
            username = payload.get("username")
            username = str(username).strip() if username else None
            turnstile_token = str(payload.get("turnstile_token", ""))

            # Plaintext report fields
            report_url = str(payload.get("url", "")).strip()
            description = str(payload.get("description", "")).strip()
            markdown = payload.get("markdown")
            markdown = str(markdown).strip() if markdown else None
            screenshots_b64 = payload.get("screenshots_b64") or []

            if not domain or not report_url or not description:
                return Response.json(
                    {"error": "domain, url, and description are required"},
                    status=400
                )

            if ts_enabled and not turnstile_token:
                return Response.json({"error": "turnstile_token required"}, status=400)

            ok = await verify_turnstile(env, turnstile_token, ip)
            if not ok:
                return Response.json({"error": "turnstile failed"}, status=403)

            row = await get_domain(env, domain)
            if not row or not row["is_active"]:
                return Response.json({"error": "domain not registered"}, status=404)

            # Validate payload size
            raw_size = len(json.dumps(payload).encode("utf-8"))
            max_bytes = int(getattr(env, "MAX_UPLOAD_BYTES", "3145728"))
            if raw_size > max_bytes:
                return Response.json({"error": "payload too large"}, status=413)

            submission_id = str(js_crypto.randomUUID())
            created_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")

            # Build the plaintext report object
            report = {
                "v": 1,
                "submission_id": submission_id,
                "domain": domain,
                "url": report_url,
                "username": username,
                "description": description,
                "markdown": markdown,
                "screenshots_b64": screenshots_b64,
                "created_at": created_at,
            }
            report_json_bytes = json.dumps(report).encode("utf-8")

            # Encrypt the report with AES-256-GCM
            ct_bytes, key_hex, iv_hex = await _aes_gcm_encrypt(report_json_bytes)

            # Compute hash of ciphertext for integrity reference
            artifact_hash = await sha256_hex(ct_bytes)

            # Pack the encrypted report into a zip
            inner_filename = f"report-{submission_id}.bin"
            zip_bytes = _build_zip(inner_filename, ct_bytes)

            # Email the zip with the decryption key in the body
            subject = f"BLT-Zero Vulnerability Report — {domain} — {submission_id}"
            sep = "=" * 60
            body_lines = [
                f"A new vulnerability report has been submitted for: {domain}",
                f"",
                f"Submission ID      : {submission_id}",
                f"Created            : {created_at}",
                f"Ciphertext SHA-256 : {artifact_hash}",
                f"",
                sep,
                "ZIP FILE DECRYPTION KEY",
                sep,
                f"Key (AES-256-GCM) : {key_hex}",
                f"IV                : {iv_hex}",
                f"Algorithm         : AES-256-GCM",
                f"",
                f"The attached ZIP contains '{inner_filename}'.",
                f"Decrypt with the key above to obtain the plaintext report (JSON).",
                f"",
                f"Quick decrypt (Python):",
                f"  pip install cryptography",
                f"  python decrypt_report.py {key_hex} {iv_hex} {inner_filename}",
                f"",
                f"— BLT-Zero / OWASP BLT",
            ]
            body = "\n".join(body_lines)

            zip_filename = f"blt-zero-{domain}-{submission_id}.zip"
            await send_email(
                env,
                row["org_email"],
                subject,
                body,
                zip_filename,
                zip_bytes,
            )

            # Store minimal metadata
            await insert_submission(env, {
                "id": submission_id,
                "domain": domain,
                "username": username,
                "artifact_hash": artifact_hash,
            })

            return Response.json({
                "ok": True,
                "submission_id": submission_id,
                "artifact_hash": artifact_hash,
            })

        # 404
        return Response("Not found", status=404)

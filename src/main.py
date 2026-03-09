import io
import json
import os
import string
import struct
import zipfile
import zlib
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from workers import WorkerEntrypoint, Response
from js import URL

from libs.utils import html_response
from services.email import send_email
from services.security import (
    normalize_domain,
    verify_turnstile,
    turnstile_enabled,
)
from services.templates import submit_page


# ---------------------------------------------------------------------------
# ZipCrypto – standard PKZIP password-protected ZIP (pure Python, no libs)
# Supports all ZIP tools: Windows Explorer, macOS Archive Utility, 7-Zip, etc.
# ---------------------------------------------------------------------------

# Pre-compute CRC32 lookup table (PKZIP polynomial 0xEDB88320)
_CRC32_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (0xEDB88320 ^ (_c >> 1)) if (_c & 1) else (_c >> 1)
    _CRC32_TABLE.append(_c)


def _crc32_update(crc: int, byte: int) -> int:
    """One-byte CRC32 update (ZipCrypto key schedule)."""
    return ((crc >> 8) ^ _CRC32_TABLE[(crc ^ byte) & 0xFF]) & 0xFFFFFFFF


class _ZipCryptoEncrypter:
    """ZipCrypto stream encrypter.

    Produces standard PKZIP-encrypted data readable by any ZIP tool.
    Security note: ZipCrypto is weaker than modern AES encryption but
    universally supported. A strong random 20-character password makes
    brute-force impractical in practice.
    """

    _INIT_KEYS = (0x12345678, 0x23456789, 0x34567890)

    def __init__(self, password: bytes) -> None:
        k0, k1, k2 = self._INIT_KEYS
        for c in password:
            k0 = _crc32_update(k0, c)
            k1 = (k1 + (k0 & 0xFF)) & 0xFFFFFFFF
            k1 = (k1 * 134775813 + 1) & 0xFFFFFFFF
            k2 = _crc32_update(k2, k1 >> 24)
        self._k = [k0, k1, k2]

    def _stream_byte(self) -> int:
        t = (self._k[2] | 2) & 0xFFFF
        return ((t * (t ^ 1)) >> 8) & 0xFF

    def _advance(self, plaintext_byte: int) -> None:
        k = self._k
        k[0] = _crc32_update(k[0], plaintext_byte)
        k[1] = (k[1] + (k[0] & 0xFF)) & 0xFFFFFFFF
        k[1] = (k[1] * 134775813 + 1) & 0xFFFFFFFF
        k[2] = _crc32_update(k[2], k[1] >> 24)

    def encrypt_byte(self, plaintext_byte: int) -> int:
        enc = plaintext_byte ^ self._stream_byte()
        self._advance(plaintext_byte)
        return enc

    def encrypt(self, data: bytes) -> bytes:
        return bytes(self.encrypt_byte(b) for b in data)


def _build_password_zip(inner_filename: str, data: bytes, password: str) -> bytes:
    """Return a ZIP archive with ZipCrypto password protection.

    The resulting file can be opened by any standard ZIP application;
    the user is prompted for the password when extracting.
    """
    pwd = password.encode("utf-8")

    # Compress the payload (raw DEFLATE, without zlib header/trailer)
    compressed = zlib.compress(data, level=9)[2:-4]
    file_crc = zlib.crc32(data) & 0xFFFFFFFF

    # 12-byte encryption header: 11 random bytes + CRC high byte
    raw_enc_header = os.urandom(11) + bytes([file_crc >> 24])

    encrypter = _ZipCryptoEncrypter(pwd)
    enc_header = encrypter.encrypt(raw_enc_header)
    enc_body = encrypter.encrypt(compressed)
    encrypted_payload = enc_header + enc_body

    # DOS date/time for "now"
    now = datetime.utcnow()
    dostime = (now.hour << 11) | (now.minute << 5) | (now.second // 2)
    dosdate = ((now.year - 1980) << 9) | (now.month << 5) | now.day

    fn_bytes = inner_filename.encode("utf-8")
    flags = 0x0001  # encrypted

    # Local file header (30 bytes + filename)
    local_hdr = struct.pack(
        "<4sHHHHHIIIHH",
        b"PK\x03\x04",   # signature
        20,               # version needed (2.0)
        flags,            # general purpose bit flag
        8,                # compression method (deflated)
        dostime,
        dosdate,
        file_crc,
        len(encrypted_payload),
        len(data),
        len(fn_bytes),
        0,                # extra field length
    ) + fn_bytes

    cd_offset = len(local_hdr) + len(encrypted_payload)

    # Central directory record (46 bytes + filename)
    central_dir = struct.pack(
        "<4sHHHHHHIIIHHHHHII",
        b"PK\x01\x02",   # signature
        0x0314,           # version made by (Unix, 3.0)
        20,               # version needed
        flags,
        8,                # deflated
        dostime,
        dosdate,
        file_crc,
        len(encrypted_payload),
        len(data),
        len(fn_bytes),
        0,                # extra length
        0,                # comment length
        0,                # disk number start
        0,                # internal attributes
        0x81A40000,       # external attributes (regular file, 0644)
        0,                # offset of local header
    ) + fn_bytes

    # End of central directory (22 bytes)
    eocd = struct.pack(
        "<4sHHHHIIH",
        b"PK\x05\x06",
        0,                # disk number
        0,                # disk with start of CD
        1,                # entries on this disk
        1,                # total entries
        len(central_dir),
        cd_offset,
        0,                # comment length
    )

    return local_hdr + encrypted_payload + central_dir + eocd


# ---------------------------------------------------------------------------
# Password generator
# ---------------------------------------------------------------------------

_PWD_ALPHABET = string.ascii_letters + string.digits + "!@#$%&*-_=+"
_PWD_ALPHA_LEN = len(_PWD_ALPHABET)


def _generate_password(length: int = 20) -> str:
    """Generate a cryptographically random password of given length."""
    raw = os.urandom(length * 2)
    chars: list[str] = []
    for b in raw:
        if len(chars) >= length:
            break
        # Reject values that would introduce modulo bias
        if b < 256 - (256 % _PWD_ALPHA_LEN):
            chars.append(_PWD_ALPHABET[b % _PWD_ALPHA_LEN])
    return "".join(chars)


# ---------------------------------------------------------------------------
# Worker entry point
# ---------------------------------------------------------------------------

class Default(WorkerEntrypoint):
    async def fetch(self, request):
        """Main fetch handler for the worker."""
        env = self.env

        url = URL.new(request.url)
        ts_enabled = turnstile_enabled(env)

        # ── GET / → submission form ──────────────────────────────────────
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

        # ── POST /submit → zip report + email ───────────────────────────
        if request.method == "POST" and url.pathname == "/submit":
            try:
                payload = await request.json()
            except Exception:
                return Response.json({"error": "invalid json"}, status=400)

            domain = normalize_domain(payload.get("domain", ""))
            username = payload.get("username")
            username = str(username).strip() if username else None
            turnstile_token = str(payload.get("turnstile_token", ""))

            report_url = str(payload.get("url", "")).strip()
            description = str(payload.get("description", "")).strip()
            markdown = payload.get("markdown")
            markdown = str(markdown).strip() if markdown else None
            screenshots_b64 = payload.get("screenshots_b64") or []

            if not domain or not report_url or not description:
                return Response.json(
                    {"error": "domain, url, and description are required"},
                    status=400,
                )

            if ts_enabled and not turnstile_token:
                return Response.json({"error": "turnstile_token required"}, status=400)

            ip = request.headers.get("CF-Connecting-IP", "0.0.0.0")
            ok = await verify_turnstile(env, turnstile_token, ip)
            if not ok:
                return Response.json({"error": "turnstile failed"}, status=403)

            # Validate org email is configured
            org_email = getattr(env, "ORG_EMAIL", "").strip()
            if not org_email:
                return Response.json({"error": "server misconfigured"}, status=500)

            # Validate payload size
            raw_size = len(json.dumps(payload).encode("utf-8"))
            max_bytes = int(getattr(env, "MAX_UPLOAD_BYTES", "3145728"))
            if raw_size > max_bytes:
                return Response.json({"error": "payload too large"}, status=413)

            created_at = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z")

            # Build report JSON
            report = {
                "v": 1,
                "domain": domain,
                "url": report_url,
                "username": username,
                "description": description,
                "markdown": markdown,
                "screenshots_b64": screenshots_b64,
                "created_at": created_at,
            }
            report_json_bytes = json.dumps(report).encode("utf-8")

            # Generate strong 20-char random password
            password = _generate_password(20)

            # Create password-protected ZIP
            inner_filename = f"report-{domain}-{created_at[:10]}.json"
            zip_bytes = _build_password_zip(inner_filename, report_json_bytes, password)

            # Build email body with password
            sep = "=" * 60
            body_lines = [
                f"A vulnerability report has been submitted for: {domain}",
                "",
                f"Submitted : {created_at}",
                "",
                sep,
                "ZIP PASSWORD",
                sep,
                password,
                sep,
                "",
                "The attached ZIP file contains the full vulnerability report.",
                "Open the ZIP with any standard archive tool and enter the",
                "password above when prompted.",
                "",
                "— BLT-Zero / OWASP BLT",
            ]
            body = "\n".join(body_lines)

            zip_filename = f"blt-zero-{domain}-{created_at[:10]}.zip"
            subject = f"BLT-Zero Vulnerability Report — {domain}"
            await send_email(
                env,
                org_email,
                subject,
                body,
                zip_filename,
                zip_bytes,
            )

            return Response.json({"ok": True})

        # ── 404 ──────────────────────────────────────────────────────────
        return Response("Not found", status=404)

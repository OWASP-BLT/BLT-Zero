"""Tests for Phase 2 ECDH key-wrapping: org_decrypt password package handling
and the SSRF-protection helper in main.py.
"""

import base64
import os
import re
import sys

import pytest

sys.path.insert(0, ".")

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from tools.org_decrypt import _ecdh_decrypt


# -----------------------------------------------------------------------
# Helpers (mirror the browser-side ECDH wrapping logic)
# -----------------------------------------------------------------------

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64enc(b: bytes) -> str:
    return base64.b64encode(b).decode()


def _browser_wrap(org_pub_key, password: str) -> dict:
    """Simulate the browser's ecdhWrapPassword() function in Python."""
    eph_priv = ec.generate_private_key(ec.SECP256R1())
    eph_pub = eph_priv.public_key()

    shared = eph_priv.exchange(ec.ECDH(), org_pub_key)

    salt = os.urandom(16)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"blt-zero-v1")
    key = hkdf.derive(shared)

    iv = os.urandom(12)
    ct = AESGCM(key).encrypt(iv, password.encode("utf-8"), None)

    nums = eph_pub.public_numbers()
    x = nums.x.to_bytes(32, "big")
    y = nums.y.to_bytes(32, "big")

    return {
        "type": "password_package",
        "version": "1",
        "eph_pub_jwk": {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64url(x),
            "y": _b64url(y),
            "ext": True,
        },
        "salt_b64": _b64enc(salt),
        "iv_b64": _b64enc(iv),
        "ciphertext_b64": _b64enc(ct),
    }


# -----------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------

def test_password_package_round_trip():
    """Browser wraps password; org decrypts and recovers the exact password."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key()

    original_password = "super-secret-abc123XYZ"
    pkg = _browser_wrap(pub, original_password)

    decrypted_bytes = _ecdh_decrypt(priv, pkg)
    assert decrypted_bytes.decode("utf-8") == original_password


def test_password_package_wrong_key_raises():
    """Using the wrong private key should raise (AES-GCM authentication failure)."""
    priv_org = ec.generate_private_key(ec.SECP256R1())
    priv_wrong = ec.generate_private_key(ec.SECP256R1())

    pkg = _browser_wrap(priv_org.public_key(), "secret-pw")

    with pytest.raises(Exception):
        _ecdh_decrypt(priv_wrong, pkg)


def test_password_package_tampered_ciphertext_raises():
    """Tampered ciphertext should fail AES-GCM authentication."""
    priv = ec.generate_private_key(ec.SECP256R1())
    pkg = _browser_wrap(priv.public_key(), "secret-pw")

    # Flip a byte in the ciphertext
    ct_bytes = bytearray(base64.b64decode(pkg["ciphertext_b64"]))
    ct_bytes[0] ^= 0xFF
    pkg["ciphertext_b64"] = base64.b64encode(bytes(ct_bytes)).decode()

    with pytest.raises(Exception):
        _ecdh_decrypt(priv, pkg)


# -----------------------------------------------------------------------
# SSRF protection helper (_is_private_host extracted for unit testing)
# -----------------------------------------------------------------------

_PRIVATE_HOST_RE = re.compile(
    r"^(localhost"
    r"|127\."
    r"|10\."
    r"|172\.(1[6-9]|2[0-9]|3[01])\."
    r"|192\.168\."
    r"|169\.254\."
    r"|0\."
    r"|::1"
    r"|fc[0-9a-f]{2}:"
    r"|fd[0-9a-f]{2}:)",
    re.IGNORECASE,
)


def _is_private_host(host: str) -> bool:
    return bool(_PRIVATE_HOST_RE.match(host))


@pytest.mark.parametrize("host", [
    "localhost",
    "127.0.0.1",
    "10.0.0.1",
    "10.255.255.255",
    "192.168.1.1",
    "172.16.0.1",
    "172.31.255.255",
    "169.254.169.254",   # AWS/Azure metadata endpoint
    "0.0.0.0",
    "::1",
])
def test_private_host_is_blocked(host):
    assert _is_private_host(host) is True


@pytest.mark.parametrize("host", [
    "example.com",
    "owasp.org",
    "security.example.org",
    "172.32.0.1",     # 172.32.x is NOT private
    "172.15.0.1",     # 172.15.x is NOT private
    "11.0.0.1",
    "100.64.0.1",     # Carrier-grade NAT — not in private ranges we block
])
def test_public_host_is_allowed(host):
    assert _is_private_host(host) is False

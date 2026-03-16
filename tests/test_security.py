from datetime import datetime

import pytest

from src.services.security import (
    get_client_ip,
    minute_bucket_iso,
    normalize_domain,
    sha256_hex,
    turnstile_enabled,
)


def test_normalize_domain_strips_and_lowercases():
    assert normalize_domain("  Example.COM  ") == "example.com"


def test_normalize_domain_empty_string():
    assert normalize_domain("") == ""
    assert normalize_domain("   ") == ""


def test_get_client_ip_from_header():
    class Req:
        def __init__(self, headers):
            self.headers = headers

    req = Req(headers={"CF-Connecting-IP": "203.0.113.10"})
    assert get_client_ip(req) == "203.0.113.10"


def test_get_client_ip_default_when_missing():
    class Req:
        def __init__(self, headers):
            self.headers = headers

    req = Req(headers={})
    assert get_client_ip(req) == "0.0.0.0"


def test_minute_bucket_iso_with_fixed_datetime():
    dt = datetime(2026, 3, 1, 12, 34, 56)
    assert minute_bucket_iso(dt) == "2026-03-01T12:34"


def test_minute_bucket_iso_default_uses_current_time():
    """Call with no args; assert returned string has YYYY-MM-DDTHH:MM shape."""
    result = minute_bucket_iso()
    assert len(result) == 16
    assert result[4] == "-" and result[7] == "-" and result[10] == "T" and result[13] == ":"


@pytest.mark.asyncio
async def test_sha256_hex_matches_known_value():
    data = b"blt-zero-test"
    digest = await sha256_hex(data)
    # Precomputed with Python's hashlib.sha256(b"blt-zero-test").hexdigest()
    assert digest == "aa28ed2eef4c7a5de7ca5860e6317c3cc7d88fe69fadeb5eceb432031a78f73e"


class _Env:
    def __init__(self, disable: str, site_key: str | None, secret: str | None):
        self.DISABLE_TURNSTILE = disable
        if site_key is not None:
            self.TURNSTILE_SITE_KEY = site_key
        if secret is not None:
            self.TURNSTILE_SECRET = secret


class _EnvNoDisable:
    """Env variant without DISABLE_TURNSTILE (tests getattr default path)."""

    def __init__(self, site_key: str | None, secret: str | None):
        if site_key is not None:
            self.TURNSTILE_SITE_KEY = site_key
        if secret is not None:
            self.TURNSTILE_SECRET = secret


def test_turnstile_enabled_false_when_globally_disabled():
    env = _Env(disable="true", site_key="site", secret="secret")
    assert turnstile_enabled(env) is False


def test_turnstile_enabled_false_when_missing_keys():
    env = _Env(disable="false", site_key=None, secret=None)
    assert turnstile_enabled(env) is False


def test_turnstile_enabled_true_when_configured():
    env = _Env(disable="false", site_key="site", secret="secret")
    assert turnstile_enabled(env) is True


def test_turnstile_enabled_true_when_disable_flag_missing():
    """When DISABLE_TURNSTILE is absent, getattr defaults to 'false'; keys present => enabled."""
    env = _EnvNoDisable(site_key="site", secret="secret")
    assert turnstile_enabled(env) is True


def test_turnstile_enabled_false_when_keys_are_empty_strings():
    """Empty string keys should be treated as disabled."""
    class EnvWithEmptyKeys:
        DISABLE_TURNSTILE = "false"
        TURNSTILE_SITE_KEY = ""
        TURNSTILE_SECRET = ""

    env = EnvWithEmptyKeys()
    assert turnstile_enabled(env) is False

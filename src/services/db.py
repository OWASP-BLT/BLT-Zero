from typing import Optional, TypedDict


class DomainRow(TypedDict):
    domain: str
    org_email: str
    is_active: int
    alg: str
    key_id: str
    public_key_jwk: str


async def get_domain(env, domain: str) -> Optional[DomainRow]:
    """Get domain information from the database."""
    q = """SELECT domain, org_email, is_active, alg, key_id, public_key_jwk
           FROM domains WHERE domain = ? LIMIT 1"""
    
    res = await env.DB.prepare(q).bind(domain).all()
    
    if not res.results:
        return None
    
    return res.results[0]


async def upsert_domain(env, data: dict):
    """Insert or update a domain in the database."""
    q = """
    INSERT INTO domains (domain, org_email, alg, key_id, public_key_jwk, is_active, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, (strftime('%Y-%m-%dT%H:%M:%fZ','now')))
    ON CONFLICT(domain) DO UPDATE SET
      org_email=excluded.org_email,
      alg=excluded.alg,
      key_id=excluded.key_id,
      public_key_jwk=excluded.public_key_jwk,
      is_active=excluded.is_active,
      updated_at=(strftime('%Y-%m-%dT%H:%M:%fZ','now'))
    """
    
    await env.DB.prepare(q).bind(
        data["domain"],
        data["org_email"],
        data["alg"],
        data["key_id"],
        data["public_key_jwk"],
        data["is_active"]
    ).run()


async def insert_submission(env, submission: dict):
    """Insert a new submission into the database."""
    q = """INSERT INTO submissions (id, domain, username, artifact_hash) VALUES (?,?,?,?)"""
    
    await env.DB.prepare(q).bind(
        submission["id"],
        submission["domain"],
        submission.get("username"),
        submission["artifact_hash"]
    ).run()


async def rate_limit_hit(env, key: str, window_start: str) -> int:
    """Track rate limit hits and return current count."""
    existing = await env.DB.prepare(
        """SELECT count FROM rate_limits WHERE k = ? LIMIT 1"""
    ).bind(key).all()
    
    if not existing.results:
        await env.DB.prepare(
            """INSERT INTO rate_limits (k, count, window_start) VALUES (?,?,?)"""
        ).bind(key, 1, window_start).run()
        return 1
    
    count = existing.results[0]["count"] + 1
    await env.DB.prepare(
        """UPDATE rate_limits SET count = ? WHERE k = ?"""
    ).bind(count, key).run()
    
    return count


async def track_admin_auth_failure(env, ip: str, timestamp: str):
    """Track a failed admin authentication attempt."""
    key = f"admin_fail:{ip}"
    
    existing = await env.DB.prepare(
        """SELECT count FROM rate_limits WHERE k = ? LIMIT 1"""
    ).bind(key).all()
    
    if not existing.results:
        await env.DB.prepare(
            """INSERT INTO rate_limits (k, count, window_start) VALUES (?,?,?)"""
        ).bind(key, 1, timestamp).run()
    else:
        count = existing.results[0]["count"] + 1
        await env.DB.prepare(
            """UPDATE rate_limits SET count = ?, window_start = ? WHERE k = ?"""
        ).bind(count, timestamp, key).run()


async def get_admin_auth_failures(env, ip: str) -> tuple[int, Optional[str]]:
    """Get count of admin auth failures and timestamp of last failure for an IP."""
    key = f"admin_fail:{ip}"
    
    res = await env.DB.prepare(
        """SELECT count, window_start FROM rate_limits WHERE k = ? LIMIT 1"""
    ).bind(key).all()
    
    if not res.results:
        return (0, None)
    
    return (res.results[0]["count"], res.results[0]["window_start"])


async def clear_admin_auth_failures(env, ip: str):
    """Clear admin auth failures for an IP (called on successful auth)."""
    key = f"admin_fail:{ip}"
    
    await env.DB.prepare(
        """DELETE FROM rate_limits WHERE k = ?"""
    ).bind(key).run()

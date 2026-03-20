_DOMAINS = {}
_SUBMISSIONS = {}
_RATE_LIMIT_COUNTS = {}


async def get_domain(_env, domain):
    if not domain:
        return None
    return _DOMAINS.get(domain)


async def upsert_domain(_env, row):
    domain = row.get("domain")
    if not domain:
        return None
    _DOMAINS[domain] = {
        "domain": row.get("domain"),
        "org_email": row.get("org_email"),
        "alg": row.get("alg"),
        "key_id": row.get("key_id"),
        "public_key_jwk": row.get("public_key_jwk"),
        "is_active": row.get("is_active", 1),
    }
    return _DOMAINS[domain]


async def insert_submission(_env, row):
    submission_id = row.get("id")
    if not submission_id:
        return None
    _SUBMISSIONS[submission_id] = {
        "id": submission_id,
        "domain": row.get("domain"),
        "artifact_hash": row.get("artifact_hash"),
    }
    return _SUBMISSIONS[submission_id]


async def rate_limit_hit(_env, key, _bucket=None):
    _RATE_LIMIT_COUNTS[key] = _RATE_LIMIT_COUNTS.get(key, 0) + 1
    return _RATE_LIMIT_COUNTS[key]

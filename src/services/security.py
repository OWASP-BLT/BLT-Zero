def normalize_domain(input: str) -> str:
    """Normalize domain name to lowercase and trimmed."""
    return input.strip().lower()


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
    if not turnstile_enabled(env):
        return True

    from js import fetch, FormData

    form = FormData.new()
    form.append("secret", env.TURNSTILE_SECRET)
    form.append("response", token)
    form.append("remoteip", ip)

    resp = await fetch(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        method="POST",
        body=form,
    )

    if not resp.ok:
        return False

    json_data = await resp.json()
    return bool(json_data.get("success", False))

import html
import re
from pathlib import Path


def esc(s: str) -> str:
    """Escape HTML characters."""
    return html.escape(s)


def is_turnstile_enabled(site_key: str = None) -> bool:
    """Check if Turnstile is enabled based on site key."""
    if not site_key:
        return False
    
    v = str(site_key).strip().lower()
    if not v:
        return False
    if v in ["false", "0", "null", "undefined"]:
        return False
    
    return True


def replace_template(template: str, replacements: dict) -> str:
    """Replace {{key}} placeholders in template with values."""
    result = template
    for key, value in replacements.items():
        result = re.sub(r'\{\{' + key + r'\}\}', value, result)
    return result


def read_html_file(filename: str) -> str:
    """Read HTML file from pages directory."""
    import os
    
    # Get the directory where this file is located
    current_dir = Path(__file__).parent
    
    # Try multiple possible paths relative to various locations
    paths = [
        current_dir.parent / "pages" / filename,  # From services dir, go up to src then to pages
        current_dir.parent.parent / "src" / "pages" / filename,  # From project root
        Path("pages") / filename,  # Direct path
        Path("src/pages") / filename,  # From project root
    ]
    
    for path in paths:
        try:
            if path.exists():
                return path.read_text()
        except Exception:
            continue
    
    # If all paths fail, raise error with helpful message
    raise FileNotFoundError(f"Could not find {filename} in any of: {paths}")


def build_commit_info(sha: str, date_iso: str) -> str:
    """Build the footer commit info HTML snippet."""
    if not sha:
        return ''
    short_sha = sha[:7]
    commit_url = f"https://github.com/OWASP-BLT/BLT-Zero/commit/{sha}"
    date_attr = f' data-ts="{esc(date_iso)}"' if date_iso else ''
    fallback_text = date_iso[:10] if date_iso else short_sha  # YYYY-MM-DD portion of ISO 8601
    return (
        f'<span class="text-xs text-gray-600 dark:text-gray-400">'
        f'updated <span id="commit-time-ago"{date_attr}>{fallback_text}</span> '
        f'<a href="{commit_url}" target="_blank" rel="noopener noreferrer" '
        f'class="font-mono underline-offset-4 transition-colors hover:text-gray-900 dark:hover:text-gray-50 hover:underline">'
        f'{short_sha}</a>'
        f'</span>'
    )


def layout(title: str, body: str, include_turnstile_script: bool, commit_sha: str = '', commit_date: str = '') -> str:
    """Wrap content in the main layout template."""
    # Read layout HTML
    layout_html = read_html_file("layout.html")
    
    turnstile_script = (
        '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
        if include_turnstile_script else ''
    )
    
    return replace_template(layout_html, {
        "TITLE": esc(title),
        "BODY": body,
        "TURNSTILE_SCRIPT": turnstile_script,
        "COMMIT_INFO": build_commit_info(commit_sha, commit_date)
    })


def submit_page(opts: dict) -> str:
    """Generate the submission page HTML."""
    domain_prefill = opts.get("domainPrefill", "")
    turnstile_site_key = opts.get("turnstileSiteKey", "")
    max_files = opts.get("maxFiles", 3)
    max_total_bytes = opts.get("maxTotalBytes", 3145728)
    commit_sha = opts.get("commitSha", "")
    commit_date = opts.get("commitDate", "")
    
    ts_enabled = is_turnstile_enabled(turnstile_site_key)
    
    turnstile_widget = (
        f'<div class="cf-turnstile" data-sitekey="{esc(turnstile_site_key)}"></div>'
        if ts_enabled else
        '<p class="text-sm text-muted-foreground">Turnstile disabled (local testing).</p>'
    )
    
    # Read submit page HTML
    submit_html = read_html_file("submit.html")
    
    body = replace_template(submit_html, {
        "MAX_FILES": str(max_files),
        "MAX_MB": str(max_total_bytes // (1024 * 1024)),
        "DOMAIN_PREFILL": esc(domain_prefill),
        "TURNSTILE_WIDGET": turnstile_widget,
        "MAX_TOTAL_BYTES": str(max_total_bytes),
        "TURNSTILE_ENABLED": "true" if ts_enabled else "false"
    })
    
    return layout("BLT-Zero — Submit Encrypted Report", body, ts_enabled, commit_sha, commit_date)


def docs_security(commit_sha: str = '', commit_date: str = '') -> str:
    """Generate the security documentation page."""
    docs_security_html = read_html_file("docs-security.html")
    
    return layout("BLT-Zero — Security Model", docs_security_html, False, commit_sha, commit_date)


def docs_org_onboarding(app_origin: str, commit_sha: str = '', commit_date: str = '') -> str:
    """Generate the organization onboarding documentation page."""
    docs_org_onboarding_html = read_html_file("docs-org-onboarding.html")
    
    body = replace_template(docs_org_onboarding_html, {
        "APP_ORIGIN": esc(app_origin)
    })
    
    return layout("BLT-Zero — Org Onboarding", body, False, commit_sha, commit_date)


def docs_decrypt(commit_sha: str = '', commit_date: str = '') -> str:
    """Generate the decryption guide page."""
    docs_decrypt_html = read_html_file("docs-decrypt.html")
    
    return layout("BLT-Zero — Decrypt Guide", docs_decrypt_html, False, commit_sha, commit_date)


def admin_onboard_page(turnstile_site_key: str = None, commit_sha: str = '', commit_date: str = '') -> str:
    """Generate the admin onboarding page."""
    ts_enabled = is_turnstile_enabled(turnstile_site_key)
    
    turnstile_widget = (
        f'<div class="cf-turnstile" data-sitekey="{esc(turnstile_site_key or "")}"></div>'
        if ts_enabled else
        '<p class="text-sm text-muted-foreground">Turnstile disabled (local testing).</p>'
    )
    
    turnstile_status = "+ Turnstile" if ts_enabled else "(Turnstile disabled)"
    
    admin_onboard_html = read_html_file("admin-onboard.html")
    
    body = replace_template(admin_onboard_html, {
        "TURNSTILE_WIDGET": turnstile_widget,
        "TURNSTILE_STATUS": turnstile_status,
        "TURNSTILE_ENABLED": "true" if ts_enabled else "false"
    })
    
    return layout("BLT-Zero — Org Admin Onboarding", body, ts_enabled, commit_sha, commit_date)


def onboarding_email_body(app_origin: str, domain: str) -> str:
    """Generate the onboarding email body text."""
    return f"""Hello Security Team,

You have been onboarded to BLT-Zero (zero.owaspblt.org) for domain: {domain}

How it works:
- Reporters encrypt in their browser using your public key.
- BLT-Zero receives only ciphertext and emails it to you.
- Only your private key can decrypt.

Next steps:
- Decrypt guide: {app_origin}/docs/decrypt
- Security model: {app_origin}/docs/security

Regards,
BLT-Zero Maintainers (OWASP BLT)
"""

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
    current_dir = Path(__file__).parent

    paths = [
        current_dir.parent / "pages" / filename,
        current_dir.parent.parent / "src" / "pages" / filename,
        Path("pages") / filename,
        Path("src/pages") / filename,
    ]

    for path in paths:
        try:
            if path.exists():
                return path.read_text()
        except Exception:
            continue

    raise FileNotFoundError(f"Could not find {filename} in any of: {paths}")


def layout(title: str, body: str, include_turnstile_script: bool) -> str:
    """Wrap content in the main layout template."""
    layout_html = read_html_file("layout.html")

    turnstile_script = (
        '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
        if include_turnstile_script else ''
    )

    return replace_template(layout_html, {
        "TITLE": esc(title),
        "BODY": body,
        "TURNSTILE_SCRIPT": turnstile_script,
    })


def submit_page(opts: dict) -> str:
    """Generate the submission page HTML."""
    domain_prefill = opts.get("domainPrefill", "")
    turnstile_site_key = opts.get("turnstileSiteKey", "")
    max_files = opts.get("maxFiles", 3)
    max_total_bytes = opts.get("maxTotalBytes", 3145728)

    ts_enabled = is_turnstile_enabled(turnstile_site_key)

    turnstile_widget = (
        f'<div class="cf-turnstile" data-sitekey="{esc(turnstile_site_key)}"></div>'
        if ts_enabled else
        '<p class="text-sm text-muted-foreground">Turnstile disabled (local testing).</p>'
    )

    submit_html = read_html_file("submit.html")

    body = replace_template(submit_html, {
        "MAX_FILES": str(max_files),
        "MAX_MB": str(max_total_bytes // (1024 * 1024)),
        "DOMAIN_PREFILL": esc(domain_prefill),
        "TURNSTILE_WIDGET": turnstile_widget,
        "MAX_TOTAL_BYTES": str(max_total_bytes),
        "TURNSTILE_ENABLED": "true" if ts_enabled else "false",
    })

    return layout("BLT-Zero — Submit Vulnerability Report", body, ts_enabled)

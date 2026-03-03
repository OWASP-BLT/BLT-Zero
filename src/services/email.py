import json
import base64
from js import Headers, fetch


async def send_email(env, to, subject, body, attachment_name=None, attachment_json=None):
    """Send email via MailChannels or SendGrid."""
    provider = getattr(env, "EMAIL_PROVIDER", "mailchannels").lower()
    from_email = getattr(env, "SENDGRID_FROM_EMAIL", "no-reply@example.com")
    from_name = getattr(env, "SENDGRID_FROM_NAME", "BLT-Zero")
    
    # Helper: UTF-8 → base64
    def b64utf8(s):
        return base64.b64encode(s.encode('utf-8')).decode('ascii')
    
    if provider == "sendgrid":
        api_key = getattr(env, "SENDGRID_API_KEY", None)
        if not api_key:
            raise Exception("SENDGRID_API_KEY missing.")
        
        payload = {
            "personalizations": [{"to": [{"email": to}]}],
            "from": {"email": from_email, "name": from_name},
            "subject": subject,
            "content": [{"type": "text/plain", "value": body}],
        }
        
        if attachment_name and attachment_json:
            payload["attachments"] = [{
                "content": b64utf8(attachment_json),
                "filename": attachment_name,
                "type": "application/json",
                "disposition": "attachment"
            }]
        
        headers = Headers.new()
        headers.set("authorization", f"Bearer {api_key}")
        headers.set("content-type", "application/json")
        
        r = await fetch(
            "https://api.sendgrid.com/v3/mail/send",
            method="POST",
            headers=headers,
            body=json.dumps(payload)
        )
        
        # SendGrid returns 202 Accepted on success
        if r.status != 202:
            txt = await r.text() if hasattr(r, 'text') else ""
            raise Exception(f"Email delivery failed (SendGrid): {r.status} {txt}")
        return
    
    # MailChannels
    mailchannels = {
        "personalizations": [{"to": [{"email": to}]}],
        "from": {"email": "no-reply@zero.owaspblt.org", "name": "BLT-Zero"},
        "subject": subject,
        "content": [{"type": "text/plain", "value": body}],
    }
    
    if attachment_name and attachment_json:
        # For MailChannels, encode attachment properly
        attachment_b64 = base64.b64encode(attachment_json.encode('utf-8')).decode('ascii')
        mailchannels["attachments"] = [{
            "filename": attachment_name,
            "contentType": "application/json",
            "content": attachment_b64,
        }]
    
    headers = Headers.new()
    headers.set("content-type", "application/json")
    
    r = await fetch(
        "https://api.mailchannels.net/tx/v1/send",
        method="POST",
        headers=headers,
        body=json.dumps(mailchannels)
    )
    
    if not r.ok:
        raise Exception("Email delivery failed (MailChannels).")


async def sync_points(env, username, domain):
    """Sync points with main BLT API."""
    token = getattr(env, "MAIN_BLT_API_TOKEN", None)
    if not token:
        return
    
    headers = Headers.new()
    headers.set("content-type", "application/json")
    headers.set("authorization", f"Token {token}")
    
    await fetch(
        f"{env.MAIN_BLT_API_URL}/api/v1/zero-trust-points/",
        method="POST",
        headers=headers,
        body=json.dumps({"username": username, "domain_name": domain})
    )

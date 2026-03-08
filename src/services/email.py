import json
import base64
from js import Headers, fetch


async def send_email(env, to, subject, body, attachment_name=None, attachment_data=None):
    """Send email via MailChannels or SendGrid.

    attachment_data may be either bytes (binary) or str (text).
    """
    provider = getattr(env, "EMAIL_PROVIDER", "mailchannels").lower()
    from_email = getattr(env, "SENDGRID_FROM_EMAIL", "no-reply@example.com")
    from_name = getattr(env, "SENDGRID_FROM_NAME", "BLT-Zero")

    def b64encode(data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        return base64.b64encode(data).decode("ascii")

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

        if attachment_name and attachment_data is not None:
            payload["attachments"] = [{
                "content": b64encode(attachment_data),
                "filename": attachment_name,
                "type": "application/zip",
                "disposition": "attachment",
            }]

        headers = Headers.new()
        headers.set("authorization", f"Bearer {api_key}")
        headers.set("content-type", "application/json")

        r = await fetch(
            "https://api.sendgrid.com/v3/mail/send",
            method="POST",
            headers=headers,
            body=json.dumps(payload),
        )

        if r.status != 202:
            txt = await r.text() if hasattr(r, "text") else ""
            raise Exception(f"Email delivery failed (SendGrid): {r.status} {txt}")
        return

    # MailChannels
    mailchannels = {
        "personalizations": [{"to": [{"email": to}]}],
        "from": {"email": "no-reply@zero.blt.owasp.org", "name": "BLT-Zero"},
        "subject": subject,
        "content": [{"type": "text/plain", "value": body}],
    }

    if attachment_name and attachment_data is not None:
        mailchannels["attachments"] = [{
            "filename": attachment_name,
            "contentType": "application/zip",
            "content": b64encode(attachment_data),
        }]

    headers = Headers.new()
    headers.set("content-type", "application/json")

    r = await fetch(
        "https://api.mailchannels.net/tx/v1/send",
        method="POST",
        headers=headers,
        body=json.dumps(mailchannels),
    )

    if not r.ok:
        raise Exception("Email delivery failed (MailChannels).")

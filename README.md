# BLT-Zero

**Simple encrypted vulnerability reporting — password-protected ZIP delivery.**

BLT-Zero is a Cloudflare Workers site that lets security researchers submit vulnerability reports.
The Worker packages the report as a **password-protected ZIP file** and emails it to the
configured organisation inbox. The ZIP password (20 random characters) is included in the same email.

It is an independent application under the OWASP BLT project family.

---

## 🔒 How It Works

1. Reporter fills in the submission form (domain, URL, description, screenshots).
2. Worker receives the report, generates a **strong 20-character random password**.
3. Report is packaged into a **password-protected ZIP** (ZipCrypto, universally compatible).
4. ZIP is emailed to the configured `ORG_EMAIL` as an attachment.
5. Password is included in the same email body.
6. Organisation opens the ZIP with any standard archive tool and enters the password.

No database. No key management. No extra tooling required.

---

## 🛠️ Tech Stack

- Runtime: Cloudflare Workers (Python)
- Email: SendGrid (recommended) or MailChannels
- Protection: Optional Cloudflare Turnstile CAPTCHA

---

## 🚀 Setup

### 1. Install Wrangler

```bash
npm install -g wrangler
wrangler login
```

### 2. Configure environment

Copy `.dev.vars.example` to `.dev.vars` and fill in values:

```bash
cp .dev.vars.example .dev.vars
```

Key variables:

| Variable | Description |
|---|---|
| `ORG_EMAIL` | Organisation inbox that receives reports |
| `EMAIL_PROVIDER` | `mailchannels` (default) or `sendgrid` |
| `SENDGRID_API_KEY` | Required when `EMAIL_PROVIDER=sendgrid` |
| `DISABLE_TURNSTILE` | `true` for local dev, `false` in production |

For production, set `ORG_EMAIL` as a secret:
```bash
wrangler secret put ORG_EMAIL
```

### 3. Run locally

```bash
wrangler dev
```

The application will be available at `http://localhost:8787`.

### 4. Deploy

```bash
wrangler deploy
```

---

## 🤝 Contributing

BLT-Zero is part of [OWASP BLT Project #79 — Zero Trust Vulnerability Reporting](https://github.com/OWASP-BLT/BLT-Zero/issues/1).

Contributions are welcome! Please:

1. Check the [open issues](https://github.com/OWASP-BLT/BLT-Zero/issues) for tasks to work on.
2. Fork the repository and create a feature branch.
3. Submit a pull request referencing the relevant issue.

Please follow the [OWASP BLT contribution guidelines](https://github.com/OWASP-BLT/BLT/blob/master/CONTRIBUTING.md).

---

## 📜 License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).

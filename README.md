# BLT-Zero (MVP Phase)

**Zero-Trust Vulnerability Reporting — encrypted payload delivery.**

BLT-Zero is a Cloudflare Workers site that lets security researchers submit sensitive vulnerability reports and screenshots **encrypted directly in the browser**. The Worker receives a pre-encrypted payload, forwards it directly to the organization’s security inbox, and stores only minimal metadata.

It is an independent application under the OWASP BLT project family, intended to run on its own deployment and database.

---

## 🔐 What is BLT-Zero?

BLT-Zero provides a secure workflow for delivering vulnerability reports:

- **Encryption happens client-side (browser)** using modern AES-256 ZIP encryption.
- **BLT-Zero never stores plaintext** vulnerability details.
- **Organizations decrypt locally** using standard archive tools.

### Key Principles

| Principle | Description |
|----------|-------------|
| **Encrypted Transit** | Worker receives only an encrypted ZIP package in Base64 (no plaintext files). |
| **Direct Delivery** | Reports are emailed directly to the organization's security team. |
| **No tracking by design** | No analytics/cookies/fingerprinting in this project. |
| **Abuse controls** | Rate limiting + optional Cloudflare Turnstile. |

---

## 🏗️ Architecture

### Components

- **Client (Browser)**
  - Gathers the form data (Target URL, Description, Markdown) and dynamically builds a `report.json` in memory.
  - Bundles the JSON and uploaded screenshots using `@zip.js/zip.js`.
  - Generates a strong, random 24-character password and encrypts the ZIP file (AES-256) entirely inside the browser.
  - **(Phase 2)** Calls `/pubkey?email={org_email}` — if the org has published a public key, uses WebCrypto ECDH to wrap the password before sending anything to the Worker.
  - Sends the Base64-encoded encrypted ZIP and either the ECDH-wrapped key package or (fallback) the plaintext password to the Worker.

- **Worker (Cloudflare Python Worker)**
  - Validates request + (optional) Turnstile.
  - **(Phase 2)** On `/pubkey` requests, fetches the org's public JWK from `https://{org-domain}/.well-known/blt-zero/public_key.jwk` and returns it to the browser (avoids CORS for the browser fetch).
  - Emails the encrypted ZIP attachment to the org inbox via SendGrid or MailChannels.
  - In Phase 2 mode, the email body contains the ECDH-wrapped key package JSON instead of a plaintext password.

---

## 🔒 Cryptography & Decryption

### Phase 1 (Fallback — no org public key published)

Encryption is handled via **AES-256 Password-Protected ZIPs**. The browser generates a secure, ephemeral password, encrypts the payload, and the Worker forwards this password to the organization alongside the file. The password appears in the email body in plaintext.

### Phase 2 (Preferred — org publishes ECDH key at well-known URL)

| Step | Algorithm |
|------|-----------|
| Key exchange | ECDH P-256 (ephemeral browser key × org static key) |
| Key derivation | HKDF-SHA256 (`info = "blt-zero-v1"`, 16-byte random salt) |
| Password encryption | AES-256-GCM (12-byte random IV) |

The browser generates an ephemeral P-256 key pair, performs ECDH with the org's static public key, derives an AES key with HKDF, and AES-GCM-encrypts the ZIP password. Only the org's private key can recover the password. The Worker never sees the plaintext password.

**Decryption (Important Note for Windows Users)**

Because the browser uses modern AES-256 encryption, **the default Windows File Explorer cannot extract the ZIP file** (it will throw Error `0x80004005`).

To decrypt the report, organizations must use a modern archive utility:
- **Windows:** Use [7-Zip](https://www.7-zip.org/) or WinRAR. Right-click -> Extract Here -> Enter the password from the email.
- **macOS:** Use The Unarchiver or the built-in Archive Utility.
- **Linux:** Use the `unzip` command-line tool.

---

## ✅ Features

- 🔒 Client-side ZIP encryption in the browser (`@zip.js`).
- 📧 Direct email delivery to org security inbox via SendGrid.
- 🧾 Minimal storage: domain + optional username + artifact hash only.
- 🛡️ Rate limiting to prevent abuse.
- 📊 Optional points sync to main BLT.
- 🔑 ECDH key-wrapping: password never appears in plaintext when org publishes a public key.

---

## 🗺️ Roadmap

| Phase | Status | Description |
|-------|--------|-------------|
| **Phase 1 — MVP** | ✅ Done | Client-side AES-256 ZIP encryption. Decryption password emailed alongside the ZIP in plaintext. |
| **Phase 2 — Key-Wrapped Delivery** | 🚧 In Progress | Org self-publishes an ECDH P-256 public key at a well-known URL on their domain. Browser wraps the ZIP password with the org's key before sending anything to the Worker; the Worker never sees the plaintext password. No initial contact with BLT-Zero is required. |
| **Phase 3 — Full Zero-Knowledge** | 📋 Planned | Browser encrypts the report payload directly with the org's public key (no ZIP password at all). The Worker is a pure relay — it never handles any cryptographic material derived from the report. |

### Phase 2 — How Key Discovery Works (No Initial Contact Required)

Orgs self-publish their public key at a predictable URL on their own domain:

```
https://{org-domain}/.well-known/blt-zero/public_key.jwk
```

When a reporter submits a report to `security@example.com`, the Worker fetches
`https://example.com/.well-known/blt-zero/public_key.jwk` automatically.  
If the key is found, the browser wraps the ZIP password with the org's key (ECDH P-256 + HKDF-SHA256 + AES-256-GCM) before sending anything to the server.  
If the key is not published, the system falls back to Phase 1 behaviour.

---

## 🚀 Workflow (end-to-end)

### Phase 1 (fallback — org has no published key)

1. Reporter fills out the vulnerability form and attaches screenshots.
2. Browser generates a password and bundles everything into an AES-256 encrypted ZIP.
3. Worker receives the encrypted ZIP and the plaintext password.
4. Worker emails the ZIP attachment + password to the org inbox.
5. Org receives the email, downloads the ZIP, and decrypts it locally using 7-Zip.

### Phase 2 (preferred — org publishes key at well-known URL)

1. Reporter fills out the vulnerability form and attaches screenshots.
2. Browser calls `/pubkey?email={org_email}`; Worker fetches the org's public JWK from their domain.
3. Browser generates a password, encrypts the ZIP (AES-256), then **ECDH-wraps** the password with the org's public key — the Worker never sees the plaintext password.
4. Browser sends `{zip_content_b64, encrypted_key_package}` to Worker.
5. Worker emails the ZIP attachment; the encrypted key package (JSON) is included in the email body.
6. Org saves the JSON snippet from the email to `blt-zero-key.json` and runs:<br>`python tools/org_decrypt.py private_key.jwk blt-zero-key.json`
7. Tool prints the recovered password; org uses it to open the ZIP.

---

## 🛠️ Tech Stack

- Runtime: Cloudflare Workers (Python support)
- Frontend Crypto: `@zip.js/zip.js` (AES-256) + WebCrypto API (ECDH P-256 key wrapping)
- Email: SendGrid / MailChannels
- Protection: optional Turnstile + rate limiting

---

### Installation

1. Clone the repository:
```bash
git clone [https://github.com/OWASP-BLT/BLT-Zero.git](https://github.com/OWASP-BLT/BLT-Zero.git)
cd BLT-Zero
```

2. Install Wrangler (if not already installed):
```bash
npm install -g wrangler
```

3. Login to Cloudflare:
```bash
wrangler login
```

4. Create `.dev.vars` file from `.dev.vars.example` and populate wrangler.toml with Database ID from previous step:

### Development

Run the development server:
```bash
wrangler dev
```

The application will be available at `http://localhost:8787`

### Deployment

Deploy to Cloudflare Workers:
```bash
wrangler deploy
```

### Org Onboarding (Keys)

Organizations can enable **Phase 2 key-wrapped delivery** (no initial contact with BLT-Zero required) by:

**Step 1 — Generate keypair locally:**
```bash
python tools/org_keygen.py
```

This generates:
- `private_key.jwk` — keep this secret, never share it
- `public_key.jwk` — publish this at a well-known URL on your domain

**Step 2 — Publish the public key at a well-known URL:**

Host `public_key.jwk` at exactly:
```
https://{your-security-email-domain}/.well-known/blt-zero/public_key.jwk
```

For example, if your security contact is `security@example.com`, host the file at:
```
https://example.com/.well-known/blt-zero/public_key.jwk
```

The file must be served with `Content-Type: application/json` and accessible over HTTPS.  
No registration or contact with BLT-Zero is required — the Worker will discover your key automatically.

**Step 3 — Decrypt received reports:**

When you receive a report email with an ECDH-wrapped key package, save the JSON block from the email body to `blt-zero-key.json`, then run:
```bash
python tools/org_decrypt.py private_key.jwk blt-zero-key.json
```

This prints the recovered ZIP password. Use it to open the attached `.zip` file.

> **Legacy / Phase 1:** If you have not published a public key, reports still arrive with the plaintext password in the email body as before.  The well-known URL approach is a drop-in upgrade requiring no BLT-Zero configuration changes.

### Optional BLT points / BACON sync

BLT-Zero can **optionally** award BLT points/BACON for successful encrypted submissions
without ever sending plaintext report data to the main BLT platform.

- If the reporter supplies a `username` and you configure BLT sync, the Worker will
  POST a small JSON payload to the main BLT API:

  ```json
  { "username": "<reporter>", "domain_name": "<program domain>" }
  ```

- No report content, ciphertext, or fields derived from the encrypted package are sent.

To enable this integration:

1. Configure the following variables in `wrangler.toml` / `.dev.vars`:

   - `MAIN_BLT_API_URL` – base URL for the BLT API (defaults to `https://api.owaspblt.org`)
   - `MAIN_BLT_API_TOKEN` – BLT API token with permission to award points for Zero-Trust submissions

2. Deploy BLT-Zero with those values set.

If `MAIN_BLT_API_TOKEN` is not set, BLT sync is silently skipped and submissions
remain purely local to BLT-Zero.

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

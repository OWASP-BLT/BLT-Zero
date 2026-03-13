# BLT-Zero

**Zero-Trust Vulnerability Reporting — ciphertext-only delivery.**

BLT-Zero is a Cloudflare Workers site that lets security researchers submit sensitive vulnerability reports **encrypted in the browser** using the target organization’s **public key**. The Worker receives **ciphertext only**, forwards it to the organization’s security inbox, and stores only minimal metadata.

It is an independent application under the OWASP BLT project family, intended to run on its own deployment and database.

---

## 🔐 What is BLT-Zero?

BLT-Zero provides a **zero-trust workflow** for delivering vulnerability reports securely:

- **Encryption happens client-side (browser)** using the Web Crypto API.
- **BLT-Zero never receives plaintext** vulnerability details.
- **Organizations decrypt locally** using their private key.

### Key Principles

| Principle | Description |
|----------|-------------|
| **Ciphertext-only server** | Worker receives only an encrypted JSON package (no plaintext). |
| **Org-only decryption** | Reports are encrypted to the organization’s public key; only their private key can decrypt. |
| **Minimal metadata** | Only domain, optional username, hash, and timestamps are stored in D1. |
| **No tracking by design** | No analytics/cookies/fingerprinting in this project. |
| **Abuse controls** | Rate limiting + optional Cloudflare Turnstile. |

---

## 🏗️ Architecture

### Components

- **Client (Browser)**
  - Builds the report JSON in memory
  - Encrypts it using **P-256 ECDH + HKDF(SHA-256) + AES-GCM**
  - Sends only the encrypted package to the Worker

- **Worker (TypeScript)**
  - Validates request + (optional) Turnstile
  - Looks up the org public key for the domain from **D1**
  - Emails the encrypted JSON package to the org inbox (SendGrid or MailChannels)
  - Stores minimal metadata in D1 (no report content)

- **D1 (SQLite)**
  - `domains`: domain → org email + org public key (JWK) + key_id
  - `submissions`: submission id + domain + optional username + artifact hash
  - `rate_limits`: simple per-IP minute bucket counters

---

## 🔒 Cryptography (implemented)

**Client-side encryption**
- Org publishes a **P-256 public key** (JWK) to BLT-Zero (admin onboarding).
- Browser generates an **ephemeral P-256 keypair**, performs **ECDH**, derives AES key via **HKDF**, encrypts with **AES-GCM**.
- Output is a JSON “package” containing:
  - `eph_pub_jwk`, `salt`, `iv`, `ciphertext`, `key_id`, `domain`, etc.

**Decryption**
- Organization uses the private key locally with the provided `tools/org_decrypt.py`
- Produces `report.json` (plaintext) on the org side only.

---

## ✅ Features

- 🔒 End-to-end encryption in the browser (Worker never sees plaintext)
- 📧 Direct delivery to org security inbox (ciphertext attachment)
- 🧾 Minimal storage: domain + optional username + artifact hash only
- 🧑‍💼 Org onboarding page to register domain + public key and optionally send onboarding email
- 🧰 Tools
  - `tools/org_keygen.py` – generate org keypair locally
  - `tools/org_decrypt.py` – decrypt incoming packages locally
- 🛡️ Rate limiting
- 🧩 Optional Turnstile
  - Can be disabled for local dev using `DISABLE_TURNSTILE=true`
- 📊 Optional points/BACON sync to main BLT (metadata-only; no report contents)

---

## 🚀 Workflow (end-to-end)

1. Org admin generates keypair locally (private stays with org).
2. Org admin onboards domain + public key into BLT-Zero (`/admin/onboard`).
3. Reporter submits report → browser encrypts → Worker receives ciphertext only.
4. Worker emails ciphertext JSON attachment to org inbox + stores minimal metadata.
5. Org decrypts locally using `tools/org_decrypt.py`.

---

## 🛠️ Tech Stack

- Runtime: Cloudflare Workers
- Worker Language: TypeScript (best fit for Web Crypto + performance)
- Crypto: Web Crypto API (ECDH P-256 + HKDF + AES-GCM)
- DB: Cloudflare D1
- Email: SendGrid (recommended) or MailChannels
- Protection: optional Turnstile + rate limiting

---

### Installation

1. Clone the repository:
```bash
git clone https://github.com/OWASP-BLT/BLT-Zero.git
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

4. Create the D1 database:
```bash
wrangler d1 create blt_zero
```

5. Create `.dev.vars` file from `.dev.vars.example` and populate wrangler.toml with Database ID from previous step:

6. Apply database migrations:
```bash
# For local development
wrangler d1 migrations apply blt_zero --local

# For production (remote database)
wrangler d1 migrations apply blt_zero --remote
```

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

1. Generate organization keypair locally:
```bash
python tools/org_keygen.py
```

This will generate:

- `private_key.jwk` (keep this secret)
- `public_key.jwk` (share this with BLT-Zero)

2. Decrypt a received vulnerability report:
```bash
python tools/org_decrypt.py private_key.jwk package.json
```

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

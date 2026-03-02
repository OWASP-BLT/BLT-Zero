import { getDomain, upsertDomain, insertSubmission, rateLimitHit } from "./db";
import {
  normalizeDomain,
  getClientIp,
  minuteBucketISO,
  sha256Hex,
  verifyTurnstile,
  turnstileEnabled
} from "./security";
import {
  submitPage,
  docsSecurity,
  docsOrgOnboarding,
  docsDecrypt,
  adminOnboardPage,
  onboardingEmailBody
} from "./templates";

function json(data: any, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}
function html(s: string, status = 200) {
  return new Response(s, { status, headers: { "content-type": "text/html; charset=utf-8" } });
}

async function sendEmail(
  env: any,
  to: string,
  subject: string,
  body: string,
  attachmentName?: string,
  attachmentJson?: string
) {
  const provider = (env.EMAIL_PROVIDER || "mailchannels").toLowerCase();

  const fromEmail = env.SENDGRID_FROM_EMAIL || "no-reply@example.com";
  const fromName = env.SENDGRID_FROM_NAME || "BLT-Zero";

  // helper: UTF-8 → base64 (safe for JSON)
  const b64utf8 = (s: string) => {
    const bytes = new TextEncoder().encode(s);
    let bin = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      bin += String.fromCharCode(...bytes.subarray(i, i + chunk));
    }
    return btoa(bin);
  };

  if (provider === "sendgrid") {
    const apiKey = env.SENDGRID_API_KEY;
    if (!apiKey) throw new Error("SENDGRID_API_KEY missing.");

    const payload: any = {
      personalizations: [{ to: [{ email: to }] }],
      from: { email: fromEmail, name: fromName },
      subject,
      content: [{ type: "text/plain", value: body }],
    };

    if (attachmentName && attachmentJson) {
      payload.attachments = [{
        content: b64utf8(attachmentJson),
        filename: attachmentName,
        type: "application/json",
        disposition: "attachment"
      }];
    }

    const r = await fetch("https://api.sendgrid.com/v3/mail/send", {
      method: "POST",
      headers: {
        "authorization": `Bearer ${apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    // SendGrid returns 202 Accepted on success
    if (r.status !== 202) {
      const txt = await r.text().catch(() => "");
      throw new Error(`Email delivery failed (SendGrid): ${r.status} ${txt}`);
    }
    return;
  }
  // MailChannels
  const mailchannels: any = {
    personalizations: [{ to: [{ email: to }] }],
    from: { email: "no-reply@blt-zero.owasp.org", name: "BLT-Zero" },
    subject,
    content: [{ type: "text/plain", value: body }],
  };

  if (attachmentName && attachmentJson) {
    mailchannels.attachments = [
      {
        filename: attachmentName,
        contentType: "application/json",
        content: btoa(unescape(encodeURIComponent(attachmentJson))),
      },
    ];
  }

  const r = await fetch("https://api.mailchannels.net/tx/v1/send", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(mailchannels),
  });

  if (!r.ok) throw new Error("Email delivery failed (MailChannels).");
}

async function syncPoints(env: any, username: string, domain: string) {
  const token = env.MAIN_BLT_API_TOKEN;
  if (!token) return;
  await fetch(`${env.MAIN_BLT_API_URL}/api/v1/zero-trust-points/`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Token ${token}` },
    body: JSON.stringify({ username, domain_name: domain }),
  });
}

export default {
  async fetch(req: Request, env: any, ctx: any) {
    const url = new URL(req.url);
    const tsEnabled = turnstileEnabled(env);

    // UI
    if (req.method === "GET" && url.pathname === "/") {
      return html(
        submitPage({
          domainPrefill: url.searchParams.get("domain") || "",
          turnstileSiteKey: tsEnabled ? env.TURNSTILE_SITE_KEY : "",
          maxFiles: 3,
          maxTotalBytes: parseInt(env.MAX_UPLOAD_BYTES || "3145728", 10),
        })
      );
    }

    // Docs
    if (req.method === "GET" && url.pathname === "/docs/security") return html(docsSecurity());
    if (req.method === "GET" && url.pathname === "/docs/org-onboarding")
      return html(docsOrgOnboarding(env.APP_ORIGIN));
    if (req.method === "GET" && url.pathname === "/docs/decrypt") return html(docsDecrypt());

    // Admin page
    if (req.method === "GET" && url.pathname === "/admin/onboard") {
      return html(adminOnboardPage(tsEnabled ? env.TURNSTILE_SITE_KEY : ""));
    }

    // Admin onboard POST
    if (req.method === "POST" && url.pathname === "/admin/onboard") {
      const ip = getClientIp(req);
      let payload: any;
      try {
        payload = await req.json();
      } catch {
        return json({ error: "invalid json" }, 400);
      }

      const token = String(payload.admin_token || "");
      const turnstileToken = String(payload.turnstile_token || "");

      if (!token) return json({ error: "admin_token required" }, 400);
      if (tsEnabled && !turnstileToken) return json({ error: "turnstile_token required" }, 400);

      // Admin auth
      if (!env.ADMIN_TOKEN || token !== env.ADMIN_TOKEN) return json({ error: "unauthorized" }, 401);

      // Turnstile verify (auto-pass if disabled)
      const ok = await verifyTurnstile(env, turnstileToken, ip);
      if (!ok) return json({ error: "turnstile failed" }, 403);

      const domain = normalizeDomain(payload.domain || "");
      const org_email = String(payload.org_email || "").trim();
      const key_id = String(payload.key_id || "").trim();
      const public_key_jwk = String(payload.public_key_jwk || "").trim();
      const send_onboarding_email = !!payload.send_onboarding_email;

      if (!domain || !org_email || !key_id || !public_key_jwk) {
        return json({ error: "domain, org_email, key_id, public_key_jwk required" }, 400);
      }

      // Basic JWK validation (shape only)
      try {
        const jwk = JSON.parse(public_key_jwk);
        if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) {
          return json({ error: "public_key_jwk must be EC P-256 JWK" }, 400);
        }
      } catch {
        return json({ error: "public_key_jwk must be valid JSON" }, 400);
      }

      await upsertDomain(env, {
        domain,
        org_email,
        alg: "ECDH_P256_HKDF_SHA256_AESGCM",
        key_id,
        public_key_jwk,
        is_active: 1,
      });

      let emailSent = false;
      if (send_onboarding_email) {
        const subject = `BLT-Zero Onboarding — ${domain}`;
        const body = onboardingEmailBody(env.APP_ORIGIN, domain);
        await sendEmail(env, org_email, subject, body);
        emailSent = true;
      }

      return json({ ok: true, domain, email_sent: emailSent });
    }

    // Domain key fetch
    if (req.method === "GET" && url.pathname === "/api/domain") {
      const d = normalizeDomain(url.searchParams.get("domain") || "");
      if (!d) return json({ error: "domain required" }, 400);
      const row = await getDomain(env, d);
      if (!row || !row.is_active) return json({ error: "domain not registered" }, 404);
      return json({
        domain: row.domain,
        org_email: row.org_email,
        alg: row.alg,
        key_id: row.key_id,
        public_key_jwk: row.public_key_jwk,
      });
    }

    // Submit
    if (req.method === "POST" && url.pathname === "/submit") {
      const ip = getClientIp(req);
      const bucket = minuteBucketISO(new Date());
      const limitKey = `ip:${ip}:${bucket}`;
      const count = await rateLimitHit(env, limitKey, bucket);
      const maxPerMin = parseInt(env.RATE_LIMIT_PER_MINUTE || "5", 10);
      if (count > maxPerMin) return json({ error: "rate limit exceeded" }, 429);

      let payload: any;
      try {
        payload = await req.json();
      } catch {
        return json({ error: "invalid json" }, 400);
      }

      const domain = normalizeDomain(payload.domain || "");
      const username = payload.username ? String(payload.username).trim() : null;
      const turnstileToken = String(payload.turnstile_token || "");
      const encryptedPackage = payload.encrypted_package;

      if (!domain || !encryptedPackage) {
        return json({ error: "domain and encrypted_package required" }, 400);
      }
      if (tsEnabled && !turnstileToken) {
        return json({ error: "turnstile_token required" }, 400);
      }

      const ok = await verifyTurnstile(env, turnstileToken, ip);
      if (!ok) return json({ error: "turnstile failed" }, 403);

      const row = await getDomain(env, domain);
      if (!row || !row.is_active) return json({ error: "domain not registered" }, 404);

      // Validate encrypted package shape only
      if (encryptedPackage.domain !== domain) return json({ error: "domain mismatch" }, 400);
      if (
        !encryptedPackage.ciphertext_b64 ||
        !encryptedPackage.iv_b64 ||
        !encryptedPackage.salt_b64 ||
        !encryptedPackage.eph_pub_jwk
      ) {
        return json({ error: "invalid encrypted package" }, 400);
      }

      const pkgJson = JSON.stringify(encryptedPackage);
      const pkgBytes = new TextEncoder().encode(pkgJson);
      const maxBytes = parseInt(env.MAX_UPLOAD_BYTES || "3145728", 10);
      if (pkgBytes.byteLength > maxBytes) return json({ error: "encrypted package too large" }, 413);

      const artifactHash = await sha256Hex(pkgBytes);
      const submissionId = crypto.randomUUID();

      // Email ciphertext package to org
      const subject = `BLT-Zero Encrypted Report — ${domain} — ${submissionId}`;
      const body = [
        `Encrypted vulnerability report for: ${domain}`,
        `Submission ID: ${submissionId}`,
        `Ciphertext SHA-256: ${artifactHash}`,
        ``,
        `Decrypt guide: ${env.APP_ORIGIN}/docs/decrypt`,
        `Security model: ${env.APP_ORIGIN}/docs/security`,
        ``,
        `BLT-Zero cannot decrypt this report.`,
      ].join("\n");

      await sendEmail(
        env,
        row.org_email,
        subject,
        body,
        `blt-zero-${domain}-${artifactHash}.json`,
        pkgJson
      );

      // Store minimal metadata
      await insertSubmission(env, {
        id: submissionId,
        domain,
        username,
        artifact_hash: artifactHash,
      });

      // Points sync async
      if (username) ctx.waitUntil(syncPoints(env, username, domain));

      return json({ ok: true, submission_id: submissionId, artifact_hash: artifactHash });
    }

    return new Response("Not found", { status: 404 });
  },
};
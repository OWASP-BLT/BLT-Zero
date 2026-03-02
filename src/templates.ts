function esc(s: string) {
  return s.replace(/[&<>"']/g, (c) =>
    ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;",
    }[c] as string)
  );
}
function isTurnstileEnabled(siteKey: string | undefined | null): boolean {
  const v = (siteKey ?? "").trim().toLowerCase();
  if (!v) return false;
  if (v === "false" || v === "0" || v === "null" || v === "undefined") return false;
  return true;
}

export function layout(title: string, body: string, includeTurnstileScript: boolean) {
  return `<!doctype html><html><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>${esc(title)}</title>
<style>
  body{font-family:system-ui;margin:0;background:#0b0f17;color:#e8eefc}
  a{color:#9ecbff}
  .wrap{max-width:880px;margin:0 auto;padding:24px}
  .card{background:#121a28;border:1px solid #24314b;border-radius:14px;padding:18px;margin:14px 0}
  label{display:block;margin:10px 0 6px}
  input,textarea{width:100%;padding:10px;border-radius:10px;border:1px solid #2a3958;background:#0b0f17;color:#e8eefc}
  button{padding:10px 14px;border-radius:10px;border:0;background:#3b82f6;color:white;font-weight:600;cursor:pointer}
  code,pre{background:#0b0f17;border:1px solid #24314b;padding:8px;border-radius:10px;overflow:auto}
  .muted{color:#b8c5e6}
  .row{display:flex;gap:12px;flex-wrap:wrap}
  .row>div{flex:1 1 260px}
  .pill{display:inline-block;padding:2px 10px;border:1px solid #2a3958;border-radius:999px}
  .small{font-size:13px}
  .warn{color:#ffd08a}
</style>
${includeTurnstileScript ? `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>` : ""}
</head><body><div class="wrap">
<h1>${esc(title)}</h1>
${body}
</div></body></html>`;
}

export function submitPage(opts: {
  domainPrefill?: string;
  turnstileSiteKey?: string; // empty means disabled
  maxFiles: number;
  maxTotalBytes: number;
}) {
  const tsEnabled = isTurnstileEnabled(opts.turnstileSiteKey);

  const turnstileHtml = tsEnabled
    ? `<div class="cf-turnstile" data-sitekey="${esc(opts.turnstileSiteKey ?? "")}"></div>`
    : `<p class="small muted">Turnstile disabled (local testing).</p>`;

  const body = `
<div class="card">
  <div class="muted">
    <span class="pill">Zero-Trust</span>
    <span class="pill">No plaintext to server</span>
    <span class="pill">Org-only decryption</span>
  </div>
  <p class="muted">
    Your report is encrypted <b>in your browser</b> using the organization’s public key.
    BLT-Zero receives <b>ciphertext only</b>.
  </p>
  <ul class="small muted">
    <li>Max screenshots: <b>${opts.maxFiles}</b></li>
    <li>Encrypted package cap: <b>${Math.floor(opts.maxTotalBytes / (1024 * 1024))} MB</b></li>
  </ul>
</div>

<div class="card">
  <form id="f">
    <label>Target Domain</label>
    <input id="domain" value="${esc(opts.domainPrefill || "")}" placeholder="example.com" required/>

    <div class="row">
      <div>
        <label>Your BLT Username (optional, for points)</label>
        <input id="username" placeholder="your_blt_username"/>
      </div>
      <div>
        <label>Target URL</label>
        <input id="url" placeholder="https://example.com/path" required/>
      </div>
    </div>

    <label>Vulnerability Description</label>
    <textarea id="description" rows="5" required></textarea>

    <label>Detailed Report (Markdown, optional)</label>
    <textarea id="markdown" rows="7"></textarea>

    <label>Screenshots (optional, up to ${opts.maxFiles})</label>
    <input type="file" id="shots" accept="image/*" multiple/>

    ${turnstileHtml}

    <p class="warn small" id="limitMsg"></p>

    <button type="submit" id="btn">Encrypt & Submit</button>
    <p class="small muted" id="status"></p>
  </form>
</div>

<div class="card small muted">
  <a href="/docs/security">Security model</a> •
  <a href="/docs/org-onboarding">Org onboarding</a> •
  <a href="/docs/decrypt">Decrypt guide</a> •
  <a href="/admin/onboard">Org admin onboard</a>
</div>

<script>
const MAX_FILES = ${opts.maxFiles};
const MAX_TOTAL = ${opts.maxTotalBytes};
const TURNSTILE_ENABLED = ${tsEnabled ? "true" : "false"};

function b64(u8){
  let s=""; const chunk=0x8000;
  for(let i=0;i<u8.length;i+=chunk){ s += String.fromCharCode.apply(null, u8.subarray(i,i+chunk)); }
  return btoa(s);
}

async function sha256Hex(ab){
  const dig = await crypto.subtle.digest("SHA-256", ab);
  const bytes = new Uint8Array(dig);
  return [...bytes].map(b=>b.toString(16).padStart(2,"0")).join("");
}

async function importOrgKey(jwk){
  return await crypto.subtle.importKey("jwk", jwk, {name:"ECDH", namedCurve:"P-256"}, false, []);
}
async function genEphemeral(){
  return await crypto.subtle.generateKey({name:"ECDH", namedCurve:"P-256"}, true, ["deriveBits"]);
}
async function deriveAesKey(ephPriv, orgPub, saltU8){
  const bits = await crypto.subtle.deriveBits({name:"ECDH", public:orgPub}, ephPriv, 256);
  const ikm = new Uint8Array(bits);
  const hkdfKey = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
  return await crypto.subtle.deriveKey(
    {name:"HKDF", hash:"SHA-256", salt:saltU8, info:new TextEncoder().encode("blt-zero-v1")},
    hkdfKey,
    {name:"AES-GCM", length:256},
    false,
    ["encrypt"]
  );
}
async function fetchDomainKey(domain){
  const r = await fetch("/api/domain?domain="+encodeURIComponent(domain));
  if(!r.ok) throw new Error("Domain not registered for BLT-Zero.");
  return await r.json();
}
async function readFilesLimited(fileList){
  const files = [...fileList].slice(0, MAX_FILES);
  const out = [];
  for(const f of files){
    const ab = await f.arrayBuffer();
    out.push({
      filename:f.name,
      mime:f.type || "application/octet-stream",
      size:ab.byteLength,
      sha256: await sha256Hex(ab),
      b64: b64(new Uint8Array(ab))
    });
  }
  return out;
}

document.getElementById("f").addEventListener("submit", async (e)=>{
  e.preventDefault();
  const status = document.getElementById("status");
  const btn = document.getElementById("btn");
  const limitMsg = document.getElementById("limitMsg");
  limitMsg.textContent="";
  status.textContent="";
  btn.disabled=true;

  try{
    const domain = document.getElementById("domain").value.trim().toLowerCase();
    const username = document.getElementById("username").value.trim() || null;
    const url = document.getElementById("url").value.trim();
    const description = document.getElementById("description").value.trim();
    const markdown = document.getElementById("markdown").value.trim() || null;

    let turnstileToken = "";
    if (TURNSTILE_ENABLED){
      turnstileToken = document.querySelector('input[name="cf-turnstile-response"]')?.value || "";
      if(!turnstileToken) throw new Error("Turnstile missing. Retry.");
    }

    status.textContent="Loading org key…";
    const org = await fetchDomainKey(domain);
    const orgJwk = JSON.parse(org.public_key_jwk);
    const orgPub = await importOrgKey(orgJwk);

    status.textContent="Preparing screenshots…";
    const shots = await readFilesLimited(document.getElementById("shots").files || []);

    // Plaintext exists ONLY in browser memory (never sent)
    const report = {
      v:1, domain, url, username, description, markdown,
      screenshots: shots.map(s=>({filename:s.filename,mime:s.mime,size:s.size,sha256:s.sha256})),
      screenshots_b64: shots.map(s=>({filename:s.filename,b64:s.b64})),
      created_at: new Date().toISOString()
    };

    status.textContent="Encrypting…";
    const reportBytes = new TextEncoder().encode(JSON.stringify(report));

    const eph = await genEphemeral();
    const ephPubJwk = await crypto.subtle.exportKey("jwk", eph.publicKey);

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aesKey = await deriveAesKey(eph.privateKey, orgPub, salt);

    const ct = await crypto.subtle.encrypt({name:"AES-GCM", iv}, aesKey, reportBytes);

    const pkg = {
      v:1, alg:org.alg, key_id:org.key_id,
      domain, username,
      eph_pub_jwk: ephPubJwk,
      salt_b64: b64(salt),
      iv_b64: b64(iv),
      ciphertext_b64: b64(new Uint8Array(ct))
    };

    const pkgBytes = new TextEncoder().encode(JSON.stringify(pkg));
    if(pkgBytes.byteLength > MAX_TOTAL){
      limitMsg.textContent="Encrypted package too large. Reduce screenshots/size.";
      throw new Error("Size limit exceeded.");
    }

    status.textContent="Submitting…";
    const resp = await fetch("/submit", {
      method:"POST",
      headers: {"content-type":"application/json"},
      body: JSON.stringify({
        domain, username,
        turnstile_token: turnstileToken,
        encrypted_package: pkg
      })
    });

    const out = await resp.json().catch(()=>({}));
    if(!resp.ok) throw new Error(out?.error || "Submit failed.");

    status.innerHTML = "✅ Submitted. ID: <code>"+out.submission_id+"</code>";
  }catch(err){
    status.textContent = "❌ " + (err?.message || String(err));
  }finally{
    btn.disabled=false;
  }
});
</script>
`;

  return layout("BLT-Zero — Submit Encrypted Report", body, tsEnabled);
}

export function docsSecurity() {
  return layout(
    "BLT-Zero — Security Model",
    `
<div class="card">
  <p><b>Guarantee:</b> Worker never receives plaintext vulnerability details.</p>
  <ul>
    <li>Reporter browser encrypts using org public key (P-256 ECDH + HKDF + AES-GCM).</li>
    <li>Worker receives ciphertext package and forwards to org inbox.</li>
    <li>D1 stores only domain, username(optional), hash, timestamp, org public key.</li>
  </ul>
</div>`,
    false
  );
}

export function docsOrgOnboarding(appOrigin: string) {
  return layout(
    "BLT-Zero — Org Onboarding",
    `
<div class="card">
  <h3>What org admin does</h3>
  <ol>
    <li>Generate keypair locally (private stays with org)</li>
    <li>Upload public key to BLT-Zero via admin onboarding page</li>
    <li>Decrypt incoming reports locally with private key</li>
  </ol>
</div>

<div class="card">
  <h3>Scripts</h3>
  <p>We provide scripts in the BLT-Zero repo under <code>tools/</code>.</p>
  <pre>${esc(`${appOrigin}/docs/decrypt\n${appOrigin}/docs/security`)}</pre>
</div>`,
    false
  );
}

export function docsDecrypt() {
  return layout(
    "BLT-Zero — Decrypt Guide",
    `
<div class="card">
  <ol>
    <li>Download the JSON attachment from the BLT-Zero email</li>
    <li>Run:
      <pre>python tools/org_decrypt.py private_key.jwk package.json</pre>
    </li>
    <li>Output: <code>report.json</code></li>
  </ol>
</div>`,
    false
  );
}

export function adminOnboardPage(turnstileSiteKey?: string) {
  const tsEnabled = isTurnstileEnabled(turnstileSiteKey);

  const turnstileHtml = tsEnabled
    ? `<div class="cf-turnstile" data-sitekey="${esc(turnstileSiteKey ?? "")}"></div>`
    : `<p class="small muted">Turnstile disabled (local testing).</p>`;

  return layout(
    "BLT-Zero — Org Admin Onboarding",
    `
<div class="card">
  <p class="muted">This page inserts/updates a domain entry in D1 and can send an onboarding email.</p>
  <p class="warn small">Protected by ADMIN_TOKEN ${tsEnabled ? "+ Turnstile" : "(Turnstile disabled)"}.</p>
</div>

<div class="card">
  <form id="a">
    <label>ADMIN TOKEN</label>
    <input id="token" placeholder="paste ADMIN_TOKEN" required/>

    <div class="row">
      <div>
        <label>Domain</label>
        <input id="domain" placeholder="example.com" required/>
      </div>
      <div>
        <label>Security Inbox Email</label>
        <input id="email" placeholder="security@example.com" required/>
      </div>
    </div>

    <label>Public Key (JWK JSON)</label>
    <textarea id="jwk" rows="8" placeholder='{"kty":"EC","crv":"P-256",...}' required></textarea>

    <label>Key ID</label>
    <input id="keyid" placeholder="hex string" required/>

    <label>Send onboarding email now?</label>
    <input type="checkbox" id="sendmail" checked/>

    ${turnstileHtml}

    <button type="submit">Onboard Domain</button>
    <p class="small muted" id="out"></p>
  </form>
</div>

<script>
const TURNSTILE_ENABLED = ${tsEnabled ? "true" : "false"};

document.getElementById("a").addEventListener("submit", async (e)=>{
  e.preventDefault();
  const out = document.getElementById("out");
  out.textContent="";

  let turnstileToken = "";
  if (TURNSTILE_ENABLED){
    turnstileToken = document.querySelector('input[name="cf-turnstile-response"]')?.value || "";
    if(!turnstileToken){ out.textContent="Turnstile missing."; return; }
  }

  try{
    const resp = await fetch("/admin/onboard", {
      method:"POST",
      headers: {"content-type":"application/json"},
      body: JSON.stringify({
        admin_token: document.getElementById("token").value.trim(),
        turnstile_token: turnstileToken,
        domain: document.getElementById("domain").value.trim().toLowerCase(),
        org_email: document.getElementById("email").value.trim(),
        key_id: document.getElementById("keyid").value.trim(),
        public_key_jwk: document.getElementById("jwk").value.trim(),
        send_onboarding_email: document.getElementById("sendmail").checked
      })
    });
    const j = await resp.json().catch(()=>({}));
    if(!resp.ok) throw new Error(j?.error || "Onboard failed");
    out.textContent = "✅ Onboarded: " + j.domain + (j.email_sent ? " (email sent)" : "");
  }catch(err){
    out.textContent = "❌ " + (err?.message || String(err));
  }
});
</script>
`,
    tsEnabled
  );
}

export function onboardingEmailBody(appOrigin: string, domain: string) {
  return `Hello Security Team,

You have been onboarded to BLT-Zero (blt-zero.owasp.org) for domain: ${domain}

How it works:
- Reporters encrypt in their browser using your public key.
- BLT-Zero receives only ciphertext and emails it to you.
- Only your private key can decrypt.

Next steps:
- Decrypt guide: ${appOrigin}/docs/decrypt
- Security model: ${appOrigin}/docs/security

Regards,
BLT-Zero Maintainers (OWASP BLT)
`;
}
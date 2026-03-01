export function normalizeDomain(input: string): string {
  return input.trim().toLowerCase();
}

export function getClientIp(req: Request): string {
  return req.headers.get("CF-Connecting-IP") || "0.0.0.0";
}

export function minuteBucketISO(date = new Date()): string {
  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, "0");
  const d = String(date.getUTCDate()).padStart(2, "0");
  const hh = String(date.getUTCHours()).padStart(2, "0");
  const mm = String(date.getUTCMinutes()).padStart(2, "0");
  return `${y}-${m}-${d}T${hh}:${mm}`;
}

/**
 * ✅ Guarantee a "real" ArrayBuffer (not ArrayBufferLike / SharedArrayBuffer)
 * by copying into a fresh Uint8Array.
 */
function toPlainArrayBuffer(input: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(input.byteLength);
  copy.set(input);
  return copy.buffer; // this is guaranteed ArrayBuffer
}

export async function sha256Hex(data: Uint8Array): Promise<string> {
  const ab = toPlainArrayBuffer(data);
  const digest = await crypto.subtle.digest("SHA-256", ab);
  const bytes = new Uint8Array(digest);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
export function turnstileEnabled(env: any): boolean {
  return env.DISABLE_TURNSTILE !== "true" && !!env.TURNSTILE_SITE_KEY && !!env.TURNSTILE_SECRET;
}

export async function verifyTurnstile(env: any, token: string, ip: string): Promise<boolean> {
  // If disabled, always pass.
  if (!turnstileEnabled(env)) return true;

  const form = new FormData();
  form.append("secret", env.TURNSTILE_SECRET);
  form.append("response", token);
  form.append("remoteip", ip);

  const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    body: form,
  });

  if (!resp.ok) return false;
  const json: any = await resp.json();
  return !!json.success;
}
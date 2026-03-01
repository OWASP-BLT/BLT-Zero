export type DomainRow = {
  domain: string;
  org_email: string;
  is_active: number;
  alg: string;
  key_id: string;
  public_key_jwk: string;
};

export async function getDomain(env: any, domain: string): Promise<DomainRow | null> {
  const q = `SELECT domain, org_email, is_active, alg, key_id, public_key_jwk
             FROM domains WHERE domain = ? LIMIT 1`;
  const res = await env.DB.prepare(q).bind(domain).all();
  if (!res.results?.length) return null;
  return res.results[0] as DomainRow;
}

export async function upsertDomain(
  env: any,
  data: { domain: string; org_email: string; alg: string; key_id: string; public_key_jwk: string; is_active: number }
) {
  const q = `
    INSERT INTO domains (domain, org_email, alg, key_id, public_key_jwk, is_active, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, (strftime('%Y-%m-%dT%H:%M:%fZ','now')))
    ON CONFLICT(domain) DO UPDATE SET
      org_email=excluded.org_email,
      alg=excluded.alg,
      key_id=excluded.key_id,
      public_key_jwk=excluded.public_key_jwk,
      is_active=excluded.is_active,
      updated_at=(strftime('%Y-%m-%dT%H:%M:%fZ','now'))
  `;
  await env.DB.prepare(q).bind(
    data.domain, data.org_email, data.alg, data.key_id, data.public_key_jwk, data.is_active
  ).run();
}

export async function insertSubmission(
  env: any,
  submission: { id: string; domain: string; username?: string | null; artifact_hash: string }
) {
  const q = `INSERT INTO submissions (id, domain, username, artifact_hash) VALUES (?,?,?,?)`;
  await env.DB.prepare(q).bind(
    submission.id,
    submission.domain,
    submission.username ?? null,
    submission.artifact_hash
  ).run();
}

export async function rateLimitHit(env: any, key: string, windowStart: string) {
  const existing = await env.DB.prepare(`SELECT count FROM rate_limits WHERE k = ? LIMIT 1`)
    .bind(key)
    .all();

  if (!existing.results?.length) {
    await env.DB.prepare(`INSERT INTO rate_limits (k, count, window_start) VALUES (?,?,?)`)
      .bind(key, 1, windowStart)
      .run();
    return 1;
  }

  const count = (existing.results[0] as any).count + 1;
  await env.DB.prepare(`UPDATE rate_limits SET count = ? WHERE k = ?`).bind(count, key).run();
  return count;
}
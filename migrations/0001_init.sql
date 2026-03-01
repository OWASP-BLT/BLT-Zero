-- 0001_init.sql
CREATE TABLE IF NOT EXISTS domains (
  domain TEXT PRIMARY KEY,
  org_email TEXT NOT NULL,
  is_active INTEGER NOT NULL DEFAULT 1,

  alg TEXT NOT NULL DEFAULT 'ECDH_P256_HKDF_SHA256_AESGCM',
  key_id TEXT NOT NULL,
  public_key_jwk TEXT NOT NULL,

  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS submissions (
  id TEXT PRIMARY KEY,
  domain TEXT NOT NULL,
  username TEXT,
  artifact_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS rate_limits (
  k TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  window_start TEXT NOT NULL
);
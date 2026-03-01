-- 0002_indexes.sql
-- Helpful indexes for lookups & filtering
CREATE INDEX IF NOT EXISTS idx_submissions_domain_created
  ON submissions(domain, created_at);

CREATE INDEX IF NOT EXISTS idx_submissions_username_created
  ON submissions(username, created_at);

CREATE INDEX IF NOT EXISTS idx_rate_limits_window
  ON rate_limits(window_start);
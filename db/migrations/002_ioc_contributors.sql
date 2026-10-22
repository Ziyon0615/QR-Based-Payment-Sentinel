ALTER TABLE iocs
  ADD COLUMN IF NOT EXISTS submitted_by_user_id TEXT REFERENCES users(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_iocs_submitted_by_user_id
  ON iocs(submitted_by_user_id);

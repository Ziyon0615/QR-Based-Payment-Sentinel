CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL,
  payload_hash TEXT NOT NULL,
  payload_preview TEXT NOT NULL,
  payload_type TEXT NOT NULL,
  normalized_url TEXT,
  domain TEXT,
  risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  classification TEXT NOT NULL CHECK (classification IN ('Safe', 'Suspicious', 'Malicious')),
  indicators_json JSONB NOT NULL,
  observables_json JSONB NOT NULL,
  payment_context_json JSONB,
  redirect_chain_json JSONB NOT NULL,
  latency_ms DOUBLE PRECISION NOT NULL,
  source TEXT NOT NULL,
  expected_label TEXT CHECK (expected_label IS NULL OR expected_label IN ('Safe', 'Suspicious', 'Malicious')),
  user_id TEXT
);

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_classification ON scans(classification);

CREATE TABLE IF NOT EXISTS iocs (
  id TEXT PRIMARY KEY,
  indicator TEXT NOT NULL,
  indicator_type TEXT NOT NULL CHECK (indicator_type IN ('url', 'domain', 'ip')),
  severity TEXT NOT NULL,
  confidence INTEGER NOT NULL DEFAULT 80 CHECK (confidence BETWEEN 0 AND 100),
  source TEXT NOT NULL,
  notes TEXT,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  first_seen TIMESTAMPTZ NOT NULL,
  last_seen TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_indicator_type_lower
  ON iocs(indicator_type, lower(indicator));

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  email TEXT,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower ON users(lower(username));
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_lower ON users(lower(email)) WHERE email IS NOT NULL;

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

ALTER TABLE scans ADD COLUMN IF NOT EXISTS user_id TEXT REFERENCES users(id) ON DELETE SET NULL;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'scans_user_id_fkey') THEN
    ALTER TABLE scans ADD CONSTRAINT scans_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_scans_user_created_at ON scans(user_id, created_at DESC);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  action TEXT NOT NULL,
  detail_json JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_created_at ON audit_logs(user_id, created_at DESC);

INSERT INTO users (id, username, email, password_hash, password_salt, role, created_at)
VALUES (
  '832a2ddf-9a0b-49e0-a722-3665fc84e073',
  'qradmin',
  NULL,
  '9cc4adbf9eb862c35d37978b37fed7abba7cbbc194891442c9558bbdf7abe13eb4e194dd76d035fd5127e1ab0f8c6ff7e4cb14dbe91124b1e360ace2a7dba3cd',
  'c3418ee69d04adf3823a75e3bd8541c7',
  'admin',
  NOW()
)
ON CONFLICT DO NOTHING;

INSERT INTO iocs (id, indicator, indicator_type, severity, confidence, source, notes, active, first_seen, last_seen)
VALUES
  ('2d66924d-cdde-449a-86c0-8e8ca4d4f093', 'phishing.test', 'domain', 'critical', 100, 'Controlled test data', 'Reserved academic test indicator', TRUE, NOW(), NOW()),
  ('f4f0af88-cef9-483f-92b8-ac47881489d2', 'malicious.example', 'domain', 'critical', 100, 'Controlled test data', 'Reserved academic test indicator', TRUE, NOW(), NOW()),
  ('1969b315-556a-4ab7-80a7-925d500411f1', 'https://malicious.example/collect', 'url', 'critical', 100, 'Controlled test data', 'Reserved academic test indicator', TRUE, NOW(), NOW())
ON CONFLICT (indicator_type, (lower(indicator))) DO NOTHING;

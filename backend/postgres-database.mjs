import pg from "pg";
import { attachDatabasePool } from "@vercel/functions";
import { createHash, randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";

const { Pool } = pg;
const globalKey = Symbol.for("qr-sentinel.postgres-pool");
const globalStore = globalThis;

if (!globalStore[globalKey]) {
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    max: 10,
    idleTimeoutMillis: 20_000,
    connectionTimeoutMillis: 10_000,
  });
  if (process.env.VERCEL) attachDatabasePool(pool);
  globalStore[globalKey] = pool;
}

const pool = globalStore[globalKey];

function passwordHash(password, salt) {
  return scryptSync(password, salt, 64).toString("hex");
}

function publicUser(row) {
  return row ? {
    id: row.id,
    username: row.username,
    email: row.email,
    role: row.role,
    createdAt: new Date(row.created_at).toISOString(),
  } : null;
}

function jsonValue(value, fallback) {
  if (value === null || value === undefined) return fallback;
  if (typeof value !== "string") return value;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function hydrateScan(row) {
  const recommendation = row.classification === "Safe"
    ? "No high-risk indicators were detected. Verify the merchant and amount before continuing."
    : row.classification === "Suspicious"
      ? "Pause and verify the merchant or destination through an independent channel."
      : "Do not open the destination or proceed with payment. Report the QR code to the merchant or provider.";
  return {
    ...row,
    indicators: jsonValue(row.indicators_json, []),
    observables: jsonValue(row.observables_json, {}),
    paymentContext: jsonValue(row.payment_context_json, null),
    redirectChain: jsonValue(row.redirect_chain_json, []),
    riskScore: row.risk_score,
    payloadPreview: row.payload_preview,
    payloadType: row.payload_type,
    normalizedUrl: row.normalized_url,
    latencyMs: Number(row.latency_ms),
    createdAt: new Date(row.created_at).toISOString(),
    expectedLabel: row.expected_label,
    recommendation,
  };
}
export async function registerUser(input) {
  const username = String(input.username || "").trim();
  const email = String(input.email || "").trim().toLowerCase();
  const password = String(input.password || "");
  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) throw new Error("Username must be 3 to 32 letters, numbers, dots, dashes, or underscores.");
  if (!/[a-zA-Z]/.test(username)) throw new Error("Username cannot contain numbers only. Add at least one letter.");
  if (email.length > 254 || !/^[a-z0-9._%+-]+@gmail\.com$/i.test(email)) throw new Error("Enter a valid Gmail address ending in @gmail.com.");
  if (password.length < 8 || password.length > 128) throw new Error("Password must be between 8 and 128 characters.");

  const existing = await pool.query(
    "SELECT username, email FROM users WHERE lower(username) = lower($1) OR lower(email) = lower($2) LIMIT 1",
    [username, email],
  );
  if (existing.rows.some((row) => row.username.toLowerCase() === username.toLowerCase())) throw new Error("Username is already registered.");
  if (existing.rows.some((row) => row.email?.toLowerCase() === email)) throw new Error("Gmail address is already registered.");

  const salt = randomBytes(16).toString("hex");
  const user = { id: randomUUID(), username, email, role: "user", createdAt: new Date().toISOString() };
  await pool.query(
    "INSERT INTO users (id, username, email, password_hash, password_salt, role, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)",
    [user.id, user.username, user.email, passwordHash(password, salt), salt, user.role, user.createdAt],
  );
  return user;
}

export async function authenticateUser(usernameInput, passwordInput) {
  const username = String(usernameInput || "").trim();
  const password = String(passwordInput || "");
  const result = await pool.query("SELECT * FROM users WHERE lower(username) = lower($1) LIMIT 1", [username]);
  const row = result.rows[0];
  if (!row) return null;
  const supplied = Buffer.from(passwordHash(password, row.password_salt), "hex");
  const stored = Buffer.from(row.password_hash, "hex");
  return supplied.length === stored.length && timingSafeEqual(supplied, stored) ? publicUser(row) : null;
}

export async function createSession(userId) {
  await pool.query("DELETE FROM sessions WHERE expires_at <= NOW()");
  const token = randomBytes(32).toString("hex");
  const tokenHash = createHash("sha256").update(token).digest("hex");
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + 12 * 60 * 60 * 1000);
  await pool.query(
    "INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES ($1, $2, $3, $4)",
    [tokenHash, userId, createdAt, expiresAt],
  );
  return { token, expiresAt };
}

export async function getSessionUser(token) {
  if (!token) return null;
  const tokenHash = createHash("sha256").update(token).digest("hex");
  const result = await pool.query(`
    SELECT users.* FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = $1 AND sessions.expires_at > NOW()
    LIMIT 1
  `, [tokenHash]);
  return publicUser(result.rows[0]);
}

export async function deleteSession(token) {
  if (!token) return;
  const tokenHash = createHash("sha256").update(token).digest("hex");
  await pool.query("DELETE FROM sessions WHERE token_hash = $1", [tokenHash]);
}

export async function findIocMatches({ urls = [], domains = [], ips = [] }) {
  const candidates = [
    ...urls.map((value) => ["url", value]),
    ...domains.map((value) => ["domain", value]),
    ...ips.map((value) => ["ip", value]),
  ];
  if (!candidates.length) return [];
  const values = [];
  const placeholders = candidates.map(([type, value], index) => {
    values.push(type, value);
    const offset = index * 2;
    return `(indicator_type = $${offset + 1} AND lower(indicator) = lower($${offset + 2}))`;
  });
  const result = await pool.query(`
    SELECT * FROM iocs
    WHERE active = TRUE AND (expires_at IS NULL OR expires_at > NOW())
      AND (${placeholders.join(" OR ")})
  `, values);
  return result.rows;
}

export async function saveScan(result, input) {
  const id = randomUUID();
  const createdAt = new Date().toISOString();
  await pool.query(`
    INSERT INTO scans (
      id, created_at, payload_hash, payload_preview, payload_type,
      normalized_url, domain, risk_score, classification, indicators_json,
      observables_json, payment_context_json, redirect_chain_json, latency_ms,
      source, expected_label
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, $12::jsonb, $13::jsonb, $14, $15, $16)
  `, [
    id, createdAt, result.payloadHash, result.payloadPreview, result.payloadType,
    result.normalizedUrl || null, result.domain || null, result.riskScore,
    result.classification, JSON.stringify(result.indicators), JSON.stringify(result.observables),
    JSON.stringify(result.paymentContext), JSON.stringify(result.redirectChain), result.latencyMs,
    input.source || "manual", input.expectedLabel || null,
  ]);
  return { ...result, id, createdAt, source: input.source || "manual", expectedLabel: input.expectedLabel || null };
}

export async function listScans(limit = 30) {
  const safeLimit = Math.min(Math.max(Number(limit) || 30, 1), 200);
  const result = await pool.query("SELECT * FROM scans ORDER BY created_at DESC LIMIT $1", [safeLimit]);
  return result.rows.map(hydrateScan);
}

export async function listIocs() {
  const result = await pool.query("SELECT * FROM iocs ORDER BY last_seen DESC, indicator ASC");
  return result.rows;
}

export async function addIoc(input) {
  const timestamp = new Date().toISOString();
  const id = randomUUID();
  const result = await pool.query(`
    INSERT INTO iocs (id, indicator, indicator_type, severity, confidence, source, notes, active, first_seen, last_seen, expires_at)
    VALUES ($1, $2, $3, $4, $5, $6, $7, TRUE, $8, $8, $9)
    ON CONFLICT (indicator_type, (lower(indicator))) DO UPDATE SET
      severity = EXCLUDED.severity,
      confidence = EXCLUDED.confidence,
      source = EXCLUDED.source,
      notes = EXCLUDED.notes,
      active = TRUE,
      last_seen = EXCLUDED.last_seen,
      expires_at = EXCLUDED.expires_at
    RETURNING *
  `, [
    id, input.indicator.trim(), input.indicatorType, input.severity || "high",
    Number(input.confidence ?? 80), input.source || "Manual entry", input.notes || null,
    timestamp, input.expiresAt || null,
  ]);
  return result.rows[0];
}

export async function getStats() {
  const [summaryResult, latenciesResult, labeledResult] = await Promise.all([
    pool.query(`
      SELECT COUNT(*)::int total,
        COUNT(*) FILTER (WHERE classification = 'Safe')::int safe,
        COUNT(*) FILTER (WHERE classification = 'Suspicious')::int suspicious,
        COUNT(*) FILTER (WHERE classification = 'Malicious')::int malicious,
        COALESCE(ROUND(AVG(latency_ms)::numeric, 2), 0)::float8 mean_latency
      FROM scans
    `),
    pool.query("SELECT latency_ms FROM scans ORDER BY latency_ms"),
    pool.query("SELECT classification, expected_label FROM scans WHERE expected_label IS NOT NULL"),
  ]);
  const summary = summaryResult.rows[0];
  const latencies = latenciesResult.rows.map((row) => Number(row.latency_ms));
  const p95Index = latencies.length ? Math.ceil(latencies.length * 0.95) - 1 : 0;
  let tp = 0, tn = 0, fp = 0, fn = 0;
  for (const row of labeledResult.rows) {
    const actualPositive = row.expected_label !== "Safe";
    const predictedPositive = row.classification !== "Safe";
    if (actualPositive && predictedPositive) tp += 1;
    else if (!actualPositive && !predictedPositive) tn += 1;
    else if (!actualPositive && predictedPositive) fp += 1;
    else fn += 1;
  }
  const ratio = (a, b) => (b ? Number((a / b).toFixed(4)) : null);
  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, tp + fn);
  return {
    total: summary.total || 0,
    safe: summary.safe || 0,
    suspicious: summary.suspicious || 0,
    malicious: summary.malicious || 0,
    meanLatencyMs: summary.mean_latency || 0,
    p95LatencyMs: latencies.length ? latencies[p95Index] : 0,
    evaluation: {
      sampleSize: labeledResult.rows.length,
      tp, tn, fp, fn,
      accuracy: ratio(tp + tn, tp + tn + fp + fn),
      precision,
      recall,
      f1: precision !== null && recall !== null && precision + recall ? Number((2 * precision * recall / (precision + recall)).toFixed(4)) : null,
      falsePositiveRate: ratio(fp, fp + tn),
      falseNegativeRate: ratio(fn, fn + tp),
    },
  };
}


import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { createHash, randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";

const databasePath = resolve(process.env.DATABASE_PATH || "data/qr-sentinel.db");
mkdirSync(dirname(databasePath), { recursive: true });

const db = new DatabaseSync(databasePath);
db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
db.exec(`
  CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    payload_preview TEXT NOT NULL,
    payload_type TEXT NOT NULL,
    normalized_url TEXT,
    domain TEXT,
    risk_score INTEGER NOT NULL,
    classification TEXT NOT NULL,
    indicators_json TEXT NOT NULL,
    observables_json TEXT NOT NULL,
    payment_context_json TEXT,
    redirect_chain_json TEXT NOT NULL,
    latency_ms REAL NOT NULL,
    source TEXT NOT NULL,
    expected_label TEXT
  );

  CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_scans_classification ON scans(classification);

  CREATE TABLE IF NOT EXISTS iocs (
    id TEXT PRIMARY KEY,
    indicator TEXT NOT NULL COLLATE NOCASE,
    indicator_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence INTEGER NOT NULL DEFAULT 80,
    source TEXT NOT NULL,
    notes TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    expires_at TEXT,
    UNIQUE(indicator, indicator_type)
  );

  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
`);

const userColumns = db.prepare("PRAGMA table_info(users)").all();
if (!userColumns.some((column) => column.name === "email")) {
  db.exec("ALTER TABLE users ADD COLUMN email TEXT COLLATE NOCASE");
}
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE email IS NOT NULL");

const scanColumns = db.prepare("PRAGMA table_info(scans)").all();
if (!scanColumns.some((column) => column.name === "user_id")) {
  db.exec("ALTER TABLE scans ADD COLUMN user_id TEXT REFERENCES users(id) ON DELETE SET NULL");
}
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_scans_user_created_at ON scans(user_id, created_at DESC);

  CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_audit_logs_user_created_at ON audit_logs(user_id, created_at DESC);
`);

function passwordHash(password, salt) {
  return scryptSync(password, salt, 64).toString("hex");
}

function createUserRecord(username, password, role = "user", email = null) {
  const salt = randomBytes(16).toString("hex");
  const user = { id: randomUUID(), username, email, role, createdAt: new Date().toISOString() };
  db.prepare("INSERT INTO users (id, username, email, password_hash, password_salt, role, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
    .run(user.id, user.username, user.email, passwordHash(password, salt), salt, user.role, user.createdAt);
  return user;
}

if (!db.prepare("SELECT id FROM users WHERE username = ?").get("qradmin")) {
  createUserRecord("qradmin", "qradmin123", "admin");
}

const seedIoc = db.prepare(`
  INSERT OR IGNORE INTO iocs
    (id, indicator, indicator_type, severity, confidence, source, notes, active, first_seen, last_seen)
  VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
`);

const now = new Date().toISOString();
for (const seed of [
  ["phishing.test", "domain", "critical", 100, "Controlled test data", "Reserved academic test indicator"],
  ["malicious.example", "domain", "critical", 100, "Controlled test data", "Reserved academic test indicator"],
  ["https://malicious.example/collect", "url", "critical", 100, "Controlled test data", "Reserved academic test indicator"],
]) {
  seedIoc.run(randomUUID(), ...seed, now, now);
}

function safeJson(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

function publicUser(row) {
  return row ? { id: row.id, username: row.username, email: row.email, role: row.role, createdAt: row.created_at } : null;
}

export function registerUser(input) {
  const username = String(input.username || "").trim();
  const email = String(input.email || "").trim().toLowerCase();
  const password = String(input.password || "");
  if (!/^[a-zA-Z0-9_.-]{3,32}$/.test(username)) throw new Error("Username must be 3 to 32 letters, numbers, dots, dashes, or underscores.");
  if (!/[a-zA-Z]/.test(username)) throw new Error("Username cannot contain numbers only. Add at least one letter.");
  if (email.length > 254 || !/^[a-z0-9._%+-]+@gmail\.com$/i.test(email)) throw new Error("Enter a valid Gmail address ending in @gmail.com.");
  if (password.length < 8 || password.length > 128) throw new Error("Password must be between 8 and 128 characters.");
  if (db.prepare("SELECT id FROM users WHERE username = ?").get(username)) throw new Error("Username is already registered.");
  if (db.prepare("SELECT id FROM users WHERE email = ?").get(email)) throw new Error("Gmail address is already registered.");
  return createUserRecord(username, password, "user", email);
}

export function authenticateUser(usernameInput, passwordInput) {
  const username = String(usernameInput || "").trim();
  const password = String(passwordInput || "");
  const row = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!row) return null;
  const supplied = Buffer.from(passwordHash(password, row.password_salt), "hex");
  const stored = Buffer.from(row.password_hash, "hex");
  return supplied.length === stored.length && timingSafeEqual(supplied, stored) ? publicUser(row) : null;
}

export function createSession(userId) {
  db.prepare("DELETE FROM sessions WHERE expires_at <= ?").run(new Date().toISOString());
  const token = randomBytes(32).toString("hex");
  const tokenHash = createHash("sha256").update(token).digest("hex");
  const createdAt = new Date();
  const expiresAt = new Date(createdAt.getTime() + 12 * 60 * 60 * 1000);
  db.prepare("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
    .run(tokenHash, userId, createdAt.toISOString(), expiresAt.toISOString());
  return { token, expiresAt };
}

export function getSessionUser(token) {
  if (!token) return null;
  const tokenHash = createHash("sha256").update(token).digest("hex");
  const row = db.prepare(`
    SELECT users.* FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > ?
  `).get(tokenHash, new Date().toISOString());
  return publicUser(row);
}

export function deleteSession(token) {
  if (!token) return;
  const tokenHash = createHash("sha256").update(token).digest("hex");
  db.prepare("DELETE FROM sessions WHERE token_hash = ?").run(tokenHash);
}

function hydrateScan(row) {
  const recommendation = row.classification === "Safe"
    ? "No high-risk indicators were detected. Verify the merchant and amount before continuing."
    : row.classification === "Suspicious"
      ? "Pause and verify the merchant or destination through an independent channel."
      : "Do not open the destination or proceed with payment. Report the QR code to the merchant or provider.";
  return {
    ...row,
    indicators: safeJson(row.indicators_json, []),
    observables: safeJson(row.observables_json, {}),
    paymentContext: safeJson(row.payment_context_json, null),
    redirectChain: safeJson(row.redirect_chain_json, []),
    riskScore: row.risk_score,
    payloadPreview: row.payload_preview,
    payloadType: row.payload_type,
    normalizedUrl: row.normalized_url,
    latencyMs: row.latency_ms,
    createdAt: row.created_at,
    expectedLabel: row.expected_label,
    userId: row.user_id,
    recommendation,
  };
}

export function findIocMatches({ urls = [], domains = [], ips = [] }) {
  const candidates = [
    ...urls.map((value) => ["url", value]),
    ...domains.map((value) => ["domain", value]),
    ...ips.map((value) => ["ip", value]),
  ];
  const find = db.prepare(`
    SELECT * FROM iocs
    WHERE active = 1 AND indicator_type = ? AND lower(indicator) = lower(?)
      AND (expires_at IS NULL OR expires_at > ?)
  `);
  return candidates.flatMap(([type, value]) => find.all(type, value, new Date().toISOString()));
}

export function saveScan(result, input) {
  const id = randomUUID();
  const createdAt = new Date().toISOString();
  db.prepare(`
    INSERT INTO scans (
      id, created_at, payload_hash, payload_preview, payload_type,
      normalized_url, domain, risk_score, classification, indicators_json,
      observables_json, payment_context_json, redirect_chain_json, latency_ms,
      source, expected_label, user_id
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    createdAt,
    result.payloadHash,
    result.payloadPreview,
    result.payloadType,
    result.normalizedUrl || null,
    result.domain || null,
    result.riskScore,
    result.classification,
    JSON.stringify(result.indicators),
    JSON.stringify(result.observables),
    JSON.stringify(result.paymentContext),
    JSON.stringify(result.redirectChain),
    result.latencyMs,
    input.source || "manual",
    input.expectedLabel || null,
    input.userId || null,
  );
  return { ...result, id, createdAt, source: input.source || "manual", expectedLabel: input.expectedLabel || null, userId: input.userId || null };
}

export function listScans(limit = 30, userId = null) {
  const safeLimit = Math.min(Math.max(Number(limit) || 30, 1), 200);
  const rows = userId
    ? db.prepare(`SELECT scans.*, users.username FROM scans LEFT JOIN users ON users.id = scans.user_id WHERE scans.user_id = ? ORDER BY scans.created_at DESC LIMIT ?`).all(userId, safeLimit)
    : db.prepare(`SELECT scans.*, users.username FROM scans LEFT JOIN users ON users.id = scans.user_id ORDER BY scans.created_at DESC LIMIT ?`).all(safeLimit);
  return rows.map(hydrateScan);
}

export function listIocs(activeOnly = false) {
  return db.prepare(`SELECT * FROM iocs${activeOnly ? " WHERE active = 1" : ""} ORDER BY last_seen DESC, indicator ASC`).all();
}

export function addIoc(input) {
  const timestamp = new Date().toISOString();
  const id = randomUUID();
  db.prepare(`
    INSERT INTO iocs (id, indicator, indicator_type, severity, confidence, source, notes, active, first_seen, last_seen, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(indicator, indicator_type) DO UPDATE SET
      severity = CASE WHEN iocs.active = 1 AND excluded.active = 0 THEN iocs.severity ELSE excluded.severity END,
      confidence = CASE WHEN iocs.active = 1 AND excluded.active = 0 THEN iocs.confidence ELSE excluded.confidence END,
      source = CASE WHEN iocs.active = 1 AND excluded.active = 0 THEN iocs.source ELSE excluded.source END,
      notes = CASE WHEN iocs.active = 1 AND excluded.active = 0 THEN iocs.notes ELSE excluded.notes END,
      active = CASE WHEN iocs.active = 1 THEN 1 ELSE excluded.active END,
      last_seen = excluded.last_seen,
      expires_at = CASE WHEN iocs.active = 1 AND excluded.active = 0 THEN iocs.expires_at ELSE excluded.expires_at END
  `).run(
    id,
    input.indicator.trim(),
    input.indicatorType,
    input.severity || "high",
    Number(input.confidence ?? 80),
    input.source || "Manual entry",
    input.notes || null,
    input.active ? 1 : 0,
    timestamp,
    timestamp,
    input.expiresAt || null,
  );
  return db.prepare("SELECT * FROM iocs WHERE indicator_type = ? AND lower(indicator) = lower(?)").get(input.indicatorType, input.indicator.trim());
}

export function deleteIoc(id) {
  const ioc = db.prepare("SELECT * FROM iocs WHERE id = ?").get(id);
  if (!ioc) return null;
  db.prepare("DELETE FROM iocs WHERE id = ?").run(id);
  return ioc;
}

export function reviewIoc(id, action) {
  const ioc = db.prepare("SELECT * FROM iocs WHERE id = ?").get(id);
  if (!ioc) return null;
  if (action === "approve") {
    db.prepare("UPDATE iocs SET active = 1, last_seen = ? WHERE id = ?").run(new Date().toISOString(), id);
    return db.prepare("SELECT * FROM iocs WHERE id = ?").get(id);
  }
  db.prepare("DELETE FROM iocs WHERE id = ?").run(id);
  return ioc;
}

export function getStats(userId = null) {
  const where = userId ? " WHERE user_id = ?" : "";
  const parameters = userId ? [userId] : [];
  const summary = db.prepare(`
    SELECT COUNT(*) total,
      SUM(CASE WHEN classification = 'Safe' THEN 1 ELSE 0 END) safe,
      SUM(CASE WHEN classification = 'Suspicious' THEN 1 ELSE 0 END) suspicious,
      SUM(CASE WHEN classification = 'Malicious' THEN 1 ELSE 0 END) malicious,
      ROUND(AVG(latency_ms), 2) mean_latency
    FROM scans
    ${where}
  `).get(...parameters);
  const latencies = db.prepare(`SELECT latency_ms FROM scans${where} ORDER BY latency_ms`).all(...parameters).map((row) => row.latency_ms);
  const p95Index = latencies.length ? Math.ceil(latencies.length * 0.95) - 1 : 0;
  const labeledWhere = userId ? " WHERE user_id = ? AND expected_label IS NOT NULL" : " WHERE expected_label IS NOT NULL";
  const labeled = db.prepare(`SELECT classification, expected_label FROM scans${labeledWhere}`).all(...parameters);
  let tp = 0, tn = 0, fp = 0, fn = 0;
  for (const row of labeled) {
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
  const stats = {
    total: summary.total || 0,
    safe: summary.safe || 0,
    suspicious: summary.suspicious || 0,
    malicious: summary.malicious || 0,
    meanLatencyMs: summary.mean_latency || 0,
    p95LatencyMs: latencies.length ? latencies[p95Index] : 0,
    evaluation: {
      sampleSize: labeled.length,
      tp, tn, fp, fn,
      accuracy: ratio(tp + tn, tp + tn + fp + fn),
      precision,
      recall,
      f1: precision !== null && recall !== null && precision + recall ? Number((2 * precision * recall / (precision + recall)).toFixed(4)) : null,
      falsePositiveRate: ratio(fp, fp + tn),
      falseNegativeRate: ratio(fn, fn + tp),
    },
  };
  if (!userId) {
    const userSummary = db.prepare(`
      SELECT COUNT(*) total_users,
        SUM(CASE WHEN EXISTS (SELECT 1 FROM scans WHERE scans.user_id = users.id) THEN 1 ELSE 0 END) active_users
      FROM users WHERE role = 'user'
    `).get();
    const today = new Date();
    today.setUTCHours(0, 0, 0, 0);
    const sevenDaysAgo = new Date(today);
    sevenDaysAgo.setUTCDate(sevenDaysAgo.getUTCDate() - 6);
    const dailyRows = db.prepare(`SELECT substr(created_at, 1, 10) day, COUNT(*) total FROM scans WHERE created_at >= ? GROUP BY day ORDER BY day`).all(sevenDaysAgo.toISOString());
    const dailyMap = new Map(dailyRows.map((row) => [row.day, row.total]));
    const dailyScans = Array.from({ length: 7 }, (_, index) => {
      const date = new Date(sevenDaysAgo);
      date.setUTCDate(date.getUTCDate() + index);
      const day = date.toISOString().slice(0, 10);
      return { day, total: dailyMap.get(day) || 0 };
    });
    const topUsers = db.prepare(`
      SELECT users.id, users.username, COUNT(scans.id) total
      FROM users LEFT JOIN scans ON scans.user_id = users.id
      WHERE users.role = 'user'
      GROUP BY users.id, users.username
      ORDER BY total DESC, users.username ASC LIMIT 5
    `).all();
    stats.admin = {
      totalUsers: userSummary.total_users || 0,
      activeUsers: userSummary.active_users || 0,
      scansToday: db.prepare("SELECT COUNT(*) total FROM scans WHERE created_at >= ?").get(today.toISOString()).total,
      scansLast7Days: dailyScans.reduce((sum, item) => sum + item.total, 0),
      averageScansPerUser: userSummary.total_users ? Number((stats.total / userSummary.total_users).toFixed(1)) : 0,
      dailyScans,
      topUsers,
    };
  }
  return stats;
}

export function logActivity(userId, action, detail = {}) {
  const activity = { id: randomUUID(), userId: userId || null, action, detail, createdAt: new Date().toISOString() };
  db.prepare("INSERT INTO audit_logs (id, user_id, action, detail_json, created_at) VALUES (?, ?, ?, ?, ?)")
    .run(activity.id, activity.userId, activity.action, JSON.stringify(activity.detail), activity.createdAt);
  return activity;
}

export function listActivity(limit = 100, userId = null) {
  const safeLimit = Math.min(Math.max(Number(limit) || 100, 1), 300);
  const rows = userId
    ? db.prepare(`SELECT audit_logs.*, users.username, users.role FROM audit_logs LEFT JOIN users ON users.id = audit_logs.user_id WHERE audit_logs.user_id = ? ORDER BY audit_logs.created_at DESC LIMIT ?`).all(userId, safeLimit)
    : db.prepare(`SELECT audit_logs.*, users.username, users.role FROM audit_logs LEFT JOIN users ON users.id = audit_logs.user_id ORDER BY audit_logs.created_at DESC LIMIT ?`).all(safeLimit);
  return rows.map((row) => ({
    id: row.id,
    userId: row.user_id,
    username: row.username || "System",
    role: row.role || "system",
    action: row.action,
    detail: safeJson(row.detail_json, {}),
    createdAt: row.created_at,
  }));
}

export function listUsers() {
  return db.prepare(`
    SELECT users.id, users.username, users.email, users.role, users.created_at,
      COUNT(scans.id) scan_count,
      SUM(CASE WHEN scans.classification = 'Safe' THEN 1 ELSE 0 END) safe_count,
      SUM(CASE WHEN scans.classification IN ('Suspicious', 'Malicious') THEN 1 ELSE 0 END) risky_count,
      MAX(scans.created_at) last_scan_at,
      (SELECT MAX(audit_logs.created_at) FROM audit_logs WHERE audit_logs.user_id = users.id) last_activity_at
    FROM users LEFT JOIN scans ON scans.user_id = users.id
    GROUP BY users.id, users.username, users.email, users.role, users.created_at
    ORDER BY users.created_at DESC
  `).all().map((row) => ({
    id: row.id,
    username: row.username,
    email: row.email,
    role: row.role,
    createdAt: row.created_at,
    scanCount: row.scan_count || 0,
    safeCount: row.safe_count || 0,
    riskyCount: row.risky_count || 0,
    lastScanAt: row.last_scan_at,
    lastActivityAt: row.last_activity_at,
  }));
}

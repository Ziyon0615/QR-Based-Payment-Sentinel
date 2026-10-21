import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { randomUUID } from "node:crypto";

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
`);

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
      source, expected_label
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
  );
  return { ...result, id, createdAt, source: input.source || "manual", expectedLabel: input.expectedLabel || null };
}

export function listScans(limit = 30) {
  const safeLimit = Math.min(Math.max(Number(limit) || 30, 1), 200);
  return db.prepare("SELECT * FROM scans ORDER BY created_at DESC LIMIT ?").all(safeLimit).map(hydrateScan);
}

export function listIocs() {
  return db.prepare("SELECT * FROM iocs ORDER BY last_seen DESC, indicator ASC").all();
}

export function addIoc(input) {
  const timestamp = new Date().toISOString();
  const id = randomUUID();
  db.prepare(`
    INSERT INTO iocs (id, indicator, indicator_type, severity, confidence, source, notes, active, first_seen, last_seen, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
    ON CONFLICT(indicator, indicator_type) DO UPDATE SET
      severity = excluded.severity,
      confidence = excluded.confidence,
      source = excluded.source,
      notes = excluded.notes,
      active = 1,
      last_seen = excluded.last_seen,
      expires_at = excluded.expires_at
  `).run(
    id,
    input.indicator.trim(),
    input.indicatorType,
    input.severity || "high",
    Number(input.confidence ?? 80),
    input.source || "Manual entry",
    input.notes || null,
    timestamp,
    timestamp,
    input.expiresAt || null,
  );
  return db.prepare("SELECT * FROM iocs WHERE indicator_type = ? AND lower(indicator) = lower(?)").get(input.indicatorType, input.indicator.trim());
}

export function getStats() {
  const summary = db.prepare(`
    SELECT COUNT(*) total,
      SUM(CASE WHEN classification = 'Safe' THEN 1 ELSE 0 END) safe,
      SUM(CASE WHEN classification = 'Suspicious' THEN 1 ELSE 0 END) suspicious,
      SUM(CASE WHEN classification = 'Malicious' THEN 1 ELSE 0 END) malicious,
      ROUND(AVG(latency_ms), 2) mean_latency
    FROM scans
  `).get();
  const latencies = db.prepare("SELECT latency_ms FROM scans ORDER BY latency_ms").all().map((row) => row.latency_ms);
  const p95Index = latencies.length ? Math.ceil(latencies.length * 0.95) - 1 : 0;
  const labeled = db.prepare("SELECT classification, expected_label FROM scans WHERE expected_label IS NOT NULL").all();
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
  return {
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
}

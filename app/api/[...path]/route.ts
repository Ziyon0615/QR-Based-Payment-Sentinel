import { analyzePayload } from "../../../backend/engine.mjs";
import {
  addIoc,
  authenticateUser,
  createSession,
  deleteIoc,
  deleteSession,
  findIocMatches,
  getSessionUser,
  getStats,
  listActivity,
  listIocs,
  listScans,
  listUsers,
  logActivity,
  registerUser,
  saveScan,
} from "../../../backend/postgres-database.mjs";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 30;

const loginAttempts = new Map<string, { count: number; resetAt: number }>();

function json(status: number, body: unknown, extraHeaders: HeadersInit = {}) {
  return Response.json(body, { status, headers: { "cache-control": "no-store", ...extraHeaders } });
}

async function readJson(request: Request) {
  const contentLength = Number(request.headers.get("content-length") || 0);
  if (contentLength > 131072) throw new Error("Request body exceeds the 128 KB limit.");
  const text = await request.text();
  if (Buffer.byteLength(text, "utf8") > 131072) throw new Error("Request body exceeds the 128 KB limit.");
  return JSON.parse(text || "{}");
}

function cookieValue(request: Request, name: string) {
  for (const cookie of String(request.headers.get("cookie") || "").split(";")) {
    const [key, ...parts] = cookie.trim().split("=");
    if (key === name) return decodeURIComponent(parts.join("="));
  }
  return "";
}

function sessionCookie(token: string, maxAge = 12 * 60 * 60) {
  const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
  return `qr_sentinel_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Max-Age=${maxAge}; SameSite=Lax${secure}`;
}

async function currentUser(request: Request) {
  return getSessionUser(cookieValue(request, "qr_sentinel_session"));
}

function clientAddress(request: Request) {
  return request.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    || request.headers.get("x-real-ip")
    || "unknown";
}

function allowLoginAttempt(request: Request) {
  const address = clientAddress(request);
  const now = Date.now();
  const state = loginAttempts.get(address);
  if (!state || state.resetAt <= now) {
    loginAttempts.set(address, { count: 1, resetAt: now + 5 * 60_000 });
    return true;
  }
  if (state.count >= 10) return false;
  state.count += 1;
  return true;
}

async function handle(request: Request) {
  const url = new URL(request.url);
  try {
    if (request.method === "GET" && url.pathname === "/api/health") {
      return json(200, { status: "ok", database: process.env.DATABASE_URL ? "postgres" : "sqlite", service: "QRBased Sentinel API" });
    }
    if (request.method === "GET" && url.pathname === "/api/auth/me") {
      const user = await currentUser(request);
      return json(user ? 200 : 401, user ? { user } : { error: "Authentication required." });
    }
    if (request.method === "POST" && url.pathname === "/api/auth/login") {
      if (!allowLoginAttempt(request)) return json(429, { error: "Too many login attempts. Try again in a few minutes." });
      const input = await readJson(request);
      const user = await authenticateUser(input.username, input.password);
      if (!user) return json(401, { error: "Invalid username or password." });
      loginAttempts.delete(clientAddress(request));
      const session = await createSession(user.id);
      await logActivity(user.id, "signed_in");
      return json(200, { user }, { "set-cookie": sessionCookie(session.token) });
    }
    if (request.method === "POST" && url.pathname === "/api/auth/register") {
      if (!allowLoginAttempt(request)) return json(429, { error: "Too many registration attempts. Try again in a few minutes." });
      const input = await readJson(request);
      const user = await registerUser(input);
      const session = await createSession(user.id);
      await logActivity(user.id, "account_created");
      return json(201, { user }, { "set-cookie": sessionCookie(session.token) });
    }
    if (request.method === "POST" && url.pathname === "/api/auth/logout") {
      const token = cookieValue(request, "qr_sentinel_session");
      const user = await getSessionUser(token);
      if (user) await logActivity(user.id, "signed_out");
      await deleteSession(token);
      return json(200, { ok: true }, { "set-cookie": sessionCookie("", 0) });
    }

    const user = await currentUser(request);
    if (!user) return json(401, { error: "Authentication required." });
    const userScope = user.role === "admin" ? null : user.id;
    if (request.method === "GET" && url.pathname === "/api/scans") {
      const limit = url.searchParams.get("limit");
      return json(200, { scans: await listScans(limit ? Number(limit) : undefined, userScope) });
    }
    if (request.method === "GET" && url.pathname === "/api/stats") return json(200, await getStats(userScope));
    if (request.method === "GET" && url.pathname === "/api/users") {
      if (user.role !== "admin") return json(403, { error: "Administrator access required." });
      return json(200, { users: await listUsers() });
    }
    if (request.method === "GET" && url.pathname === "/api/activity") {
      const requestedUserId = user.role === "admin" ? url.searchParams.get("userId") : user.id;
      const limit = url.searchParams.get("limit");
      return json(200, { activity: await listActivity(limit ? Number(limit) : undefined, requestedUserId || null) });
    }
    if (request.method === "GET" && url.pathname === "/api/iocs") return json(200, { iocs: await listIocs() });
    if (request.method === "POST" && url.pathname === "/api/iocs") {
      const input = await readJson(request);
      if (!input.indicator || !["url", "domain", "ip"].includes(input.indicatorType)) return json(400, { error: "indicator and a valid indicatorType are required" });
      const ioc = await addIoc(input);
      await logActivity(user.id, "indicator_added", { indicatorType: input.indicatorType, indicator: input.indicator });
      return json(201, { ioc });
    }
    if (request.method === "DELETE" && url.pathname.startsWith("/api/iocs/")) {
      if (user.role !== "admin") return json(403, { error: "Administrator access required." });
      const id = decodeURIComponent(url.pathname.slice("/api/iocs/".length));
      if (!id || id.includes("/")) return json(404, { error: "Threat indicator not found." });
      const ioc = await deleteIoc(id);
      if (!ioc) return json(404, { error: "Threat indicator not found." });
      await logActivity(user.id, "indicator_deleted", { indicatorType: ioc.indicator_type, indicator: ioc.indicator });
      return json(200, { deleted: true, ioc });
    }
    if (request.method === "POST" && url.pathname === "/api/analyze") {
      const input = await readJson(request);
      if (!input.payload) return json(400, { error: "payload is required" });
      if (input.expectedLabel && !["Safe", "Suspicious", "Malicious"].includes(input.expectedLabel)) return json(400, { error: "expectedLabel must be Safe, Suspicious, or Malicious" });
      const analysis = await analyzePayload(input.payload, {
        resolveRedirects: input.resolveRedirects !== false,
        lookupIocs: findIocMatches,
      });
      const scan = await saveScan(analysis, { ...input, userId: user.id });
      await logActivity(user.id, "qr_scanned", { scanId: scan.id, classification: scan.classification, riskScore: scan.riskScore, source: scan.source });
      return json(201, scan);
    }
    return json(404, { error: "Not found" });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unexpected server error";
    const status = /already registered|duplicate key/i.test(message)
      ? 409
      : /required|limit|JSON|Payload|Username|Password|Gmail|email/i.test(message)
        ? 400
        : 500;
    return json(status, { error: message });
  }
}

export const GET = handle;
export const POST = handle;
export const DELETE = handle;

export function OPTIONS() {
  return new Response(null, { status: 204, headers: { allow: "GET, POST, DELETE, OPTIONS" } });
}

import { createServer } from "node:http";
import { analyzePayload } from "./engine.mjs";
import { addIoc, authenticateUser, createSession, deleteIoc, deleteSession, findIocMatches, getSessionUser, getStats, listActivity, listIocs, listScans, listUsers, logActivity, registerUser, reviewIoc, saveScan } from "./repository.mjs";

const port = Number(process.env.PORT || 8000);
const allowedOrigins = new Set((process.env.ALLOWED_ORIGINS || "http://localhost:3000,http://127.0.0.1:3000").split(",").map((value) => value.trim()));
const loginAttempts = new Map();

function corsHeaders(request) {
  const origin = request.headers.origin;
  const headers = {
    "access-control-allow-methods": "GET,POST,PATCH,DELETE,OPTIONS",
    "access-control-allow-headers": "content-type",
    "access-control-allow-credentials": "true",
    vary: "Origin",
  };
  if (origin && allowedOrigins.has(origin)) headers["access-control-allow-origin"] = origin;
  return headers;
}

function send(request, response, status, body, extraHeaders = {}) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", ...corsHeaders(request), ...extraHeaders });
  response.end(JSON.stringify(body));
}

async function readJson(request) {
  const chunks = [];
  let total = 0;
  for await (const chunk of request) {
    total += chunk.length;
    if (total > 131072) throw new Error("Request body exceeds the 128 KB limit.");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}");
}

function cookieValue(request, name) {
  const cookies = String(request.headers.cookie || "").split(";");
  for (const cookie of cookies) {
    const [key, ...parts] = cookie.trim().split("=");
    if (key === name) return decodeURIComponent(parts.join("="));
  }
  return "";
}

function sessionCookie(token, maxAge = 12 * 60 * 60) {
  const production = process.env.NODE_ENV === "production";
  return `qr_sentinel_session=${encodeURIComponent(token)}; Path=/; HttpOnly; Max-Age=${maxAge}; ${production ? "SameSite=None; Secure" : "SameSite=Lax"}`;
}

async function currentUser(request) {
  return getSessionUser(cookieValue(request, "qr_sentinel_session"));
}

async function requireUser(request, response) {
  const user = await currentUser(request);
  if (!user) {
    send(request, response, 401, { error: "Authentication required." });
    return null;
  }
  return user;
}

function allowLoginAttempt(request) {
  const address = request.socket.remoteAddress || "unknown";
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

function clearLoginAttempts(request) {
  loginAttempts.delete(request.socket.remoteAddress || "unknown");
}

const server = createServer(async (request, response) => {
  if (request.method === "OPTIONS") {
    response.writeHead(204, corsHeaders(request));
    response.end();
    return;
  }
  const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);
  try {
    if (request.method === "GET" && url.pathname === "/api/health") return send(request, response, 200, { status: "ok", database: process.env.DATABASE_URL ? "postgres" : "sqlite", service: "QRBased Sentinel API" });
    if (request.method === "GET" && url.pathname === "/api/auth/me") {
      const user = await currentUser(request);
      return send(request, response, user ? 200 : 401, user ? { user } : { error: "Authentication required." });
    }
    if (request.method === "POST" && url.pathname === "/api/auth/login") {
      if (!allowLoginAttempt(request)) return send(request, response, 429, { error: "Too many login attempts. Try again in a few minutes." });
      const input = await readJson(request);
      const user = await authenticateUser(input.username, input.password);
      if (!user) return send(request, response, 401, { error: "Invalid username or password." });
      clearLoginAttempts(request);
      const session = await createSession(user.id);
      await logActivity(user.id, "signed_in");
      return send(request, response, 200, { user }, { "set-cookie": sessionCookie(session.token) });
    }
    if (request.method === "POST" && url.pathname === "/api/auth/register") {
      if (!allowLoginAttempt(request)) return send(request, response, 429, { error: "Too many registration attempts. Try again in a few minutes." });
      const input = await readJson(request);
      const user = await registerUser(input);
      const session = await createSession(user.id);
      await logActivity(user.id, "account_created");
      return send(request, response, 201, { user }, { "set-cookie": sessionCookie(session.token) });
    }
    if (request.method === "POST" && url.pathname === "/api/auth/logout") {
      const token = cookieValue(request, "qr_sentinel_session");
      const user = await getSessionUser(token);
      if (user) await logActivity(user.id, "signed_out");
      await deleteSession(token);
      return send(request, response, 200, { ok: true }, { "set-cookie": sessionCookie("", 0) });
    }
    const user = await requireUser(request, response);
    if (!user) return;
    const userScope = user.role === "admin" ? null : user.id;
    if (request.method === "GET" && url.pathname === "/api/scans") return send(request, response, 200, { scans: await listScans(url.searchParams.get("limit"), userScope) });
    if (request.method === "GET" && url.pathname === "/api/stats") return send(request, response, 200, await getStats(userScope));
    if (request.method === "GET" && url.pathname === "/api/users") {
      if (user.role !== "admin") return send(request, response, 403, { error: "Administrator access required." });
      return send(request, response, 200, { users: await listUsers() });
    }
    if (request.method === "GET" && url.pathname === "/api/activity") {
      const requestedUserId = user.role === "admin" ? url.searchParams.get("userId") : user.id;
      return send(request, response, 200, { activity: await listActivity(url.searchParams.get("limit"), requestedUserId || null) });
    }
    if (request.method === "GET" && url.pathname === "/api/iocs") return send(request, response, 200, { iocs: await listIocs(user.role !== "admin") });
    if (request.method === "POST" && url.pathname === "/api/iocs") {
      const input = await readJson(request);
      if (!input.indicator || !["url", "domain", "ip"].includes(input.indicatorType)) return send(request, response, 400, { error: "indicator and a valid indicatorType are required" });
      const ioc = await addIoc({ ...input, active: user.role === "admin", confidence: user.role === "admin" ? (input.confidence ?? 100) : 80, submittedByUserId: user.id });
      const pendingReview = user.role !== "admin" && !ioc.active;
      const alreadyActive = user.role !== "admin" && Boolean(ioc.active);
      await logActivity(user.id, alreadyActive ? "indicator_duplicate" : pendingReview ? "indicator_submitted" : "indicator_added", { indicatorType: input.indicatorType, indicator: input.indicator });
      return send(request, response, 201, { ioc, pendingReview, alreadyActive });
    }
    if (request.method === "PATCH" && url.pathname.startsWith("/api/iocs/")) {
      if (user.role !== "admin") return send(request, response, 403, { error: "Administrator access required." });
      const id = decodeURIComponent(url.pathname.slice("/api/iocs/".length));
      if (!id || id.includes("/")) return send(request, response, 404, { error: "Threat indicator not found." });
      const input = await readJson(request);
      if (!["approve", "reject"].includes(input.action)) return send(request, response, 400, { error: "action must be approve or reject" });
      const ioc = await reviewIoc(id, input.action);
      if (!ioc) return send(request, response, 404, { error: "Threat indicator not found." });
      await logActivity(user.id, input.action === "approve" ? "indicator_approved" : "indicator_rejected", { indicatorType: ioc.indicator_type, indicator: ioc.indicator });
      return send(request, response, 200, { action: input.action, ioc });
    }
    if (request.method === "DELETE" && url.pathname.startsWith("/api/iocs/")) {
      if (user.role !== "admin") return send(request, response, 403, { error: "Administrator access required." });
      const id = decodeURIComponent(url.pathname.slice("/api/iocs/".length));
      if (!id || id.includes("/")) return send(request, response, 404, { error: "Threat indicator not found." });
      const ioc = await deleteIoc(id);
      if (!ioc) return send(request, response, 404, { error: "Threat indicator not found." });
      await logActivity(user.id, "indicator_deleted", { indicatorType: ioc.indicator_type, indicator: ioc.indicator });
      return send(request, response, 200, { deleted: true, ioc });
    }
    if (request.method === "POST" && url.pathname === "/api/analyze") {
      const input = await readJson(request);
      if (!input.payload) return send(request, response, 400, { error: "payload is required" });
      if (input.expectedLabel && !["Safe", "Suspicious", "Malicious"].includes(input.expectedLabel)) return send(request, response, 400, { error: "expectedLabel must be Safe, Suspicious, or Malicious" });
      const analysis = await analyzePayload(input.payload, {
        resolveRedirects: input.resolveRedirects !== false,
        lookupIocs: findIocMatches,
      });
      const scan = await saveScan(analysis, { ...input, userId: user.id });
      await logActivity(user.id, "qr_scanned", { scanId: scan.id, classification: scan.classification, riskScore: scan.riskScore, source: scan.source });
      return send(request, response, 201, scan);
    }
    return send(request, response, 404, { error: "Not found" });
  } catch (error) {
    const message = error?.message || "Unexpected server error";
    const status = /already registered/i.test(message)
      ? 409
      : /required|limit|JSON|Payload|Username|Password|Gmail|email/i.test(message)
        ? 400
        : 500;
    return send(request, response, status, { error: message });
  }
});

server.listen(port, "0.0.0.0", () => {
  console.log(`QRBased Sentinel API ready on http://localhost:${port}`);
});

import { createServer } from "node:http";
import { analyzePayload } from "./engine.mjs";
import { addIoc, authenticateUser, createSession, deleteSession, findIocMatches, getSessionUser, getStats, listIocs, listScans, registerUser, saveScan } from "./database.mjs";

const port = Number(process.env.PORT || 8000);
const allowedOrigins = new Set((process.env.ALLOWED_ORIGINS || "http://localhost:3000,http://127.0.0.1:3000").split(",").map((value) => value.trim()));
const loginAttempts = new Map();

function corsHeaders(request) {
  const origin = request.headers.origin;
  const headers = {
    "access-control-allow-methods": "GET,POST,OPTIONS",
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

function currentUser(request) {
  return getSessionUser(cookieValue(request, "qr_sentinel_session"));
}

function requireUser(request, response) {
  const user = currentUser(request);
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

const server = createServer(async (request, response) => {
  if (request.method === "OPTIONS") {
    response.writeHead(204, corsHeaders(request));
    response.end();
    return;
  }
  const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);
  try {
    if (request.method === "GET" && url.pathname === "/api/health") return send(request, response, 200, { status: "ok", database: "sqlite", service: "QRBased Sentinel API" });
    if (request.method === "GET" && url.pathname === "/api/auth/me") {
      const user = currentUser(request);
      return send(request, response, user ? 200 : 401, user ? { user } : { error: "Authentication required." });
    }
    if (request.method === "POST" && url.pathname === "/api/auth/login") {
      if (!allowLoginAttempt(request)) return send(request, response, 429, { error: "Too many login attempts. Try again in a few minutes." });
      const input = await readJson(request);
      const user = authenticateUser(input.username, input.password);
      if (!user) return send(request, response, 401, { error: "Invalid username or password." });
      const session = createSession(user.id);
      return send(request, response, 200, { user }, { "set-cookie": sessionCookie(session.token) });
    }
    if (request.method === "POST" && url.pathname === "/api/auth/register") {
      if (!allowLoginAttempt(request)) return send(request, response, 429, { error: "Too many registration attempts. Try again in a few minutes." });
      const input = await readJson(request);
      const user = registerUser(input);
      const session = createSession(user.id);
      return send(request, response, 201, { user }, { "set-cookie": sessionCookie(session.token) });
    }
    if (request.method === "POST" && url.pathname === "/api/auth/logout") {
      deleteSession(cookieValue(request, "qr_sentinel_session"));
      return send(request, response, 200, { ok: true }, { "set-cookie": sessionCookie("", 0) });
    }
    if (!requireUser(request, response)) return;
    if (request.method === "GET" && url.pathname === "/api/scans") return send(request, response, 200, { scans: listScans(url.searchParams.get("limit")) });
    if (request.method === "GET" && url.pathname === "/api/stats") return send(request, response, 200, getStats());
    if (request.method === "GET" && url.pathname === "/api/iocs") return send(request, response, 200, { iocs: listIocs() });
    if (request.method === "POST" && url.pathname === "/api/iocs") {
      const input = await readJson(request);
      if (!input.indicator || !["url", "domain", "ip"].includes(input.indicatorType)) return send(request, response, 400, { error: "indicator and a valid indicatorType are required" });
      return send(request, response, 201, { ioc: addIoc(input) });
    }
    if (request.method === "POST" && url.pathname === "/api/analyze") {
      const input = await readJson(request);
      if (!input.payload) return send(request, response, 400, { error: "payload is required" });
      if (input.expectedLabel && !["Safe", "Suspicious", "Malicious"].includes(input.expectedLabel)) return send(request, response, 400, { error: "expectedLabel must be Safe, Suspicious, or Malicious" });
      const analysis = await analyzePayload(input.payload, {
        resolveRedirects: input.resolveRedirects !== false,
        lookupIocs: findIocMatches,
      });
      return send(request, response, 201, saveScan(analysis, input));
    }
    return send(request, response, 404, { error: "Not found" });
  } catch (error) {
    const message = error?.message || "Unexpected server error";
    const status = /already registered/i.test(message)
      ? 409
      : /required|limit|JSON|Payload|Username|Password/i.test(message)
        ? 400
        : 500;
    return send(request, response, status, { error: message });
  }
});

server.listen(port, "0.0.0.0", () => {
  console.log(`QRBased Sentinel API ready on http://localhost:${port}`);
});

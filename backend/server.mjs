import { createServer } from "node:http";
import { analyzePayload } from "./engine.mjs";
import { addIoc, findIocMatches, getStats, listIocs, listScans, saveScan } from "./database.mjs";

const port = Number(process.env.PORT || 8000);
const allowedOrigins = new Set((process.env.ALLOWED_ORIGINS || "http://localhost:3000,http://127.0.0.1:3000").split(",").map((value) => value.trim()));

function corsHeaders(request) {
  const origin = request.headers.origin;
  return {
    "access-control-allow-origin": origin && allowedOrigins.has(origin) ? origin : [...allowedOrigins][0],
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type",
    vary: "Origin",
  };
}

function send(request, response, status, body) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", ...corsHeaders(request) });
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

const server = createServer(async (request, response) => {
  if (request.method === "OPTIONS") {
    response.writeHead(204, corsHeaders(request));
    response.end();
    return;
  }
  const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);
  try {
    if (request.method === "GET" && url.pathname === "/api/health") return send(request, response, 200, { status: "ok", database: "sqlite", service: "QRBased Sentinel API" });
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
    const status = /required|limit|JSON|Payload/.test(error?.message || "") ? 400 : 500;
    return send(request, response, status, { error: error?.message || "Unexpected server error" });
  }
});

server.listen(port, "0.0.0.0", () => {
  console.log(`QRBased Sentinel API ready on http://localhost:${port}`);
});

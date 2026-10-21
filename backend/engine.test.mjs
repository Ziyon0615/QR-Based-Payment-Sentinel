import test from "node:test";
import assert from "node:assert/strict";
import { analyzePayload } from "./engine.mjs";

test("classifies a reserved IoC match as malicious", async () => {
  const result = await analyzePayload("https://malicious.example/collect", {
    resolveRedirects: false,
    lookupIocs: async () => [{ id: "test", indicator: "malicious.example", indicator_type: "domain", severity: "critical", source: "test" }],
  });
  assert.equal(result.classification, "Malicious");
  assert.ok(result.riskScore >= 70);
  assert.ok(result.indicators.some((item) => item.category === "Threat intelligence"));
});

test("classifies unsupported action schemes as malicious", async () => {
  const result = await analyzePayload("javascript:alert(1)", { resolveRedirects: false });
  assert.equal(result.classification, "Malicious");
  assert.ok(result.indicators.some((item) => item.id === "dangerous_scheme"));
});

test("classifies non-payment text as suspicious", async () => {
  const result = await analyzePayload("hello from a QR code", { resolveRedirects: false });
  assert.equal(result.classification, "Suspicious");
  assert.equal(result.riskScore, 40);
});

test("keeps a straightforward HTTPS payment URL below the suspicious threshold", async () => {
  const result = await analyzePayload("https://pay.example.com/checkout?amount=100", { resolveRedirects: false, lookupIocs: async () => [] });
  assert.equal(result.classification, "Safe");
  assert.ok(result.riskScore < 40);
});

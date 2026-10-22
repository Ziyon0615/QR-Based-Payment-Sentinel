import test from "node:test";
import assert from "node:assert/strict";
import { analyzePayload } from "./engine.mjs";

function crc16(text) {
  let crc = 0xffff;
  for (let index = 0; index < text.length; index += 1) {
    crc ^= text.charCodeAt(index) << 8;
    for (let bit = 0; bit < 8; bit += 1) crc = crc & 0x8000 ? (crc << 1) ^ 0x1021 : crc << 1;
    crc &= 0xffff;
  }
  return crc.toString(16).toUpperCase().padStart(4, "0");
}

function tlv(tag, value) {
  return `${tag}${String(value.length).padStart(2, "0")}${value}`;
}

function gcashStyleQr() {
  const merchantAccount = [
    tlv("00", "com.p2pqrpay"),
    tlv("01", "GXCHPHM2XXX"),
    tlv("02", "00000000"),
  ].join("");
  const body = [
    tlv("00", "01"),
    tlv("01", "11"),
    tlv("27", merchantAccount),
    tlv("52", "6016"),
    tlv("53", "608"),
    tlv("58", "PH"),
    tlv("59", "TEST MERCHANT"),
    tlv("60", "MANILA"),
  ].join("");
  const checksumInput = `${body}6304`;
  return `${checksumInput}${crc16(checksumInput)}`;
}

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

test("recognizes an alphanumeric GCash-style QR Ph payload", async () => {
  const result = await analyzePayload(gcashStyleQr(), { resolveRedirects: false, lookupIocs: async () => [] });

  assert.equal(result.payloadType, "emv_payment");
  assert.equal(result.paymentContext?.validStructure, true);
  assert.equal(result.paymentContext?.validCrc, true);
  assert.equal(result.paymentContext?.countryCode, "PH");
  assert.equal(result.classification, "Safe");
  assert.equal(result.riskScore, 0);
  assert.equal(result.indicators.length, 0);
});

test("flags an alphanumeric QR Ph payload with an invalid checksum", async () => {
  const payload = gcashStyleQr();
  const result = await analyzePayload(`${payload.slice(0, -4)}0000`, { resolveRedirects: false, lookupIocs: async () => [] });

  assert.equal(result.payloadType, "emv_payment");
  assert.equal(result.paymentContext?.validStructure, true);
  assert.equal(result.paymentContext?.validCrc, false);
  assert.equal(result.classification, "Suspicious");
  assert.ok(result.indicators.some((item) => item.id === "emv_crc"));
});

test("flags a malformed payload with an EMV payment header", async () => {
  const result = await analyzePayload("00020101021127XXbroken", { resolveRedirects: false, lookupIocs: async () => [] });

  assert.equal(result.payloadType, "emv_payment");
  assert.equal(result.paymentContext?.validStructure, false);
  assert.equal(result.classification, "Suspicious");
  assert.ok(result.indicators.some((item) => item.id === "emv_structure"));
});

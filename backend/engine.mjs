import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "tiny.one"]);
const HIGH_RISK_TLDS = new Set(["zip", "mov", "click", "top", "xyz", "work", "support", "country", "gq", "tk"]);
const PAYMENT_SCHEMES = new Set(["gcash", "maya", "paymaya", "pay", "qrph"]);
const SUSPICIOUS_TERMS = ["login", "verify", "verification", "secure", "account", "update", "wallet", "bonus", "claim", "otp", "password", "signin"];
const REDIRECT_PARAMS = ["redirect", "redirect_uri", "redirect_url", "return", "return_url", "continue", "next", "target", "url", "dest", "destination"];

function indicator(id, category, severity, score, title, detail, evidence) {
  return { id, category, severity, score, title, detail, evidence };
}

function decodeRepeated(value) {
  let output = value;
  for (let i = 0; i < 2; i += 1) {
    try {
      const decoded = decodeURIComponent(output);
      if (decoded === output) break;
      output = decoded;
    } catch {
      break;
    }
  }
  return output;
}

function parseTlv(payload) {
  const fields = {};
  let offset = 0;
  while (offset + 4 <= payload.length) {
    const tag = payload.slice(offset, offset + 2);
    const lengthText = payload.slice(offset + 2, offset + 4);
    if (!/^\d{2}$/.test(tag) || !/^\d{2}$/.test(lengthText)) return null;
    const length = Number(lengthText);
    const start = offset + 4;
    const end = start + length;
    if (end > payload.length) return null;
    fields[tag] = payload.slice(start, end);
    offset = end;
  }
  return offset === payload.length ? fields : null;
}

function crc16(text) {
  let crc = 0xffff;
  for (let i = 0; i < text.length; i += 1) {
    crc ^= text.charCodeAt(i) << 8;
    for (let bit = 0; bit < 8; bit += 1) crc = crc & 0x8000 ? (crc << 1) ^ 0x1021 : crc << 1;
    crc &= 0xffff;
  }
  return crc.toString(16).toUpperCase().padStart(4, "0");
}

function parsePaymentContext(payload) {
  // EMV merchant-presented QR payloads begin with tag 00, length 02, value 01.
  // Field values are allowed to be alphanumeric (for example QR Ph and GCash
  // identifiers), so requiring the entire payload to contain only digits
  // incorrectly rejects legitimate payment QRs.
  if (!payload.startsWith("000201")) return null;
  const fields = parseTlv(payload);
  if (!fields) return { format: "EMV MPM", validStructure: false, validCrc: false, fields: {} };
  const suppliedCrc = fields["63"];
  const validCrc = Boolean(suppliedCrc && payload.endsWith(`6304${suppliedCrc}`) && crc16(payload.slice(0, -4)) === suppliedCrc.toUpperCase());
  const required = ["00", "52", "53", "58", "59", "60"];
  const missingFields = required.filter((tag) => !fields[tag]);
  return {
    format: "EMV MPM",
    validStructure: true,
    validCrc,
    missingFields,
    pointOfInitiation: fields["01"] === "12" ? "Dynamic" : fields["01"] === "11" ? "Static" : "Unspecified",
    merchantCategoryCode: fields["52"] || null,
    currencyCode: fields["53"] || null,
    amount: fields["54"] || null,
    countryCode: fields["58"] || null,
    merchantName: fields["59"] || null,
    merchantCity: fields["60"] || null,
    merchantAccountTags: Object.keys(fields).filter((tag) => Number(tag) >= 26 && Number(tag) <= 51),
  };
}

function isPrivateIp(ip) {
  if (!ip) return true;
  if (ip === "::1" || ip === "::" || ip.startsWith("fe80:") || ip.startsWith("fc") || ip.startsWith("fd")) return true;
  if (!isIP(ip.includes("%") ? ip.split("%")[0] : ip)) return true;
  if (ip.startsWith("127.") || ip.startsWith("10.") || ip.startsWith("169.254.") || ip.startsWith("192.168.")) return true;
  const parts = ip.split(".").map(Number);
  return parts.length === 4 && parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31;
}

async function assertPublicHost(hostname) {
  const results = await lookup(hostname, { all: true });
  if (!results.length || results.some((entry) => isPrivateIp(entry.address))) throw new Error("Private or local network destination blocked");
  return results.map((entry) => entry.address);
}

export async function resolveRedirectChain(startUrl, fetcher = fetch) {
  const chain = [];
  let current = startUrl;
  for (let hop = 0; hop < 5; hop += 1) {
    const parsed = new URL(current);
    if (!["http:", "https:"].includes(parsed.protocol)) break;
    await assertPublicHost(parsed.hostname);
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 3500);
    let response;
    try {
      response = await fetcher(current, {
        method: "HEAD",
        redirect: "manual",
        signal: controller.signal,
        headers: { "user-agent": "QRBased-Sentinel/0.1 (research prototype)" },
      });
    } finally {
      clearTimeout(timer);
    }
    chain.push({ url: current, status: response.status, domain: parsed.hostname.toLowerCase() });
    if (response.status < 300 || response.status >= 400) break;
    const location = response.headers.get("location");
    if (!location) break;
    current = new URL(location, current).toString();
  }
  return chain;
}

export async function analyzePayload(payloadInput, options = {}) {
  const started = performance.now();
  const payload = String(payloadInput || "").trim();
  if (!payload) throw new Error("A decoded QR payload is required.");
  if (payload.length > 8192) throw new Error("Payload exceeds the 8 KB safety limit.");

  const indicators = [];
  const domains = new Set();
  const urls = new Set();
  const ips = new Set();
  const paymentContext = parsePaymentContext(payload);
  let payloadType = paymentContext ? "emv_payment" : "text";
  let normalizedUrl = null;
  let domain = null;
  let redirectChain = [];
  let parsedUrl = null;

  try {
    parsedUrl = new URL(payload);
    normalizedUrl = parsedUrl.toString();
    domain = parsedUrl.hostname.toLowerCase().replace(/\.$/, "");
    payloadType = ["http:", "https:"].includes(parsedUrl.protocol) ? "url" : PAYMENT_SCHEMES.has(parsedUrl.protocol.replace(":", "")) ? "payment_deep_link" : "deep_link";
    if (normalizedUrl) urls.add(normalizedUrl);
    if (domain) domains.add(domain);
    if (domain && isIP(domain)) ips.add(domain);
  } catch {
    parsedUrl = null;
  }

  if (paymentContext) {
    if (!paymentContext.validStructure) indicators.push(indicator("emv_structure", "Payment context", "high", 40, "Malformed payment structure", "The payload resembles EMV MPM but its TLV fields cannot be parsed safely.", "EMV TLV parse failed"));
    if (paymentContext.validStructure && !paymentContext.validCrc) indicators.push(indicator("emv_crc", "Payment context", "high", 40, "Invalid EMV checksum", "The payload checksum does not match its encoded payment data.", "CRC mismatch"));
    if (paymentContext.missingFields?.length) indicators.push(indicator("emv_required", "Payment context", "medium", 18, "Required payment fields are missing", "The payment payload is missing expected merchant or transaction context.", paymentContext.missingFields.join(", ")));
  } else if (!parsedUrl) {
    indicators.push(indicator("non_payment", "Payment context", "medium", 40, "Unrecognized payment payload", "The content is neither a valid URL, supported payment deep link, nor an EMV merchant-presented payment payload.", payload.slice(0, 80)));
  }

  if (parsedUrl) {
    const protocol = parsedUrl.protocol.toLowerCase();
    if (!["https:", "http:", ...[...PAYMENT_SCHEMES].map((item) => `${item}:`)].includes(protocol)) {
      indicators.push(indicator("dangerous_scheme", "Payload", "critical", 80, "Unsupported URI scheme", "The QR attempts to invoke a non-payment application or action.", protocol));
    }
    if (protocol === "http:") indicators.push(indicator("no_tls", "Transport", "medium", 18, "Unencrypted destination", "The destination uses HTTP, so the connection can be altered in transit.", normalizedUrl));
    if (parsedUrl.username || parsedUrl.password || payload.includes("@")) indicators.push(indicator("userinfo", "URL", "high", 28, "Misleading URL credentials", "The address contains user-information syntax that can conceal the true host.", parsedUrl.host));
    if (domain?.startsWith("xn--") || domain?.includes(".xn--")) indicators.push(indicator("punycode", "Domain", "high", 25, "Internationalized look-alike domain", "Punycode can be used to imitate trusted payment brands.", domain));
    if (domain && isIP(domain)) indicators.push(indicator("ip_host", "Domain", "high", 24, "Raw IP address destination", "Payment services normally use named and verifiable domains.", domain));
    if (domain && SHORTENERS.has(domain)) indicators.push(indicator("shortener", "Redirect", "medium", 22, "Shortened destination", "A URL shortener hides the final payment destination.", domain));
    const tld = domain?.split(".").pop();
    if (tld && HIGH_RISK_TLDS.has(tld)) indicators.push(indicator("risky_tld", "Domain", "medium", 14, "High-risk top-level domain", "This top-level domain is frequently abused in disposable campaigns and requires verification.", `.${tld}`));
    if (domain && domain.split(".").length > 4) indicators.push(indicator("deep_subdomain", "Domain", "low", 8, "Deep subdomain chain", "A long subdomain chain may be used to make a fraudulent host appear legitimate.", domain));
    if (payload.length > 180) indicators.push(indicator("long_url", "URL", "low", 8, "Unusually long address", "Long addresses can conceal encoded destinations and parameters.", `${payload.length} characters`));
    const decoded = decodeRepeated(payload).toLowerCase();
    const matchedTerms = SUSPICIOUS_TERMS.filter((term) => decoded.includes(term));
    if (matchedTerms.length >= 2) indicators.push(indicator("phishing_terms", "URL", "medium", 16, "Credential-oriented language", "The destination includes several terms commonly associated with credential collection.", matchedTerms.slice(0, 5).join(", ")));
    const redirectParams = REDIRECT_PARAMS.filter((name) => parsedUrl.searchParams.has(name));
    if (redirectParams.length) indicators.push(indicator("redirect_param", "Redirect", "medium", 12, "Embedded redirect parameter", "The URL contains a parameter that may forward the user to another destination.", redirectParams.join(", ")));
    if (["http:", "https:"].includes(protocol)) {
      const paymentHints = [domain, parsedUrl.pathname, parsedUrl.search].join(" ").toLowerCase();
      if (!["pay", "qr", "merchant", "wallet", "checkout", "gcash", "maya"].some((hint) => paymentHints.includes(hint))) {
        indicators.push(indicator("payment_mismatch", "Payment context", "low", 10, "Payment context is unclear", "The web destination does not expose an obvious payment-related context.", domain));
      }
      if (options.resolveRedirects !== false) {
        try {
          redirectChain = await resolveRedirectChain(normalizedUrl, options.fetcher);
          for (const hop of redirectChain) {
            domains.add(hop.domain);
            urls.add(hop.url);
          }
          const distinctDomains = [...new Set(redirectChain.map((hop) => hop.domain))];
          if (redirectChain.length > 2) indicators.push(indicator("redirect_chain", "Redirect", "medium", 14, "Multiple redirects detected", "The destination passes through several locations before stopping.", `${redirectChain.length - 1} redirects`));
          if (distinctDomains.length > 1) indicators.push(indicator("cross_domain_redirect", "Redirect", "high", 20, "Cross-domain redirect", "The QR destination changes to a different domain.", distinctDomains.join(" → ")));
          if (redirectChain.some((hop, index) => index > 0 && hop.url.startsWith("http://") && redirectChain[index - 1].url.startsWith("https://"))) indicators.push(indicator("tls_downgrade", "Redirect", "high", 25, "HTTPS downgrade", "The redirect chain moves from an encrypted to an unencrypted destination.", "HTTPS → HTTP"));
        } catch (error) {
          indicators.push(indicator("redirect_unverified", "Redirect", "low", 5, "Destination could not be verified", "Live redirect inspection was unavailable or blocked safely; no site content was opened.", error?.message || "Network check unavailable"));
        }
      }
    }
  }

  const observables = { urls: [...urls], domains: [...domains], ips: [...ips] };
  const matches = options.lookupIocs ? await options.lookupIocs(observables) : [];
  for (const match of matches) {
    const points = match.severity === "critical" ? 75 : match.severity === "high" ? 55 : 35;
    indicators.push(indicator(`ioc_${match.id}`, "Threat intelligence", match.severity, points, "Threat-intelligence match", "An extracted observable matches an active local Indicator of Compromise.", `${match.indicator_type}: ${match.indicator} · ${match.source}`));
  }

  const riskScore = Math.min(100, indicators.reduce((sum, item) => sum + item.score, 0));
  const classification = riskScore >= 70 ? "Malicious" : riskScore >= 40 ? "Suspicious" : "Safe";
  const latencyMs = Number((performance.now() - started).toFixed(2));
  return {
    payloadHash: createHash("sha256").update(payload).digest("hex"),
    payloadPreview: payload.slice(0, 220),
    payloadType,
    normalizedUrl,
    domain,
    paymentContext,
    observables,
    redirectChain,
    indicators: indicators.sort((a, b) => b.score - a.score),
    riskScore,
    classification,
    latencyMs,
    recommendation: classification === "Safe" ? "No high-risk indicators were detected. Verify the merchant and amount before continuing." : classification === "Suspicious" ? "Pause and verify the merchant or destination through an independent channel." : "Do not open the destination or proceed with payment. Report the QR code to the merchant or provider.",
  };
}

export { parsePaymentContext };

"use client";

import { ChangeEvent, FormEvent, useCallback, useEffect, useRef, useState } from "react";
import jsQR from "jsqr";

const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

type Classification = "Safe" | "Suspicious" | "Malicious";
type Indicator = { id: string; category: string; severity: string; score: number; title: string; detail: string; evidence: string };
type Scan = {
  id: string; createdAt: string; payloadPreview: string; payloadType: string;
  normalizedUrl?: string | null; domain?: string | null; riskScore: number;
  classification: Classification; recommendation: string; latencyMs: number;
  source: string; expectedLabel?: string | null; indicators: Indicator[];
  observables: { urls: string[]; domains: string[]; ips: string[] };
  redirectChain: { url: string; status: number; domain: string }[];
  paymentContext?: { format: string; validStructure: boolean; validCrc: boolean; missingFields?: string[]; merchantName?: string | null; merchantCity?: string | null; amount?: string | null; currencyCode?: string | null; countryCode?: string | null; pointOfInitiation?: string } | null;
};
type Stats = {
  total: number; safe: number; suspicious: number; malicious: number; meanLatencyMs: number; p95LatencyMs: number;
  evaluation: { sampleSize: number; tp: number; tn: number; fp: number; fn: number; accuracy: number | null; precision: number | null; recall: number | null; f1: number | null; falsePositiveRate: number | null; falseNegativeRate: number | null };
};
type Ioc = { id: string; indicator: string; indicator_type: string; severity: string; confidence: number; source: string; active: number };

const emptyStats: Stats = {
  total: 0, safe: 0, suspicious: 0, malicious: 0, meanLatencyMs: 0, p95LatencyMs: 0,
  evaluation: { sampleSize: 0, tp: 0, tn: 0, fp: 0, fn: 0, accuracy: null, precision: null, recall: null, f1: null, falsePositiveRate: null, falseNegativeRate: null },
};
const navItems = [["scan", "Scanner"], ["history", "Scan history"], ["research", "Research metrics"], ["intel", "Threat intelligence"]] as const;
const shortText = (value: string | null | undefined, length = 48) => {
  if (!value) return "Payload unavailable";
  return value.length > length ? `${value.slice(0, length)}…` : value;
};
const percent = (value: number | null) => value === null ? "—" : `${(value * 100).toFixed(1)}%`;

export default function Home() {
  const [view, setView] = useState<(typeof navItems)[number][0]>("scan");
  const [online, setOnline] = useState(false);
  const [payload, setPayload] = useState("");
  const [result, setResult] = useState<Scan | null>(null);
  const [history, setHistory] = useState<Scan[]>([]);
  const [stats, setStats] = useState<Stats>(emptyStats);
  const [iocs, setIocs] = useState<Ioc[]>([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [cameraOn, setCameraOn] = useState(false);
  const [resolveRedirects, setResolveRedirects] = useState(true);
  const [expectedLabel, setExpectedLabel] = useState("");
  const [iocDraft, setIocDraft] = useState({ indicator: "", indicatorType: "domain", severity: "high", source: "Manual research entry" });
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const frameRef = useRef<number | null>(null);
  const scanLockRef = useRef(false);

  const refresh = useCallback(async () => {
    try {
      const [healthResponse, scansResponse, statsResponse, iocsResponse] = await Promise.all([
        fetch(`${API_URL}/api/health`), fetch(`${API_URL}/api/scans?limit=50`), fetch(`${API_URL}/api/stats`), fetch(`${API_URL}/api/iocs`),
      ]);
      setOnline(healthResponse.ok);
      if (scansResponse.ok) setHistory((await scansResponse.json()).scans);
      if (statsResponse.ok) setStats(await statsResponse.json());
      if (iocsResponse.ok) setIocs((await iocsResponse.json()).iocs);
    } catch { setOnline(false); }
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(() => { void refresh(); }, 0);
    return () => window.clearTimeout(timer);
  }, [refresh]);

  const stopCamera = useCallback(() => {
    if (frameRef.current) cancelAnimationFrame(frameRef.current);
    streamRef.current?.getTracks().forEach((track) => track.stop());
    streamRef.current = null; scanLockRef.current = false; setCameraOn(false);
  }, []);
  useEffect(() => () => stopCamera(), [stopCamera]);

  async function submitPayload(value: string, source: string) {
    if (!value.trim()) { setMessage("Paste or scan a QR payload first."); return; }
    setBusy(true); setMessage("");
    try {
      const response = await fetch(`${API_URL}/api/analyze`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ payload: value.trim(), source, resolveRedirects, expectedLabel: expectedLabel || null }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || "The analysis could not be completed.");
      setResult(body); setPayload(value.trim()); setOnline(true); await refresh();
    } catch (error) { setMessage(error instanceof Error ? error.message : "The local analysis service is unavailable."); }
    finally { setBusy(false); }
  }

  async function detectCanvas(canvas: HTMLCanvasElement) {
    const Detector = (window as unknown as { BarcodeDetector?: new (input: { formats: string[] }) => { detect(source: CanvasImageSource): Promise<{ rawValue: string }[]> } }).BarcodeDetector;
    if (Detector) {
      try {
        const found = await new Detector({ formats: ["qr_code"] }).detect(canvas);
        if (found[0]?.rawValue) return found[0].rawValue;
      } catch { /* Continue with the local pixel decoder. */ }
    }
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) return "";
    const pixels = context.getImageData(0, 0, canvas.width, canvas.height);
    return jsQR(pixels.data, pixels.width, pixels.height, { inversionAttempts: "attemptBoth" })?.data || "";
  }

  async function scanFrame() {
    const video = videoRef.current, canvas = canvasRef.current;
    if (!video || !canvas || !streamRef.current || scanLockRef.current) return;
    if (video.readyState >= 2 && video.videoWidth) {
      canvas.width = video.videoWidth; canvas.height = video.videoHeight;
      canvas.getContext("2d", { willReadFrequently: true })?.drawImage(video, 0, 0);
      try {
        const value = await detectCanvas(canvas);
        if (value) { scanLockRef.current = true; stopCamera(); await submitPayload(value, "camera"); return; }
      } catch (error) { setMessage(error instanceof Error ? error.message : "Camera scan failed."); stopCamera(); return; }
    }
    frameRef.current = requestAnimationFrame(scanFrame);
  }

  async function startCamera() {
    setMessage("");
    if (!navigator.mediaDevices?.getUserMedia) { setMessage("Camera access is not supported by this browser."); return; }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: { ideal: "environment" } }, audio: false });
      streamRef.current = stream; setCameraOn(true);
      if (videoRef.current) { videoRef.current.srcObject = stream; await videoRef.current.play(); frameRef.current = requestAnimationFrame(scanFrame); }
    } catch { setMessage("Camera permission was not granted. You can upload an image or paste its payload instead."); stopCamera(); }
  }

  async function handleImage(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]; if (!file) return; setMessage("");
    try {
      const bitmap = await createImageBitmap(file), canvas = canvasRef.current; if (!canvas) return;
      canvas.width = bitmap.width; canvas.height = bitmap.height;
      canvas.getContext("2d", { willReadFrequently: true })?.drawImage(bitmap, 0, 0); bitmap.close();
      const value = await detectCanvas(canvas); if (!value) throw new Error("No readable QR code was found in that image.");
      await submitPayload(value, "upload");
    } catch (error) { setMessage(error instanceof Error ? error.message : "The QR image could not be read."); }
    finally { event.target.value = ""; }
  }

  async function addIndicator(event: FormEvent) {
    event.preventDefault(); if (!iocDraft.indicator.trim()) return;
    const response = await fetch(`${API_URL}/api/iocs`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(iocDraft) });
    const body = await response.json(); if (!response.ok) { setMessage(body.error || "IoC could not be saved."); return; }
    setIocDraft({ ...iocDraft, indicator: "" }); await refresh();
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <button className="brand" onClick={() => setView("scan")} aria-label="Open scanner"><span className="brand-mark"><span>Q</span></span><span><strong>QRBased</strong><small>Sentinel</small></span></button>
        <nav className="desktop-nav" aria-label="Main navigation">{navItems.map(([key, label]) => <button key={key} className={view === key ? "active" : ""} onClick={() => setView(key)}>{label}</button>)}</nav>
        <div className={`service-state ${online ? "online" : "offline"}`}><span />{online ? "Protection active" : "API offline"}</div>
      </header>

      {view === "scan" && <div className="page scanner-page">
        <section className="intro-row"><div><p className="eyebrow">SCAN-TIME PAYMENT DEFENSE</p><h1>Know what’s behind<br />the code <em>before</em> you pay.</h1><p className="lead">Decode, inspect, and risk-score QR payment payloads without opening their destination.</p></div><div className="privacy-note"><span className="lock-dot">◆</span><div><strong>Privacy-first analysis</strong><small>No credentials. No payments. Suspicious links stay closed.</small></div></div></section>
        <section className="scanner-grid">
          <div className="scan-card">
            <div className="card-heading"><div><span className="step">01</span><h2>Capture a QR code</h2></div><span className="local-chip">Local prototype</span></div>
            <div className={`camera-stage ${cameraOn ? "live" : ""}`}><video ref={videoRef} muted playsInline />{!cameraOn && <div className="camera-empty"><div className="scan-symbol"><i /><i /><i /><i /><span /></div><strong>Ready to inspect</strong><p>Position a payment QR inside the frame or upload a clear image.</p></div>}<div className="scan-corners"><i /><i /><i /><i /></div>{cameraOn && <div className="scan-line" />}</div>
            <canvas ref={canvasRef} className="hidden-canvas" />
            <div className="capture-actions"><button className="primary-action" onClick={cameraOn ? stopCamera : startCamera}>{cameraOn ? "Stop camera" : "Open camera"}</button><label className="secondary-action">Upload image<input type="file" accept="image/*" onChange={handleImage} /></label></div>
            <div className="divider"><span>or inspect decoded content</span></div>
            <textarea value={payload} onChange={(event) => setPayload(event.target.value)} placeholder="Paste a URL, deep link, or EMV payment payload…" aria-label="Decoded QR payload" />
            <div className="analysis-options"><label><input type="checkbox" checked={resolveRedirects} onChange={(event) => setResolveRedirects(event.target.checked)} /> Check redirect chain</label><label>Expected label<select value={expectedLabel} onChange={(event) => setExpectedLabel(event.target.value)}><option value="">Not labeled</option><option>Safe</option><option>Suspicious</option><option>Malicious</option></select></label></div>
            <button className="analyze-button" disabled={busy} onClick={() => submitPayload(payload, "manual")}>{busy ? "Analyzing safely…" : "Analyze payload"}<span>→</span></button>{message && <p className="form-message" role="alert">{message}</p>}
          </div>
          <div className="result-panel">
            <div className="card-heading"><div><span className="step">02</span><h2>Risk assessment</h2></div>{result && <span className="latency">{result.latencyMs.toFixed(0)} ms</span>}</div>
            {!result ? <div className="empty-result"><div className="radar"><span /><i /><i /><i /></div><h3>Awaiting a QR payload</h3><p>Your explainable result will appear here. The system never opens the scanned destination automatically.</p><div className="demo-row"><span>Try a controlled sample:</span><button onClick={() => submitPayload("https://pay.example.com/checkout?amount=100", "sample")}>Safe</button><button onClick={() => submitPayload("http://bit.ly/verify-wallet?redirect=https%3A%2F%2Fphishing.test", "sample")}>Suspicious</button><button onClick={() => submitPayload("https://malicious.example/collect?login=verify", "sample")}>Malicious</button></div></div> :
              <div className={`result-content ${result.classification.toLowerCase()}`}>
                <div className="score-row"><div className="score-ring" style={{ "--score": `${result.riskScore * 3.6}deg` } as React.CSSProperties}><div><strong>{result.riskScore}</strong><span>/ 100</span></div></div><div><p className="result-label">RISK CLASSIFICATION</p><h3>{result.classification}</h3><p>{result.recommendation}</p></div></div>
                <div className="payload-summary"><span>{result.payloadType.replaceAll("_", " ")}</span><strong>{result.domain || shortText(result.payloadPreview, 56)}</strong><small>SHA-256 recorded · destination not opened</small></div>
                {result.paymentContext && <div className="payment-facts"><div><span>Format</span><strong>{result.paymentContext.format}</strong></div><div><span>Merchant</span><strong>{result.paymentContext.merchantName || "Not supplied"}</strong></div><div><span>Amount</span><strong>{result.paymentContext.amount || "Not fixed"}</strong></div><div><span>Checksum</span><strong>{result.paymentContext.validCrc ? "Valid" : "Invalid"}</strong></div></div>}
                <div className="indicator-heading"><h4>Why this score</h4><span>{result.indicators.length} indicator{result.indicators.length === 1 ? "" : "s"}</span></div>
                <div className="indicator-list">{result.indicators.length ? result.indicators.map((item) => <article key={item.id} className={`indicator ${item.severity}`}><span className="indicator-points">+{item.score}</span><div><strong>{item.title}</strong><p>{item.detail}</p><code>{shortText(item.evidence, 72)}</code></div></article>) : <article className="indicator clear"><span className="indicator-points">✓</span><div><strong>No high-risk indicators</strong><p>The payload passed the current local checks. Always confirm the merchant and amount.</p></div></article>}</div>
                {result.redirectChain.length > 0 && <details className="technical"><summary>Redirect evidence</summary>{result.redirectChain.map((hop, index) => <div key={`${hop.url}-${index}`}><span>{hop.status}</span><code>{hop.url}</code></div>)}</details>}
              </div>}
          </div>
        </section>
        <section className="protection-strip"><div><span>1</span><strong>Decode</strong><small>Read payload safely</small></div><b>→</b><div><span>2</span><strong>Validate</strong><small>Check payment context</small></div><b>→</b><div><span>3</span><strong>Enrich</strong><small>Match CTI and IoCs</small></div><b>→</b><div><span>4</span><strong>Explain</strong><small>Score every signal</small></div></section>
      </div>}

      {view === "history" && <div className="page data-page">
        <div className="page-title"><div><p className="eyebrow">LOCAL EVIDENCE LOG</p><h1>Scan history</h1><p>Technical results are stored in SQLite for repeatable evaluation. Full payloads are not displayed.</p></div><button className="primary-action" onClick={() => setView("scan")}>New scan</button></div>
        <div className="summary-cards"><Metric label="Total scans" value={stats.total} /><Metric label="Safe" value={stats.safe} tone="safe" /><Metric label="Suspicious" value={stats.suspicious} tone="suspicious" /><Metric label="Malicious" value={stats.malicious} tone="malicious" /></div>
        <div className="table-card"><div className="table-head"><span>Result</span><span>Payload / destination</span><span>Indicators</span><span>Latency</span><span>Analyzed</span></div>{history.length ? history.map((scan) => <button className="history-row" key={scan.id} onClick={() => { setResult(scan); setView("scan"); }}><span><StatusPill value={scan.classification} /><b>{scan.riskScore}/100</b></span><span><strong>{scan.domain || shortText(scan.payloadPreview)}</strong><small>{scan.payloadType.replaceAll("_", " ")}</small></span><span>{scan.indicators.length}</span><span>{scan.latencyMs.toFixed(0)} ms</span><span>{new Date(scan.createdAt).toLocaleString()}</span></button>) : <div className="empty-table">No scans recorded yet. Analyze a controlled sample to begin.</div>}</div>
      </div>}

      {view === "research" && <div className="page data-page">
        <div className="page-title"><div><p className="eyebrow">STUDY EVALUATION</p><h1>Research metrics</h1><p>Live measurements aligned with the technical evaluation sheet in Chapter Three.</p></div><span className="research-badge">SQLite dataset · local</span></div>
        <div className="metric-grid"><Metric label="Accuracy" value={percent(stats.evaluation.accuracy)} /><Metric label="Precision" value={percent(stats.evaluation.precision)} /><Metric label="Recall" value={percent(stats.evaluation.recall)} /><Metric label="F1-score" value={percent(stats.evaluation.f1)} /><Metric label="Mean latency" value={`${stats.meanLatencyMs.toFixed(1)} ms`} /><Metric label="P95 latency" value={`${stats.p95LatencyMs.toFixed(1)} ms`} /></div>
        <div className="research-grid"><section className="panel"><div className="panel-title"><div><p className="eyebrow">CONFUSION MATRIX</p><h2>{stats.evaluation.sampleSize} labeled samples</h2></div></div><div className="matrix"><div /><span>Predicted risk</span><span>Predicted safe</span><b>Actual risk</b><strong>{stats.evaluation.tp}<small>True positive</small></strong><strong>{stats.evaluation.fn}<small>False negative</small></strong><b>Actual safe</b><strong>{stats.evaluation.fp}<small>False positive</small></strong><strong>{stats.evaluation.tn}<small>True negative</small></strong></div><p className="panel-note">Suspicious and Malicious are treated as positive-risk classes for this prototype evaluation.</p></section><section className="panel"><div className="panel-title"><div><p className="eyebrow">DECISION THRESHOLDS</p><h2>Explainable scoring</h2></div></div><div className="threshold"><span>0–39</span><b>Safe</b><i className="bar safe" /></div><div className="threshold"><span>40–69</span><b>Suspicious</b><i className="bar suspicious" /></div><div className="threshold"><span>70–100</span><b>Malicious</b><i className="bar malicious" /></div><p className="panel-note">Scores are additive, capped at 100, and retain every contributing indicator as evidence.</p></section></div>
        <section className="panel architecture"><div className="panel-title"><div><p className="eyebrow">FRAMEWORK PIPELINE</p><h2>One decision, four evidence layers</h2></div></div><div className="architecture-flow"><div><span>01</span><strong>Payload decoder</strong><small>URL · deep link · EMV TLV</small></div><b>→</b><div><span>02</span><strong>Context validation</strong><small>Merchant · CRC · structure</small></div><b>→</b><div><span>03</span><strong>CTI enrichment</strong><small>Domain · URL · IP · redirect</small></div><b>→</b><div><span>04</span><strong>Risk decision</strong><small>Score · label · explanation</small></div></div></section>
      </div>}

      {view === "intel" && <div className="page data-page">
        <div className="page-title"><div><p className="eyebrow">LOCAL CTI STORE</p><h1>Threat intelligence</h1><p>Add controlled research indicators. Matches contribute to the risk score without opening the destination.</p></div><span className="research-badge">{iocs.filter((item) => item.active).length} active IoCs</span></div>
        <div className="intel-grid"><form className="panel ioc-form" onSubmit={addIndicator}><div className="panel-title"><div><p className="eyebrow">NEW INDICATOR</p><h2>Add to local intelligence</h2></div></div><label>Indicator<input value={iocDraft.indicator} onChange={(event) => setIocDraft({ ...iocDraft, indicator: event.target.value })} placeholder="domain.example or full URL" /></label><div className="form-row"><label>Type<select value={iocDraft.indicatorType} onChange={(event) => setIocDraft({ ...iocDraft, indicatorType: event.target.value })}><option value="domain">Domain</option><option value="url">URL</option><option value="ip">IP address</option></select></label><label>Severity<select value={iocDraft.severity} onChange={(event) => setIocDraft({ ...iocDraft, severity: event.target.value })}><option>critical</option><option>high</option><option>medium</option></select></label></div><label>Source<input value={iocDraft.source} onChange={(event) => setIocDraft({ ...iocDraft, source: event.target.value })} /></label><button className="analyze-button">Save indicator<span>＋</span></button></form><section className="panel"><div className="panel-title"><div><p className="eyebrow">ACTIVE FEED</p><h2>Indicators of Compromise</h2></div></div><div className="ioc-list">{iocs.map((ioc) => <article key={ioc.id}><span className={`severity-dot ${ioc.severity}`} /><div><strong>{ioc.indicator}</strong><small>{ioc.indicator_type} · {ioc.source}</small></div><b>{ioc.confidence}%</b></article>)}</div></section></div>
      </div>}

      <nav className="mobile-nav" aria-label="Mobile navigation">{navItems.map(([key, label]) => <button key={key} className={view === key ? "active" : ""} onClick={() => setView(key)}><span>{key === "scan" ? "⌁" : key === "history" ? "◷" : key === "research" ? "▥" : "◇"}</span>{label.split(" ")[0]}</button>)}</nav>
      <footer><span>QRBased Sentinel · Research prototype</span><span>No financial transactions are processed.</span></footer>
    </main>
  );
}

function StatusPill({ value }: { value: Classification }) { return <span className={`status-pill ${value.toLowerCase()}`}><i />{value}</span>; }
function Metric({ label, value, tone = "" }: { label: string; value: string | number; tone?: string }) { return <div className={`metric-card ${tone}`}><span>{label}</span><strong>{value}</strong></div>; }

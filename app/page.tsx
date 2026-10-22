"use client";

import { ChangeEvent, FormEvent, useCallback, useEffect, useRef, useState } from "react";
import jsQR from "jsqr";

const API_URL = process.env.NEXT_PUBLIC_API_URL
  ?? (process.env.NODE_ENV === "development" ? "http://localhost:8000" : "");

type Classification = "Safe" | "Suspicious" | "Malicious";
type Indicator = { id: string; category: string; severity: string; score: number; title: string; detail: string; evidence: string };
type Scan = {
  id: string; createdAt: string; payloadPreview: string; payloadType: string;
  userId?: string | null; username?: string | null;
  normalizedUrl?: string | null; domain?: string | null; riskScore: number;
  classification: Classification; recommendation: string; latencyMs: number;
  source: string; expectedLabel?: string | null; indicators: Indicator[];
  observables: { urls: string[]; domains: string[]; ips: string[] };
  redirectChain: { url: string; status: number; domain: string }[];
  paymentContext?: { format: string; validStructure: boolean; validCrc: boolean; missingFields?: string[]; merchantName?: string | null; merchantCity?: string | null; amount?: string | null; currencyCode?: string | null; countryCode?: string | null; pointOfInitiation?: string } | null;
};
type Stats = {
  total: number; safe: number; suspicious: number; malicious: number; meanLatencyMs: number; p95LatencyMs: number;
  admin?: {
    totalUsers: number; activeUsers: number; scansToday: number; scansLast7Days: number; averageScansPerUser: number;
    dailyScans: { day: string; total: number }[];
    topUsers: { id: string; username: string; total: number }[];
  };
};
type Ioc = { id: string; indicator: string; indicator_type: string; severity: string; confidence: number; source: string; active: number };
type User = { id: string; username: string; email?: string | null; role: string; createdAt: string };
type UserSummary = User & { scanCount: number; safeCount: number; riskyCount: number; lastScanAt?: string | null; lastActivityAt?: string | null };
type Activity = { id: string; userId?: string | null; username: string; role: string; action: string; detail: Record<string, string | number>; createdAt: string };

const emptyStats: Stats = {
  total: 0, safe: 0, suspicious: 0, malicious: 0, meanLatencyMs: 0, p95LatencyMs: 0,
};
const navItems = [["dashboard", "Dashboard"], ["scan", "Scanner"], ["history", "Scan history"], ["intel", "Threat intelligence"]] as const;
const shortText = (value: string | null | undefined, length = 48) => {
  if (!value) return "Payload unavailable";
  return value.length > length ? `${value.slice(0, length)}…` : value;
};
const percentage = (value: number, total: number) => total ? `${((value / total) * 100).toFixed(1)}%` : "0.0%";
const apiFetch = (path: string, init: RequestInit = {}) => fetch(`${API_URL}${path}`, { ...init, credentials: "include" });

export default function Home() {
  const [view, setView] = useState<(typeof navItems)[number][0]>("dashboard");
  const [authStatus, setAuthStatus] = useState<"loading" | "guest" | "authenticated">("loading");
  const [user, setUser] = useState<User | null>(null);
  const [authMode, setAuthMode] = useState<"login" | "register">("login");
  const [authForm, setAuthForm] = useState({ username: "", email: "", password: "", confirmPassword: "" });
  const [authMessage, setAuthMessage] = useState("");
  const [authBusy, setAuthBusy] = useState(false);
  const [online, setOnline] = useState(false);
  const [payload, setPayload] = useState("");
  const [result, setResult] = useState<Scan | null>(null);
  const [history, setHistory] = useState<Scan[]>([]);
  const [stats, setStats] = useState<Stats>(emptyStats);
  const [iocs, setIocs] = useState<Ioc[]>([]);
  const [users, setUsers] = useState<UserSummary[]>([]);
  const [activity, setActivity] = useState<Activity[]>([]);
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [cameraOn, setCameraOn] = useState(false);
  const [resolveRedirects, setResolveRedirects] = useState(true);
  const [expectedLabel, setExpectedLabel] = useState("");
  const [iocDraft, setIocDraft] = useState({ indicator: "", indicatorType: "domain", severity: "high", source: "Manual research entry" });
  const [iocBusy, setIocBusy] = useState(false);
  const [iocMessage, setIocMessage] = useState("");
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const frameRef = useRef<number | null>(null);
  const scanLockRef = useRef(false);

  const refresh = useCallback(async () => {
    try {
      const isAdmin = user?.role === "admin";
      const activityPath = `/api/activity?limit=100${isAdmin && selectedUserId ? `&userId=${encodeURIComponent(selectedUserId)}` : ""}`;
      const [healthResponse, scansResponse, statsResponse, activityResponse, iocsResponse, usersResponse] = await Promise.all([
        apiFetch("/api/health"),
        apiFetch("/api/scans?limit=50"),
        apiFetch("/api/stats"),
        apiFetch(activityPath),
        apiFetch("/api/iocs"),
        isAdmin ? apiFetch("/api/users") : Promise.resolve(null),
      ]);
      setOnline(healthResponse.ok);
      if (scansResponse.status === 401) { setUser(null); setAuthStatus("guest"); return; }
      if (scansResponse.ok) setHistory((await scansResponse.json()).scans);
      if (statsResponse.ok) setStats(await statsResponse.json());
      if (activityResponse.ok) setActivity((await activityResponse.json()).activity);
      if (iocsResponse?.ok) setIocs((await iocsResponse.json()).iocs);
      if (usersResponse?.ok) setUsers((await usersResponse.json()).users);
    } catch { setOnline(false); }
  }, [selectedUserId, user?.role]);

  async function showUserActivity(userId: string | null) {
    setSelectedUserId(userId);
    const response = await apiFetch(`/api/activity?limit=100${userId ? `&userId=${encodeURIComponent(userId)}` : ""}`);
    if (response.ok) setActivity((await response.json()).activity);
  }

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void apiFetch("/api/auth/me").then(async (response) => {
        if (!response.ok) { setAuthStatus("guest"); return; }
        const body = await response.json();
        setUser(body.user); setAuthStatus("authenticated");
      }).catch(() => setAuthStatus("guest"));
    }, 0);
    return () => window.clearTimeout(timer);
  }, []);

  useEffect(() => {
    if (authStatus !== "authenticated") return;
    const timer = window.setTimeout(() => { void refresh(); }, 0);
    return () => window.clearTimeout(timer);
  }, [authStatus, refresh]);

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
      const response = await apiFetch("/api/analyze", {
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
    setIocBusy(true); setIocMessage("");
    try {
      const response = await apiFetch("/api/iocs", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ...iocDraft, indicator: iocDraft.indicator.trim() }) });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || "IoC could not be saved.");
      setIocDraft({ ...iocDraft, indicator: "" }); setIocMessage("Threat indicator saved."); await refresh();
    } catch (error) { setIocMessage(error instanceof Error ? error.message : "IoC could not be saved."); }
    finally { setIocBusy(false); }
  }

  async function submitAuthentication(event: FormEvent) {
    event.preventDefault(); setAuthMessage("");
    if (authMode === "register") {
      if (!/[a-zA-Z]/.test(authForm.username)) { setAuthMessage("Username cannot contain numbers only. Add at least one letter."); return; }
      if (!/^[a-z0-9._%+-]+@gmail\.com$/i.test(authForm.email.trim())) { setAuthMessage("Enter a valid Gmail address ending in @gmail.com."); return; }
      if (authForm.password !== authForm.confirmPassword) { setAuthMessage("Passwords do not match."); return; }
    }
    setAuthBusy(true);
    try {
      const response = await apiFetch(`/api/auth/${authMode}`, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ username: authForm.username, email: authForm.email, password: authForm.password }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || "Authentication failed.");
      setUser(body.user); setAuthStatus("authenticated"); setView("dashboard");
      setAuthForm({ username: "", email: "", password: "", confirmPassword: "" });
    } catch (error) { setAuthMessage(error instanceof Error ? error.message : "Authentication failed."); }
    finally { setAuthBusy(false); }
  }

  async function logout() {
    await apiFetch("/api/auth/logout", { method: "POST" });
    stopCamera(); setUser(null); setAuthStatus("guest"); setHistory([]); setStats(emptyStats); setIocs([]); setUsers([]); setActivity([]); setSelectedUserId(null); setResult(null); setIocMessage("");
  }

  if (authStatus === "loading") return <AuthLoading />;
  if (authStatus === "guest") return <AuthScreen mode={authMode} form={authForm} message={authMessage} busy={authBusy} onModeChange={(mode) => { setAuthMode(mode); setAuthMessage(""); }} onFormChange={setAuthForm} onSubmit={submitAuthentication} />;
  const visibleNavItems = navItems;

  return (
    <main className="app-shell">
      <header className="topbar">
        <button className="brand" onClick={() => setView("scan")} aria-label="Open scanner"><span className="brand-mark"><span>Q</span></span><span><strong>QRBased</strong><small>Sentinel</small></span></button>
        <nav className="desktop-nav" aria-label="Main navigation">{visibleNavItems.map(([key, label]) => <button key={key} className={view === key ? "active" : ""} onClick={() => setView(key)}>{label}</button>)}</nav>
        <div className="account-area"><div className={`service-state ${online ? "online" : "offline"}`}><span />{online ? "Protection active" : "API offline"}</div><button className="account-button" onClick={logout} title="Sign out"><span>{user?.username.slice(0, 1).toUpperCase()}</span><div><strong>{user?.username}</strong><small>{user?.role}</small></div><b>↪</b></button></div>
      </header>

      {view === "dashboard" && <Dashboard user={user!} stats={stats} history={history} users={users} activity={activity} selectedUserId={selectedUserId} onSelectUser={showUserActivity} onOpenScanner={() => setView("scan")} onOpenHistory={() => setView("history")} onOpenScan={(scan) => { setResult(scan); setView("scan"); }} />}

      {view === "scan" && <div className="page scanner-page">
        <section className="intro-row"><div><p className="eyebrow">SCAN-TIME PAYMENT DEFENSE</p><h1>Know what’s behind<br />the code <em>before</em> you pay.</h1><p className="lead">Decode, inspect, and risk-score QR payment payloads without opening their destination.</p></div><div className="privacy-note"><span className="lock-dot">◆</span><div><strong>Privacy-first analysis</strong><small>No credentials. No payments. Suspicious links stay closed.</small></div></div></section>
        <section className="scanner-grid">
          <div className="scan-card">
            <div className="card-heading"><div><span className="step">01</span><h2>Capture a QR code</h2></div></div>
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
        <div className="table-card"><div className="table-head"><span>Result</span><span>Payload / destination</span><span>Indicators</span><span>Latency</span><span>Analyzed</span></div>{history.length ? history.map((scan) => <button className="history-row" key={scan.id} onClick={() => { setResult(scan); setView("scan"); }}><span><StatusPill value={scan.classification} /><b>{scan.riskScore}/100</b></span><span><strong>{scan.domain || shortText(scan.payloadPreview)}</strong><small>{scan.username ? `${scan.username} · ` : ""}{scan.payloadType.replaceAll("_", " ")}</small></span><span>{scan.indicators.length}</span><span>{scan.latencyMs.toFixed(0)} ms</span><span>{new Date(scan.createdAt).toLocaleString()}</span></button>) : <div className="empty-table">No scans recorded yet. Analyze a controlled sample to begin.</div>}</div>
      </div>}

      {view === "intel" && <div className="page data-page">
        <div className="page-title"><div><p className="eyebrow">LOCAL CTI STORE</p><h1>Threat intelligence</h1><p>Add controlled research indicators. Matches contribute to the risk score without opening the destination.</p></div><span className="research-badge">{iocs.filter((item) => item.active).length} active IoCs</span></div>
        <div className="intel-grid"><form className="panel ioc-form" onSubmit={addIndicator}><div className="panel-title"><div><p className="eyebrow">NEW INDICATOR</p><h2>Add to local intelligence</h2></div></div><label>Indicator<input required maxLength={2048} value={iocDraft.indicator} onChange={(event) => setIocDraft({ ...iocDraft, indicator: event.target.value })} placeholder="domain.example, full URL, or IP address" /></label><div className="form-row"><label>Type<select value={iocDraft.indicatorType} onChange={(event) => setIocDraft({ ...iocDraft, indicatorType: event.target.value })}><option value="domain">Domain</option><option value="url">URL</option><option value="ip">IP address</option></select></label><label>Severity<select value={iocDraft.severity} onChange={(event) => setIocDraft({ ...iocDraft, severity: event.target.value })}><option>critical</option><option>high</option><option>medium</option></select></label></div><label>Source<input required maxLength={160} value={iocDraft.source} onChange={(event) => setIocDraft({ ...iocDraft, source: event.target.value })} /></label><button className="analyze-button" disabled={iocBusy}>{iocBusy ? "Saving…" : "Save indicator"}<span>＋</span></button>{iocMessage && <p className="form-message" role="status">{iocMessage}</p>}</form><section className="panel"><div className="panel-title"><div><p className="eyebrow">ACTIVE FEED</p><h2>Indicators of Compromise</h2></div></div><div className="ioc-list">{iocs.map((ioc) => <article key={ioc.id}><span className={`severity-dot ${ioc.severity}`} /><div><strong>{ioc.indicator}</strong><small>{ioc.indicator_type} · {ioc.source}</small></div><b>{ioc.confidence}%</b></article>)}</div></section></div>
      </div>}

      <nav className="mobile-nav" aria-label="Mobile navigation">{visibleNavItems.map(([key, label]) => <button key={key} className={view === key ? "active" : ""} onClick={() => setView(key)}><span>{key === "dashboard" ? "▦" : key === "scan" ? "⌁" : key === "history" ? "◷" : "◇"}</span>{label.split(" ")[0]}</button>)}</nav>
      <footer><span>QRBased Sentinel · Payment QR security</span><span>No financial transactions are processed.</span></footer>
    </main>
  );
}

const activityLabels: Record<string, string> = {
  account_created: "Created an account",
  signed_in: "Signed in",
  signed_out: "Signed out",
  qr_scanned: "Analyzed a QR code",
  indicator_added: "Added a threat indicator",
};

function Dashboard({ user, stats, history, users, activity, selectedUserId, onSelectUser, onOpenScanner, onOpenHistory, onOpenScan }: {
  user: User;
  stats: Stats;
  history: Scan[];
  users: UserSummary[];
  activity: Activity[];
  selectedUserId: string | null;
  onSelectUser: (userId: string | null) => void;
  onOpenScanner: () => void;
  onOpenHistory: () => void;
  onOpenScan: (scan: Scan) => void;
}) {
  const isAdmin = user.role === "admin";
  const admin = stats.admin;
  const maxDaily = Math.max(1, ...(admin?.dailyScans.map((item) => item.total) || [1]));
  const selectedUser = users.find((item) => item.id === selectedUserId);

  return <div className="page data-page dashboard-page">
    <div className="page-title"><div><p className="eyebrow">{isAdmin ? "ADMIN CONTROL CENTER" : "YOUR SECURITY ACTIVITY"}</p><h1>{isAdmin ? "System analytics" : "Your dashboard"}</h1><p>{isAdmin ? "Review every user, security scan, and account action across the platform." : "Track only your own QR scans, classifications, and recent account activity."}</p></div><button className="primary-action" onClick={onOpenScanner}>Scan a QR code</button></div>
    <div className="dashboard-kpis">
      <Metric label={isAdmin ? "All scans" : "Your scans"} value={stats.total} />
      {isAdmin ? <><Metric label="Registered users" value={admin?.totalUsers || 0} /><Metric label="Active scanners" value={admin?.activeUsers || 0} tone="safe" /><Metric label="Scans today" value={admin?.scansToday || 0} /><Metric label="Risky results" value={stats.suspicious + stats.malicious} tone="suspicious" /><Metric label="Average latency" value={`${stats.meanLatencyMs.toFixed(0)} ms`} /></> : <><Metric label="Safe rate" value={percentage(stats.safe, stats.total)} tone="safe" /><Metric label="Safe" value={stats.safe} tone="safe" /><Metric label="Suspicious" value={stats.suspicious} tone="suspicious" /><Metric label="Malicious" value={stats.malicious} tone="malicious" /><Metric label="Average latency" value={`${stats.meanLatencyMs.toFixed(0)} ms`} /></>}
    </div>
    <div className="dashboard-grid">
      <section className="panel analytics-panel"><div className="panel-title"><div><p className="eyebrow">RISK DISTRIBUTION</p><h2>{isAdmin ? "Platform classifications" : "Your classifications"}</h2></div></div><div className="distribution-list"><div><span><b>Safe</b><small>{stats.safe} scans</small></span><i><em className="safe" style={{ width: percentage(stats.safe, stats.total) }} /></i><strong>{percentage(stats.safe, stats.total)}</strong></div><div><span><b>Suspicious</b><small>{stats.suspicious} scans</small></span><i><em className="suspicious" style={{ width: percentage(stats.suspicious, stats.total) }} /></i><strong>{percentage(stats.suspicious, stats.total)}</strong></div><div><span><b>Malicious</b><small>{stats.malicious} scans</small></span><i><em className="malicious" style={{ width: percentage(stats.malicious, stats.total) }} /></i><strong>{percentage(stats.malicious, stats.total)}</strong></div></div></section>
      <section className="panel recent-panel"><div className="panel-title"><div><p className="eyebrow">RECENT SCANS</p><h2>{isAdmin ? "Latest across all users" : "Your latest scans"}</h2></div><button onClick={onOpenHistory}>View all</button></div><div className="recent-list">{history.slice(0, 5).map((scan) => <button key={scan.id} onClick={() => onOpenScan(scan)}><StatusPill value={scan.classification} /><span><strong>{scan.domain || shortText(scan.payloadPreview, 34)}</strong><small>{isAdmin && scan.username ? `${scan.username} · ` : ""}{new Date(scan.createdAt).toLocaleString()}</small></span><b>{scan.riskScore}</b></button>)}{!history.length && <p>No scan activity yet.</p>}</div></section>
    </div>
    {isAdmin && <div className="admin-insights">
      <section className="panel volume-panel"><div className="panel-title"><div><p className="eyebrow">7-DAY ANALYTICS</p><h2>Scan volume</h2></div><strong>{admin?.scansLast7Days || 0} total</strong></div><div className="volume-chart">{admin?.dailyScans.map((item) => <div key={item.day}><span><i style={{ height: `${Math.max(6, (item.total / maxDaily) * 100)}%` }} /></span><b>{item.total}</b><small>{new Date(`${item.day}T00:00:00`).toLocaleDateString(undefined, { weekday: "short" })}</small></div>)}</div></section>
      <section className="panel top-users-panel"><div className="panel-title"><div><p className="eyebrow">USER ANALYTICS</p><h2>Top scanners</h2></div><strong>{admin?.averageScansPerUser || 0} avg/user</strong></div><div className="top-users-list">{admin?.topUsers.map((item, index) => <button key={item.id} onClick={() => onSelectUser(item.id)}><span>{index + 1}</span><div><strong>{item.username}</strong><small>{item.total} scan{item.total === 1 ? "" : "s"}</small></div><i style={{ width: percentage(item.total, Math.max(1, stats.total)) }} /></button>)}{!admin?.topUsers.length && <p>No user scans yet.</p>}</div></section>
    </div>}
    <div className={`activity-dashboard ${isAdmin ? "admin" : "user"}`}>
      {isAdmin && <section className="panel user-directory"><div className="panel-title"><div><p className="eyebrow">USER DIRECTORY</p><h2>All accounts</h2></div><span>{users.length} accounts</span></div><div className="user-table"><div className="user-table-head"><span>User</span><span>Scans</span><span>Safe</span><span>Risky</span><span>Last activity</span><span /></div>{users.map((item) => <div className={selectedUserId === item.id ? "selected" : ""} key={item.id}><span className="user-identity"><b>{item.username.slice(0, 1).toUpperCase()}</b><span><strong>{item.username}</strong><small>{item.email || item.role}</small></span></span><span>{item.scanCount}</span><span>{item.safeCount}</span><span>{item.riskyCount}</span><span>{item.lastActivityAt ? new Date(item.lastActivityAt).toLocaleString() : "No activity"}</span><button onClick={() => onSelectUser(item.id)}>View activity</button></div>)}</div></section>}
      <section className="panel audit-panel"><div className="panel-title"><div><p className="eyebrow">AUDIT LOG</p><h2>{isAdmin ? selectedUser ? `${selectedUser.username}'s activity` : "All user activity" : "Your recent activity"}</h2></div>{isAdmin && selectedUserId && <button onClick={() => onSelectUser(null)}>Show all</button>}</div><ActivityList activity={activity} showUser={isAdmin && !selectedUserId} /></section>
    </div>
  </div>;
}

function ActivityList({ activity, showUser }: { activity: Activity[]; showUser: boolean }) {
  return <div className="audit-list">{activity.map((item) => <article key={item.id}><span className={`audit-icon ${item.action}`}>{item.action === "qr_scanned" ? "QR" : item.action === "signed_in" ? "IN" : item.action === "signed_out" ? "OUT" : item.action === "account_created" ? "+" : "IOC"}</span><div><strong>{showUser ? `${item.username} · ` : ""}{activityLabels[item.action] || item.action.replaceAll("_", " ")}</strong><small>{item.action === "qr_scanned" && item.detail.classification ? `${item.detail.classification} · risk ${item.detail.riskScore}/100 · ${item.detail.source}` : item.action === "indicator_added" ? `${item.detail.indicatorType}: ${item.detail.indicator}` : item.role}</small></div><time dateTime={item.createdAt}>{new Date(item.createdAt).toLocaleString()}</time></article>)}{!activity.length && <p className="empty-activity">No activity recorded yet.</p>}</div>;
}

function StatusPill({ value }: { value: Classification }) { return <span className={`status-pill ${value.toLowerCase()}`}><i />{value}</span>; }
function Metric({ label, value, tone = "" }: { label: string; value: string | number; tone?: string }) { return <div className={`metric-card ${tone}`}><span>{label}</span><strong>{value}</strong></div>; }

function AuthLoading() {
  return <main className="auth-shell"><div className="auth-loading" role="status"><span className="brand-mark"><span>Q</span></span><strong>QRBased Sentinel</strong><small>Checking your session…</small></div></main>;
}

function PasswordField({ label, value, autoComplete, placeholder, onChange }: {
  label: string;
  value: string;
  autoComplete: "current-password" | "new-password";
  placeholder: string;
  onChange: (value: string) => void;
}) {
  const [visible, setVisible] = useState(false);

  return <label>{label}<span className="password-field"><input type={visible ? "text" : "password"} autoComplete={autoComplete} required minLength={8} maxLength={128} value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} /><button type="button" className="password-toggle" onClick={() => setVisible((current) => !current)} aria-label={`${visible ? "Hide" : "Show"} ${label.toLowerCase()}`} aria-pressed={visible}><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z" /><circle cx="12" cy="12" r="2.75" />{visible && <path d="m4 4 16 16" />}</svg></button></span></label>;
}

function AuthScreen({ mode, form, message, busy, onModeChange, onFormChange, onSubmit }: {
  mode: "login" | "register";
  form: { username: string; email: string; password: string; confirmPassword: string };
  message: string;
  busy: boolean;
  onModeChange: (mode: "login" | "register") => void;
  onFormChange: (form: { username: string; email: string; password: string; confirmPassword: string }) => void;
  onSubmit: (event: FormEvent) => void;
}) {
  return <main className="auth-shell"><section className="auth-card"><div className="auth-intro"><div className="auth-brand"><span className="brand-mark"><span>Q</span></span><span><strong>QRBased</strong><small>Sentinel</small></span></div><p className="eyebrow">PAYMENT QR SECURITY</p><h1>Scan with confidence.</h1><p>Inspect QR payment payloads, review risk signals, and monitor scan activity from a protected workspace.</p><div className="auth-features"><span>◆ Explainable risk scoring</span><span>◆ QR image and camera scanning</span><span>◆ Local threat-intelligence matching</span></div></div><form className="auth-form" onSubmit={onSubmit}><div className="auth-tabs"><button type="button" className={mode === "login" ? "active" : ""} onClick={() => onModeChange("login")}>Sign in</button><button type="button" className={mode === "register" ? "active" : ""} onClick={() => onModeChange("register")}>Register</button></div><div><p className="eyebrow">{mode === "login" ? "WELCOME BACK" : "CREATE AN ACCOUNT"}</p><h2>{mode === "login" ? "Sign in to continue" : "Set up your access"}</h2><p>{mode === "login" ? "Use your account credentials to open the dashboard." : "Create a username with letters and register it with a Gmail address."}</p></div><label>Username<input autoComplete="username" required minLength={3} maxLength={32} pattern="(?=.*[A-Za-z])[A-Za-z0-9_.-]{3,32}" title="Use 3–32 allowed characters and include at least one letter." value={form.username} onChange={(event) => onFormChange({ ...form, username: event.target.value })} placeholder="Enter username" /></label>{mode === "register" && <label>Gmail address<input type="email" autoComplete="email" required maxLength={254} pattern="[A-Za-z0-9._%+-]+@gmail[.]com" title="Enter a Gmail address ending in @gmail.com." value={form.email} onChange={(event) => onFormChange({ ...form, email: event.target.value })} placeholder="name@gmail.com" /></label>}<PasswordField key={`password-${mode}`} label="Password" autoComplete={mode === "login" ? "current-password" : "new-password"} value={form.password} onChange={(password) => onFormChange({ ...form, password })} placeholder="Enter password" />{mode === "register" && <PasswordField label="Confirm password" autoComplete="new-password" value={form.confirmPassword} onChange={(confirmPassword) => onFormChange({ ...form, confirmPassword })} placeholder="Repeat password" />}<button className="analyze-button" disabled={busy}>{busy ? "Please wait…" : mode === "login" ? "Sign in" : "Create account"}<span>→</span></button>{message && <p className="form-message" role="alert">{message}</p>}</form></section></main>;
}

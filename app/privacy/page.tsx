import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "Privacy Policy | QRBased Sentinel",
  description: "How QRBased Sentinel collects, uses, and protects account and QR scan data.",
};

export default function PrivacyPolicyPage() {
  return (
    <main className="policy-shell">
      <article className="policy-card">
        <Link className="policy-brand" href="/" aria-label="Return to QRBased Sentinel">
          <span className="brand-mark"><span>Q</span></span>
          <span><strong>QRBased</strong><small>Sentinel</small></span>
        </Link>

        <p className="eyebrow">PRIVACY &amp; DATA PROTECTION</p>
        <h1>Privacy Policy</h1>
        <p className="policy-updated">Last updated: October 28, 2026</p>

        <p>QRBased Sentinel is a QR-payment security research application. This policy explains what information the service processes and why.</p>

        <h2>Information we collect</h2>
        <p>When you create an account, we store your email address, an internal username, and a securely hashed password. If you continue with Google, we receive your Google account identifier, email address, name, and profile picture from Google. We never receive your Google password.</p>
        <p>When you analyze a QR code or payment link, we process the submitted payload and may retain scan history, risk results, and technical security signals associated with your account.</p>

        <h2>How we use information</h2>
        <p>We use this information to authenticate you, provide QR risk analysis, maintain scan history, protect the service from abuse, and improve the reliability of security detections.</p>

        <h2>Sharing and selling</h2>
        <p>We do not sell personal information. Information is shared only with infrastructure and authentication providers needed to operate the service, or when required by law.</p>

        <h2>Security and retention</h2>
        <p>We use access controls, encrypted connections, and password hashing to protect stored information. We retain account and scan data only while it is needed to operate and secure the service.</p>

        <h2>Your choices</h2>
        <p>You may use email and password instead of Google sign-in. You may also revoke this app&apos;s Google access from your Google Account. To request access to or deletion of your account data, use the support contact shown on the Google consent screen.</p>

        <h2>Changes to this policy</h2>
        <p>We may update this policy as the service changes. The updated date above will identify the latest version.</p>

        <Link className="policy-home" href="/">&larr; Back to QRBased Sentinel</Link>
      </article>
    </main>
  );
}
